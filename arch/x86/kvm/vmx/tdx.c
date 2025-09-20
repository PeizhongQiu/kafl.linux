// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/jump_label.h>
#include <linux/trace_events.h>
#include <linux/pagemap.h>
#include <linux/kvm_host.h>

#include <asm/virtext.h>

#include "trace.h"
#include "vmx.h"
#include "x86.h"
#include "lapic.h"
#include "tdx.h"
#include "../irq.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

#define BUILD_TDVMCALL_ACCESSORS(param, gpr)				    \
static __always_inline							    \
unsigned long tdvmcall_##param##_read(struct kvm_vcpu *vcpu)		    \
{									    \
	return kvm_##gpr##_read(vcpu);					    \
}									    \
static __always_inline void tdvmcall_##param##_write(struct kvm_vcpu *vcpu, \
						     unsigned long val)	    \
{									    \
	kvm_##gpr##_write(vcpu, val);					    \
}
BUILD_TDVMCALL_ACCESSORS(p1, r12);
BUILD_TDVMCALL_ACCESSORS(p2, r13);
BUILD_TDVMCALL_ACCESSORS(p3, r14);
BUILD_TDVMCALL_ACCESSORS(p4, r15);

#define BUF_LEN 0x400
#define DMA_BUF_LEN     0x10000

typedef struct fuzz_input {
    char msr_data[BUF_LEN];
    char cpuid_data[BUF_LEN];
    char pio_data[BUF_LEN];
    char mmio_data[BUF_LEN];
    char dma_data[DMA_BUF_LEN];
}fuzz_input;
static fuzz_input fuzz_tdx_input;
static int msr_data_index = 0;
static int cpuid_data_index = 0;
static int pio_data_index = 0;
static int mmio_data_index = 0;


static inline u64 fuzz_value(char *buf, size_t buf_len,
                              int *index, size_t len)
{
    u64 v = 0;
    for (size_t i = 0; i < len; ++i) {
        v = (v << 8) | (uint8_t)buf[*index];
	*index = (*index + 1) % buf_len;
    }
    return v;
}

static inline u64 tdx_fuzz(int type, int len) {
	switch (type) {
                case TDX_FUZZ_MSR_READ:
			return fuzz_value(fuzz_tdx_input.msr_data, BUF_LEN, &msr_data_index, len);
                case TDX_FUZZ_MMIO_READ:
			return fuzz_value(fuzz_tdx_input.mmio_data, BUF_LEN, &mmio_data_index, len);
                case TDX_FUZZ_PIO_READ:
			return fuzz_value(fuzz_tdx_input.pio_data, BUF_LEN, &pio_data_index, len);
                case TDX_FUZZ_CPUID:
			return fuzz_value(fuzz_tdx_input.cpuid_data, BUF_LEN, &cpuid_data_index, len);
                case TDX_FUZZ_MSR_READ_ERR:
                case TDX_FUZZ_MSR_WRITE_ERR:
                case TDX_FUZZ_PORT_IN_ERR:
			return 0;
		default:
			return 0;
        }	
}

static inline struct kvm_vcpu *to_kvm_vcpu(struct kvm_vcpu *vcpu)
{
	if (emulate_seam)
		return (void *)to_tdx(vcpu)->tdvpr.va;
	return vcpu;
}

static __always_inline unsigned long tdexit_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rcx_read(vcpu);
}
static __always_inline unsigned long tdexit_ext_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rdx_read(vcpu);
}
static __always_inline unsigned long tdexit_gpa(struct kvm_vcpu *vcpu)
{
	return kvm_r8_read(vcpu);
}
static __always_inline unsigned long tdexit_intr_info(struct kvm_vcpu *vcpu)
{
	return kvm_r9_read(vcpu);
}

static __always_inline unsigned long tdvmcall_exit_type(struct kvm_vcpu *vcpu)
{
	return kvm_r10_read(vcpu);
}
static __always_inline unsigned long tdvmcall_exit_reason(struct kvm_vcpu *vcpu)
{
	return kvm_r11_read(vcpu);
}
static __always_inline void tdvmcall_set_return_code(struct kvm_vcpu *vcpu, long val)
{
	kvm_r10_write(vcpu, val);
}

static __always_inline void tdvmcall_set_return_val(struct kvm_vcpu *vcpu,
						    unsigned long val)
{
	kvm_r11_write(vcpu, val);
}

static int tdx_emulate_hlt(struct kvm_vcpu *vcpu)
{
	WARN_ONCE(1,"TDX: %s\n", __func__);
	tdvmcall_set_return_code(vcpu, 0);

	kvm_vcpu_halt(to_kvm_vcpu(vcpu));
	return 0;
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	WARN_ON_ONCE(vcpu->arch.pio.count != 1);

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);
	WARN_ON(!ret);

	tdvmcall_set_return_code(vcpu, 0);
	tdvmcall_set_return_val(vcpu, val);

	return 1;
}

static bool _tdx_fuzz_pio_filtered(unsigned port)
{
        switch (port) {
		/* i8237A DMA controller */
		case 0x80 ... 0x8f:
			return false;
		/* PCI */
		case 0xcd8 ... 0xcdf:
		case 0xcf8 ... 0xcfb:
			return true;
		/* PCI config space generic read access */
		case 0xcfc ... 0xcff:
			return false;
		/* PCIE hotplug device state for Q35 machine type */
		case 0xcc4:
		case 0xcc8:
			return false;
		/* ACPI ports list:
		 * 0600-0603 : ACPI PM1a_EVT_BLK
		 * 0604-0605 : ACPI PM1a_CNT_BLK
		 * 0608-060b : ACPI PM_TMR
		 * 0620-062f : ACPI GPE0_BLK
		 */
		case 0x600 ... 0x62f:
			return true;
		default:
			return true;
        }
        return false;
}

static int tdx_emulate_io(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	unsigned port;
	int size, ret, err;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	++vcpu->stat.io_exits;

	size = tdvmcall_p1_read(vcpu);
	port = tdvmcall_p3_read(vcpu);

	if (size > 4) {
		tdvmcall_set_return_code(vcpu, -E2BIG);
		return 1;
	}

	if (!tdvmcall_p2_read(vcpu)) {
		printk("[FUZZ_PIO]vcpu:%p,port:%ld,size:%d,fuzz_target:%d",vcpu,port,size,tdx->fuzz_target);

		if (((tdx->fuzz_target & TDX_FUZZ_PIO_READ) == 0) || _tdx_fuzz_pio_filtered(port)) {
			ret = ctxt->ops->pio_in_emulated(ctxt, size, port, &val, 1);
			if (!ret)
				vcpu->arch.complete_userspace_io = tdx_complete_pio_in;
			else
				tdvmcall_set_return_val(vcpu, val);
		} else {
			ret = 1;
			err = tdx_fuzz(TDX_FUZZ_PORT_IN_ERR, 0);
                	if ((tdx->fuzz_target & TDX_FUZZ_PORT_IN_ERR) != 0 && err != 0) {
                        	tdvmcall_set_return_code(vcpu, err);
                        	return 1;
                	}
			val = tdx_fuzz(TDX_FUZZ_PIO_READ, size);
			tdvmcall_set_return_val(vcpu, val);
			printk("[FUZZ_PIO]port:%ld,val:%ld",port,val);
		}
	} else {
		val = tdvmcall_p4_read(vcpu);
		ret = ctxt->ops->pio_out_emulated(ctxt, size, port, &val, 1);

		// No need for a complete_userspace_io callback.
		vcpu->arch.pio.count = 0;
	}
	if (ret)
		tdvmcall_set_return_code(vcpu, 0);
	return ret;
}

static bool _tdx_fuzz_msr_filtered(unsigned int msr)
{
	/* MSRs managed by HW - should not get these via #VE */
	switch (msr) {
		case MSR_EFER:
		case MSR_IA32_CR_PAT:
		case MSR_FS_BASE:
		case MSR_GS_BASE:
		case MSR_KERNEL_GS_BASE:
		case MSR_IA32_SYSENTER_CS:
		case MSR_IA32_SYSENTER_EIP:
		case MSR_IA32_SYSENTER_ESP:
		case MSR_STAR:
		case MSR_LSTAR:
		case MSR_SYSCALL_MASK:
		case MSR_IA32_XSS:
		case MSR_TSC_AUX:
		case MSR_IA32_SPEC_CTRL:
		case MSR_IA32_PRED_CMD:
		case MSR_IA32_FLUSH_CMD:
		case MSR_IA32_DS_AREA:
			return true;
	}

	/* MSR exceptions - skip fuzzing MSRs that are debug-only
	 * or where HW injects an error - modulated by asm/msr-list.h */
	switch (msr) {
		case MSR_IA32_SMM_MONITOR_CTL:
		case MSR_IA32_SMBASE:
		case MSR_IA32_VMX_BASIC:
		case MSR_IA32_VMX_PINBASED_CTLS:
		case MSR_IA32_VMX_PROCBASED_CTLS:
		case MSR_IA32_VMX_EXIT_CTLS:
		case MSR_IA32_VMX_ENTRY_CTLS:
		case MSR_IA32_VMX_MISC:
		case MSR_IA32_VMX_CR0_FIXED0:
		case MSR_IA32_VMX_CR0_FIXED1:
		case MSR_IA32_VMX_CR4_FIXED0:
		case MSR_IA32_VMX_CR4_FIXED1:
		case MSR_IA32_VMX_VMCS_ENUM:
		case MSR_IA32_VMX_PROCBASED_CTLS2:
		case MSR_IA32_VMX_EPT_VPID_CAP:
		case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
		case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
		case MSR_IA32_VMX_TRUE_EXIT_CTLS:
		case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
		case MSR_IA32_VMX_VMFUNC:
		case MSR_IA32_BNDCFGS:
		case MSR_IA32_PASID:
			// HW injects #GP
			return true;

		case MSR_IA32_PERFCTR0:
		case MSR_IA32_PERFCTR1:
		case MSR_IA32_PERF_CAPABILITIES:
		case MSR_CORE_PERF_FIXED_CTR0:
		case MSR_CORE_PERF_FIXED_CTR1:
		case MSR_CORE_PERF_FIXED_CTR2:
		case MSR_CORE_PERF_FIXED_CTR3:
		case MSR_CORE_PERF_FIXED_CTR_CTRL:
		case MSR_CORE_PERF_GLOBAL_STATUS:
		case MSR_CORE_PERF_GLOBAL_CTRL:
		case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
		case MSR_PERF_METRICS:
			// HW injects #GP unless PERFMON=1
			return true;

		case MSR_IA32_RTIT_STATUS:
		case MSR_IA32_RTIT_ADDR0_A:
		case MSR_IA32_RTIT_ADDR0_B:
		case MSR_IA32_RTIT_ADDR1_A:
		case MSR_IA32_RTIT_ADDR1_B:
		case MSR_IA32_RTIT_ADDR2_A:
		case MSR_IA32_RTIT_ADDR2_B:
		case MSR_IA32_RTIT_ADDR3_A:
		case MSR_IA32_RTIT_ADDR3_B:
		case MSR_IA32_RTIT_CR3_MATCH:
		case MSR_IA32_RTIT_OUTPUT_BASE:
		case MSR_IA32_RTIT_OUTPUT_MASK:
			// HW injects #GP unless XFAM[8]=1
			return true;

		case MSR_ARCH_LBR_INFO_0 ... MSR_ARCH_LBR_TO_0+0xff:
			// HW injects #GP unless XFAM[15]=1
			return true;

		case MSR_IA32_PMC0:
		case MSR_IA32_PMC0+1:
		case MSR_IA32_PMC0+2:
		case MSR_IA32_PMC0+3:
		case MSR_IA32_PMC0+4:
		case MSR_IA32_PMC0+5:
		case MSR_IA32_PMC0+6:
		case MSR_IA32_PMC0+7:
			// HW injects #GP unless PERFMON=1
			return true;
		case MSR_IA32_APICBASE:
			// HW ensures x2apic is enabled
			return false;
		// case MSR_IA32_UMWAIT_CONTROL:
		// HW inject #GP unless... CPUID(7,0).ECX[5]??
	}
	return false;
}

static int tdx_emulate_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_p1_read(vcpu);
	u64 data;
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int err;
	printk("[FUZZ_MSR]vcpu:%p,index:%d, fuzz_target: %d",vcpu,index,tdx->fuzz_target);
	if (((tdx->fuzz_target & TDX_FUZZ_MSR_READ) == 0) || _tdx_fuzz_msr_filtered(index)) {
		if (kvm_get_msr(to_kvm_vcpu(vcpu), index, &data)) {
			trace_kvm_msr_read_ex(index);
			tdvmcall_set_return_code(vcpu, -EFAULT);
			return 1;
		}
	} else {
		err = tdx_fuzz(TDX_FUZZ_MSR_READ_ERR, 0);
		if ((tdx->fuzz_target & TDX_FUZZ_MSR_READ_ERR) != 0 && err != 0) {
			tdvmcall_set_return_code(vcpu, -EFAULT);
                        return 1;
		}
		data = tdx_fuzz(TDX_FUZZ_MSR_READ, 8);
		if (index == MSR_IA32_APICBASE) {
			data = data | X2APIC_ENABLE;	
		} 
		printk("[FUZZ_MSR]index:%d,data,%ld",index,data);
	}
	trace_kvm_msr_read(index, data);

	tdvmcall_set_return_code(vcpu, 0);
	tdvmcall_set_return_val(vcpu, data);
	return 1;
}

static int tdx_emulate_wrmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_p1_read(vcpu);
	u64 data = tdvmcall_p2_read(vcpu);
	int err;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (kvm_set_msr(to_kvm_vcpu(vcpu), index, data)) {
		trace_kvm_msr_write_ex(index, data);
		tdvmcall_set_return_code(vcpu, -EFAULT);
		return 1;
	}
	
	err = tdx_fuzz(TDX_FUZZ_MSR_WRITE_ERR, 0);
	if ((tdx->fuzz_target & TDX_FUZZ_MSR_WRITE_ERR) != 0 && err != 0) {
        	tdvmcall_set_return_code(vcpu, -EFAULT);
                return 1;
        }

	trace_kvm_msr_write(index, data);
	tdvmcall_set_return_code(vcpu, 0);
	return 1;
}

static int tdx_complete_mmio(struct kvm_vcpu *vcpu)
{
	unsigned long val = 0;
	gpa_t gpa;
	int size;

	BUG_ON(vcpu->mmio_needed != 1);
	vcpu->mmio_needed = 0;

	if (!vcpu->mmio_is_write) {
		gpa = vcpu->mmio_fragments[0].gpa;
		size = vcpu->mmio_fragments[0].len;

		memcpy(&val, vcpu->run->mmio.data, size);
		tdvmcall_set_return_val(vcpu, val);
//		trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	}
	return 1;
}

static inline int tdx_mmio_write(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val = tdvmcall_p4_read(vcpu);

	if (kvm_iodevice_write(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_write(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	/* trace_kvm_mmio(KVM_TRACE_MMIO_WRITE, size, gpa, &val); */
	return 0;
}

static bool _tdx_fuzz_mmio_filtered(gpa_t gpa) 
{
	switch (gpa) {
		case 0xfec00000 ... 0xfec00010: // IOAPIC?
			return true;
		default:
			return false;
	}
	return false;
}

static inline int tdx_mmio_read(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val;
	struct vcpu_tdx *tdx = to_tdx(vcpu);
        printk("[FUZZ_MMIO]vcpu:%p,gpa:%ld,size:%d,fuzz_target:%d",vcpu,gpa,size,tdx->fuzz_target);

	if (((tdx->fuzz_target & TDX_FUZZ_MMIO_READ) == 0) || _tdx_fuzz_mmio_filtered(gpa)) {
		if (kvm_iodevice_read(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    	kvm_io_bus_read(vcpu, KVM_MMIO_BUS, gpa, size, &val))
			return -EOPNOTSUPP;
	} else {
                val = tdx_fuzz(TDX_FUZZ_MMIO_READ, size);
                printk("[FUZZ_MMIO]gpa:%ld,val:%ld",gpa,val);
	}
	tdvmcall_set_return_val(vcpu, val);
	/* trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val); */
	return 0;
}

static int tdx_emulate_mmio(struct kvm_vcpu *vcpu)
{
	struct kvm_memory_slot *slot;
	int size, write, r;
	unsigned long val;
	gpa_t gpa;

	BUG_ON(vcpu->mmio_needed);

	size = tdvmcall_p1_read(vcpu);
	write = tdvmcall_p2_read(vcpu);
	gpa = tdvmcall_p3_read(vcpu);

	if (size > 8u || ((gpa + size - 1) ^ gpa) & PAGE_MASK) {
		tdvmcall_set_return_code(vcpu, -E2BIG);
		return 1;
	}

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gpa >> PAGE_SHIFT);
	if (slot && !(slot->flags & KVM_MEMSLOT_INVALID)) {
		tdvmcall_set_return_code(vcpu, -EFAULT);
		return 1;
	}

	if (!kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		trace_kvm_fast_mmio(gpa);
		return 1;
	}

	if (write)
		r = tdx_mmio_write(vcpu, gpa, size);
	else
		r = tdx_mmio_read(vcpu, gpa, size);
	if (!r) {
		tdvmcall_set_return_code(vcpu, 0);
		return 1;
	}

	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = write;
	vcpu->arch.complete_userspace_io = tdx_complete_mmio;

	vcpu->run->mmio.phys_addr = gpa;
	vcpu->run->mmio.len = size;
	vcpu->run->mmio.is_write = write;
	vcpu->run->exit_reason = KVM_EXIT_MMIO;

	if (write) {
		memcpy(vcpu->run->mmio.data, &val, size);
	} else {
		vcpu->mmio_fragments[0].gpa = gpa;
		vcpu->mmio_fragments[0].len = size;
		/* trace_kvm_mmio(KVM_TRACE_MMIO_READ_UNSATISFIED, size, gpa, NULL); */
	}
	return 0;
}

static int tdx_trace_tdvmcall(struct kvm_vcpu *vcpu)
{
	pr_warn("tdvmcall: exit: 0x%lx (%lu, 0x%lx), (%lu, 0x%lx), (%lu, 0x%lx), (%lu, 0x%lx),\n",
		tdvmcall_exit_type(vcpu),
		tdvmcall_p1_read(vcpu), tdvmcall_p1_read(vcpu),
		tdvmcall_p2_read(vcpu), tdvmcall_p2_read(vcpu),
		tdvmcall_p3_read(vcpu), tdvmcall_p3_read(vcpu),
		tdvmcall_p4_read(vcpu), tdvmcall_p4_read(vcpu));

	tdvmcall_set_return_code(vcpu, 0);

	return 1;
}

static int tdx_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	eax = tdvmcall_p1_read(vcpu);
	ecx = tdvmcall_p2_read(vcpu);
	printk("[FUZZ_CPUID]vcpu:%p,eax:%d,ecx:%d,fuzz_target:%d",vcpu,eax,ecx,tdx->fuzz_target);

	if ((tdx->fuzz_target & TDX_FUZZ_CPUID) == 0) {
		kvm_cpuid(to_kvm_vcpu(vcpu), &eax, &ebx, &ecx, &edx, true);
	} else {
		eax = tdx_fuzz(TDX_FUZZ_CPUID, 4);
		ebx = tdx_fuzz(TDX_FUZZ_CPUID, 4);
		ecx = tdx_fuzz(TDX_FUZZ_CPUID, 4);
		edx = tdx_fuzz(TDX_FUZZ_CPUID, 4);
		printk("[FUZZ_CPUID]eax:%ld,ebx:%ld,ecx:%ld,edx:%ld",eax,ebx,ecx,edx);	
	}

	tdvmcall_p1_write(vcpu, eax);
	tdvmcall_p2_write(vcpu, ebx);
	tdvmcall_p3_write(vcpu, ecx);
	tdvmcall_p4_write(vcpu, edx);

	tdvmcall_set_return_code(vcpu, 0);

	return 1;
}

static int tdx_emulate_vmcall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;
	struct dma_entry *entry;
	unsigned long flags;

	printk("1");
	nr = tdvmcall_exit_type(vcpu);
	a0 = tdvmcall_exit_reason(vcpu);
	a1 = tdvmcall_p1_read(vcpu);
	a2 = tdvmcall_p2_read(vcpu);
	a3 = tdvmcall_p3_read(vcpu);
	printk("nr:0x%lx, a0:0x%lx, a1:0x%lx, a2:0x%lx, a3:0x%lx\n", nr, a0,a1,a2,a3);	
	if (nr == KVM_HC_FUZZ_CTRL) {
		if (a0 == 1) {
                        printk("vcpu: %p,KVM: FUZZ ENABLED, target=%llu\n", vcpu, a1);
                        to_tdx(vcpu)->fuzz_target = a1;
                } else if (a0 == 0) {
                        printk("KVM: FUZZ DISABLED\n");
                        to_tdx(vcpu)->fuzz_target = 0;
                } else {
			printk("KVM: UNknown FUZZ\n");
		}

                ret = 0;
	} else if (nr == KVM_HC_INJECT_IRQ) {
		unsigned long irq = a0;  // hypercall 参数从 a0 获取
    		if (irq >= 256) {
        		printk("irq:%d error!!!\n",irq);
			ret = 0;
		}
		printk("Injecting IRQ %lu from hypercall\n", irq);
		printk("vcpu:%p,to_kvm_vcpu:%p",vcpu,to_kvm_vcpu(vcpu));

    		// 将 IRQ 注入到 guest 中
    		kvm_queue_interrupt(to_kvm_vcpu(vcpu), irq, false); // 软中断
		printk("[KVM] Queued IRQ: %d\n", to_kvm_vcpu(vcpu)->arch.interrupt.nr);
    		// static_call(kvm_x86_enable_irq_window)(vcpu);
		// kvm_x86_ops.enable_irq_window(to_kvm_vcpu(vcpu));
		kvm_make_request(KVM_REQ_EVENT, to_kvm_vcpu(vcpu));
		ret = 0; // hypercall 返回值
	} else if (nr == KVM_HC_PREPARE_DATA) {
		unsigned long gpa = a0;

		int idx = srcu_read_lock(&to_kvm_vcpu(vcpu)->kvm->srcu);        // 保护 memslots
		ret = kvm_read_guest(to_kvm_vcpu(vcpu)->kvm, gpa, &fuzz_tdx_input, sizeof(fuzz_tdx_input));
		pr_info("prepare data: msr_data: %s;\ncpuid_data: %s\npio_data: %s\n mmio_data: %s\ndma_data: %s\n", fuzz_tdx_input.msr_data, fuzz_tdx_input.cpuid_data, fuzz_tdx_input.pio_data, fuzz_tdx_input.mmio_data, fuzz_tdx_input.dma_data);
		srcu_read_unlock(&to_kvm_vcpu(vcpu)->kvm->srcu, idx);

		msr_data_index = 0;
		cpuid_data_index = 0;
		pio_data_index = 0;
		mmio_data_index = 0;

		ret = 0;
	} else {
		ret = __kvm_emulate_hypercall(to_kvm_vcpu(vcpu), nr, a0, a1, a2, a3, true);
	}
	tdvmcall_set_return_code(vcpu, ret);

	return 1;
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long exit_reason;
	
	//printk("tdx: %s: reason 0x%lx, type: 0x%lx\n",
	//			__func__,
	//			tdvmcall_exit_reason(vcpu),
	//		   	tdvmcall_exit_type(vcpu));

	if (unlikely(tdx->tdvmcall.xmm_mask))
		goto unsupported;

	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	exit_reason = tdvmcall_exit_reason(vcpu);

	//TODO
	/* trace_kvm_tdvmcall(vmcs_readl(GUEST_RIP), exit_reason, */
	/* 		   tdvmcall_p1_read(vcpu), tdvmcall_p2_read(vcpu), */
	/* 		   tdvmcall_p3_read(vcpu), tdvmcall_p4_read(vcpu)); */

	switch (exit_reason) {
	case EXIT_REASON_TRIPLE_FAULT:
		return tdx_trace_tdvmcall(vcpu);
	case EXIT_REASON_CPUID:
		return tdx_emulate_cpuid(vcpu);
	case EXIT_REASON_HLT:
		return tdx_emulate_hlt(vcpu);
	// case EXIT_REASON_RDPMC:
	// 	ret = tdx_emulate_rdpmc(vcpu);
	// 	break;
	// case EXIT_REASON_VMCALL:
	// 	
	// 	break;
	case EXIT_REASON_IO_INSTRUCTION:
		return tdx_emulate_io(vcpu);
	case EXIT_REASON_MSR_READ:
		return tdx_emulate_rdmsr(vcpu);
	case EXIT_REASON_MSR_WRITE:
		return tdx_emulate_wrmsr(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_emulate_mmio(vcpu);
	default:
		break;
	}

unsupported:
	tdvmcall_set_return_code(vcpu, -EOPNOTSUPP);
	return 1;
}

static int tdx_handle_exception(struct kvm_vcpu *vcpu)
{
	u32 intr_info = tdexit_intr_info(vcpu);

	if (is_nmi(intr_info) || is_machine_check(intr_info))
		return 1;

	kvm_pr_unimpl("unexpected exception 0x%x\n", intr_info);
	return -EFAULT;
}

static int tdx_handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int tdx_handle_triple_fault(struct kvm_vcpu *vcpu)
{
	WARN_ONCE(1, "TDX: %s\n", __func__);
//TODO
#if 1
	kvm_vcpu_halt(vcpu);
#else
	if (halt_on_triple_fault)
		return kvm_vcpu_halt(vcpu);

	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	vcpu->mmio_needed = 0;
#endif
	return 0;
}

static int tdx_handle_ept_violation(struct kvm_vcpu *tdx_vcpu)
{
	unsigned long exit_qualification =  tdexit_exit_qual(tdx_vcpu);
	struct kvm_vcpu *vcpu = to_kvm_vcpu(tdx_vcpu);
	gpa_t gpa = tdexit_gpa(tdx_vcpu);
	u64 error_code;

	/* TODO: Use TDX's version of the vCPU to handle MMU stuff. */
	// printk("ept_violation:%lx, exit_qualification: %ld", gpa, exit_qualification);
	trace_kvm_page_fault(vcpu, gpa, exit_qualification);

	/* Is it a read fault? */
	error_code = (exit_qualification & EPT_VIOLATION_ACC_READ)
		     ? PFERR_USER_MASK : 0;
	/* Is it a write fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_WRITE)
		      ? PFERR_WRITE_MASK : 0;
	/* Is it a fetch fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_INSTR)
		      ? PFERR_FETCH_MASK : 0;
	/* ept page table entry is present? */
	error_code |= (exit_qualification & EPT_VIOLATION_RWX_MASK)
		      ? PFERR_PRESENT_MASK : 0;

	error_code |= (exit_qualification & 0x100) != 0 ?
	       PFERR_GUEST_FINAL_MASK : PFERR_GUEST_PAGE_MASK;

	vcpu->arch.exit_qualification = exit_qualification;
	return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0);
}

int __tdx_handle_exit(struct kvm_vcpu *vcpu)
{
	u16 exit_reason = to_tdx(vcpu)->exit_reason.basic;

	switch (exit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		return tdx_handle_exception(vcpu);
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return tdx_handle_external_interrupt(vcpu);
	case EXIT_REASON_TRIPLE_FAULT:
		return tdx_handle_triple_fault(vcpu);
	case EXIT_REASON_TDCALL:
		return handle_tdvmcall(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_handle_ept_violation(vcpu);
	case EXIT_REASON_EPT_MISCONFIG:
		return tdx_handle_ept_misconfig(vcpu);
	default:
		break;
	}

	kvm_pr_unimpl("unexpected exit reason 0x%x\n", exit_reason);
	return -EFAULT;
}
