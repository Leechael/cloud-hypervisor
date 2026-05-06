// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use std::any::Any;
use std::collections::HashMap;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use std::mem::offset_of;
#[cfg(any(feature = "sev_snp", feature = "tdx"))]
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
#[cfg(any(feature = "sev_snp", feature = "tdx"))]
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::result;
#[cfg(target_arch = "x86_64")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::anyhow;
#[cfg(any(feature = "sev_snp", feature = "tdx"))]
use kvm_bindings::kvm_create_guest_memfd;
use kvm_ioctls::{DeviceFd, NoDatamatch, VcpuFd, VmFd};
#[cfg(target_arch = "x86_64")]
use log::warn;
#[cfg(any(feature = "sev_snp", feature = "tdx"))]
use log::{debug, info};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_arch = "aarch64")]
use crate::aarch64::gic::KvmGicV3Its;
#[cfg(target_arch = "aarch64")]
pub use crate::aarch64::{VcpuKvmState, check_required_kvm_extensions, is_system_register};
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::gic::{Vgic, VgicConfig};
#[cfg(target_arch = "riscv64")]
use crate::arch::riscv64::aia::{Vaia, VaiaConfig};
#[cfg(target_arch = "aarch64")]
use crate::arm64_core_reg_id;
#[cfg(target_arch = "riscv64")]
use crate::riscv64::aia::KvmAiaImsics;
#[cfg(target_arch = "riscv64")]
pub use crate::riscv64::{
    VcpuKvmState, aia::AiaImsicsState as AiaState, check_required_kvm_extensions,
    is_non_core_register,
};
#[cfg(target_arch = "riscv64")]
use crate::riscv64_reg_id;
// x86_64 dependencies
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    KVM_CAP_HYPERV_SYNIC, KVM_CAP_SPLIT_IRQCHIP, KVM_CAP_X2APIC_API, KVM_GUESTDBG_USE_HW_BP,
    KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK, KVM_X2APIC_API_USE_32BIT_IDS, MsrList, kvm_enable_cap,
    kvm_msr_entry,
};
#[cfg(target_arch = "x86_64")]
use x86_64::check_required_kvm_extensions;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{CpuId, ExtendedControlRegisters, MsrEntries, VcpuKvmState};

#[cfg(target_arch = "x86_64")]
use crate::ClockData;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86::{
    CpuIdEntry, FpuState, LapicState, MTRR_MSR_INDICES, MsrEntry, NUM_IOAPIC_PINS,
    SpecialRegisters, XsaveState,
};
#[cfg(feature = "tdx")]
use crate::vm::TdxAttributes;
use crate::{
    CpuState, HypervisorType, HypervisorVmConfig, InterruptSourceConfig, IoEventAddress,
    IrqRoutingEntry, MpState, StandardRegisters, USER_MEMORY_REGION_GUEST_MEMFD,
    USER_MEMORY_REGION_LOG_DIRTY, USER_MEMORY_REGION_READ, USER_MEMORY_REGION_WRITE,
    UserMemoryRegion, VmOps, cpu, hypervisor, vm,
};
// aarch64 dependencies
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
// riscv64 dependencies
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "aarch64")]
use std::mem;

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_X86_DEFAULT_VM;
///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub use kvm_bindings::kvm_vcpu_events as VcpuEvents;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::nested::KvmNestedStateBuffer;
pub use kvm_bindings::{
    self, KVM_DEV_VFIO_FILE, KVM_DEV_VFIO_FILE_ADD, KVM_DEV_VFIO_FILE_DEL, KVM_GUESTDBG_ENABLE,
    KVM_GUESTDBG_SINGLESTEP, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_MEM_GUEST_MEMFD,
    KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY, KVM_MSI_VALID_DEVID, kvm_clock_data,
    kvm_create_device, kvm_create_device as CreateDevice, kvm_device_attr as DeviceAttr,
    kvm_device_type_KVM_DEV_TYPE_VFIO, kvm_guest_debug, kvm_irq_routing, kvm_irq_routing_entry,
    kvm_mp_state, kvm_pit_config, kvm_run, kvm_userspace_memory_region,
    kvm_userspace_memory_region2,
};
#[cfg(target_arch = "aarch64")]
use kvm_bindings::{
    KVM_GUESTDBG_USE_HW, KVM_NR_SPSR, KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG,
    KVM_REG_ARM64_SYSREG_CRM_MASK, KVM_REG_ARM64_SYSREG_CRN_MASK, KVM_REG_ARM64_SYSREG_OP0_MASK,
    KVM_REG_ARM64_SYSREG_OP1_MASK, KVM_REG_ARM64_SYSREG_OP2_MASK, KVM_REG_SIZE_U32,
    KVM_REG_SIZE_U64, KVM_REG_SIZE_U128, kvm_regs, user_pt_regs,
};
#[cfg(target_arch = "riscv64")]
use kvm_bindings::{KVM_REG_RISCV_CORE, kvm_riscv_core};
#[cfg(feature = "tdx")]
use kvm_bindings::{KVM_X86_TDX_VM, KVMIO, kvm_run__bindgen_ty_1};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{Xsave as xsave2, kvm_xsave2};
pub use kvm_ioctls::{self, Cap, Kvm, VcpuExit};
use thiserror::Error;
use vfio_ioctls::VfioDeviceFd;
#[cfg(target_arch = "x86_64")]
use vmm_sys_util::{fam::FamStruct, ioctl_io_nr};
#[cfg(feature = "tdx")]
use vmm_sys_util::{ioctl::ioctl_with_val, ioctl_iowr_nr};

#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
const KVM_CAP_VM_TYPES_RAW: libc::c_ulong = 235;
#[cfg(any(feature = "sev_snp", feature = "tdx"))]
const KVM_CAP_GUEST_MEMFD_FLAGS_RAW: libc::c_ulong = 244;
#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
const KVM_X86_TDX_VM_LEGACY: u64 = 2;
#[cfg(feature = "tdx")]
const TDX_TD_ATTRIBUTES_DEBUG: u64 = 1 << 0;
#[cfg(feature = "tdx")]
const TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE: u64 = 1 << 28;
#[cfg(feature = "tdx")]
const TDX_TD_ATTRIBUTES_PERFMON: u64 = 1 << 63;
#[cfg(feature = "tdx")]
const KVM_CAP_MAX_VCPUS_RAW: u32 = 66;
#[cfg(feature = "tdx")]
const KVM_CAP_EXCEPTION_PAYLOAD_RAW: u32 = 164;
#[cfg(feature = "tdx")]
const KVM_CAP_X86_USER_SPACE_MSR_RAW: u32 = 188;
#[cfg(feature = "tdx")]
const KVM_CAP_X86_TRIPLE_FAULT_EVENT_RAW: u32 = 218;
#[cfg(feature = "tdx")]
const KVM_CAP_X86_NOTIFY_VMEXIT_RAW: u32 = 219;
#[cfg(feature = "tdx")]
const KVM_CAP_MAX_VCPU_ID_RAW: u32 = 128;
#[cfg(feature = "tdx")]
const KVM_MEMORY_MAPPING_RAW: libc::c_ulong = 0xc020_aed5;
#[cfg(feature = "tdx")]
const KVM_X86_SETUP_MCE_RAW: libc::c_ulong = 0x4008_ae9c;
#[cfg(feature = "tdx")]
const KVM_X86_GET_MCE_CAP_SUPPORTED_RAW: libc::c_ulong = 0x8008_ae9d;
#[cfg(feature = "tdx")]
const MCG_CAP_BANKS_MASK: u64 = 0xff;
#[cfg(feature = "tdx")]
const DEFAULT_MCG_CAP: u64 = 0x100010a;
#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
static TDX_IO_EXIT_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
fn tdx_should_log_io(index: usize, port: u16) -> bool {
    if index < 512 {
        return true;
    }
    if (0xcf8..=0xcff).contains(&port) {
        return true;
    }

    matches!(
        port,
        0x20 | 0x21
            | 0x40..=0x43
            | 0x60
            | 0x61
            | 0x64
            | 0x70
            | 0x71
            | 0x80
            | 0x92
            | 0xa0
            | 0xa1
            | 0xb2
            | 0xb3
            | 0x510..=0x51b
            | 0x600..=0x60b
    ) && (index < 8192 || index % 4096 == 0)
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use crate::RegList;
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::regs;
#[cfg(target_arch = "x86_64")]
use crate::kvm::x86_64::XsaveStateError;

#[cfg(target_arch = "x86_64")]
ioctl_io_nr!(KVM_NMI, kvm_bindings::KVMIO, 0x9a);
#[cfg(feature = "tdx")]
ioctl_io_nr!(KVM_SET_TSC_KHZ_VM, kvm_bindings::KVMIO, 0xa2);

#[cfg(feature = "sev_snp")]
use igvm_defs::PAGE_SIZE_4K;
#[cfg(any(feature = "sev_snp", feature = "tdx"))]
use kvm_bindings::{KVM_MEMORY_ATTRIBUTE_PRIVATE, kvm_memory_attributes};
#[cfg(feature = "sev_snp")]
use kvm_bindings::{KVM_X86_SNP_VM, kvm_segment as Segment};
use vm_memory::GuestAddress;
#[cfg(feature = "sev_snp")]
use x86_64::sev;

// Hardcoded GPA of a bootloader and VMSA page for KVM
// TODO: Derive these from the IGVM file's PageData/SnpVpContext directives
// instead of using fixed constants, to support arbitrary bootloader layouts.
pub const BOOTLOADER_START: GuestAddress = GuestAddress(0xffc0_0000);
pub const BOOTLOADER_SIZE: usize = 0x40_0000; // 4 MiB
pub const KVM_VMSA_PAGE_ADDRESS: GuestAddress = GuestAddress(0xffff_ffff_f000);
pub const KVM_VMSA_PAGE_SIZE: usize = 0x1000; // 4 KiB

#[cfg(feature = "sev_snp")]
#[bitfield_struct::bitfield(u32)]
#[derive(PartialEq, Eq)]
/// AMD VMCB segment attributes
/// linux/arch/x86/include/asm/svm.h
pub struct SegAccess {
    #[bits(4)]
    pub seg_type: u8,
    pub s_code_data: bool,
    #[bits(2)]
    pub priv_level: u8,
    pub present: bool,
    pub available: bool,
    pub l_64bit: bool,
    pub db_size_32: bool,
    pub granularity: bool,
    #[bits(20)]
    _reserved: u32,
}

#[cfg(feature = "sev_snp")]
fn make_segment(sev_selector: igvm::snp_defs::SevSelector) -> Segment {
    let flags = SegAccess::from_bits(sev_selector.attrib.into());
    Segment {
        base: sev_selector.base,
        limit: sev_selector.limit,
        selector: sev_selector.selector,
        type_: flags.seg_type(),
        s: flags.s_code_data() as u8,
        dpl: flags.priv_level(),
        present: flags.present() as u8,
        avl: flags.available() as u8,
        db: flags.db_size_32() as u8,
        g: flags.granularity() as u8,
        l: flags.l_64bit() as u8,
        unusable: 0,
        ..Default::default()
    }
}

#[cfg(feature = "tdx")]
const KVM_EXIT_TDX: u32 = 50;
#[cfg(feature = "tdx")]
const KVM_EXIT_TDX_LEGACY: u32 = 40;
#[cfg(feature = "tdx")]
const TDG_VP_VMCALL_MAP_GPA: u64 = 0x10001;
#[cfg(feature = "tdx")]
const TDG_VP_VMCALL_GET_QUOTE: u64 = 0x10002;
#[cfg(feature = "tdx")]
const TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT: u64 = 0x10004;
#[cfg(feature = "tdx")]
const TDG_VP_VMCALL_SUCCESS: u64 = 0;
#[cfg(feature = "tdx")]
const TDG_VP_VMCALL_RETRY: u64 = 1;
#[cfg(feature = "tdx")]
const TDG_VP_VMCALL_INVALID_OPERAND: u64 = 0x8000000000000000;
#[cfg(feature = "tdx")]
const TDG_VP_VMCALL_ALIGN_ERROR: u64 = 0x8000000000000002;
#[cfg(feature = "tdx")]
const TDX_MAP_GPA_MAX_LEN: u64 = 64 * 1024 * 1024;

#[cfg(feature = "tdx")]
ioctl_iowr_nr!(KVM_MEMORY_ENCRYPT_OP, KVMIO, 0xba, std::os::raw::c_ulong);

#[cfg(feature = "tdx")]
#[repr(u32)]
enum TdxCommand {
    Capabilities = 0,
    InitVm,
    InitVcpu,
    InitMemRegion,
    Finalize,
    GetCpuid,
}

#[cfg(feature = "tdx")]
pub enum TdxExitDetails {
    MapGpa,
    GetQuote { gpa: u64, size: u64 },
    SetupEventNotifyInterrupt { vector: u64 },
}

#[cfg(feature = "tdx")]
pub enum TdxExitStatus {
    Success,
    InvalidOperand,
    AlignError,
    Retry(u64),
}

#[cfg(feature = "tdx")]
const TDX_MAX_NR_CPUID_CONFIGS: usize = 256;

#[cfg(feature = "tdx")]
const TDX_CPUID_NO_SUBLEAF: u32 = 0xffff_ffff;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_MSR: u32 = 1 << 5;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_PAE: u32 = 1 << 6;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_MCE: u32 = 1 << 7;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_APIC: u32 = 1 << 9;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_MTRR: u32 = 1 << 12;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_MCA: u32 = 1 << 14;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_CLFLUSH: u32 = 1 << 19;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_DTS: u32 = 1 << 21;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_ACPI: u32 = 1 << 22;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_IA64: u32 = 1 << 30;
#[cfg(feature = "tdx")]
const CPUID_1_EDX_PBE: u32 = 1 << 31;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_MONITOR: u32 = 1 << 3;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_VMX: u32 = 1 << 5;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_SMX: u32 = 1 << 6;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_EST: u32 = 1 << 7;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_TM2: u32 = 1 << 8;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_CX16: u32 = 1 << 13;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_XTPR: u32 = 1 << 14;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_PDCM: u32 = 1 << 15;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_DCA: u32 = 1 << 18;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_X2APIC: u32 = 1 << 21;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_AES: u32 = 1 << 25;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_XSAVE: u32 = 1 << 26;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_RDRAND: u32 = 1 << 30;
#[cfg(feature = "tdx")]
const CPUID_1_ECX_HYPERVISOR: u32 = 1 << 31;
#[cfg(feature = "tdx")]
const CPUID_EXT2_NX: u32 = 1 << 20;
#[cfg(feature = "tdx")]
const CPUID_EXT2_PDPE1GB: u32 = 1 << 26;
#[cfg(feature = "tdx")]
const CPUID_EXT2_RDTSCP: u32 = 1 << 27;
#[cfg(feature = "tdx")]
const CPUID_EXT2_LM: u32 = 1 << 29;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_FSGSBASE: u32 = 1 << 0;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_TSC_ADJUST: u32 = 1 << 1;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_SGX: u32 = 1 << 2;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_RTM: u32 = 1 << 11;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_PQM: u32 = 1 << 12;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_MPX: u32 = 1 << 14;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_RDT_A: u32 = 1 << 15;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_RDSEED: u32 = 1 << 18;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_SMAP: u32 = 1 << 20;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_CLFLUSHOPT: u32 = 1 << 23;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_CLWB: u32 = 1 << 24;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_INTEL_PT: u32 = 1 << 25;
#[cfg(feature = "tdx")]
const CPUID_7_0_EBX_SHA_NI: u32 = 1 << 29;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_TME: u32 = 1 << 13;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_FZM: u32 = 1 << 15;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_MAWAU: u32 = 31 << 17;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_KEY_LOCKER: u32 = 1 << 23;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_BUS_LOCK_DETECT: u32 = 1 << 24;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_MOVDIR64B: u32 = 1 << 28;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_ENQCMD: u32 = 1 << 29;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_SGX_LC: u32 = 1 << 30;
#[cfg(feature = "tdx")]
const CPUID_7_0_ECX_PKS: u32 = 1 << 31;
#[cfg(feature = "tdx")]
const CPUID_7_0_EDX_PCONFIG: u32 = 1 << 18;
#[cfg(feature = "tdx")]
const CPUID_7_0_EDX_SPEC_CTRL: u32 = 1 << 26;
#[cfg(feature = "tdx")]
const CPUID_7_0_EDX_ARCH_CAPABILITIES: u32 = 1 << 29;
#[cfg(feature = "tdx")]
const CPUID_7_0_EDX_CORE_CAPABILITY: u32 = 1 << 30;
#[cfg(feature = "tdx")]
const CPUID_7_0_EDX_SPEC_CTRL_SSBD: u32 = 1 << 31;
#[cfg(feature = "tdx")]
const CPUID_8000_0008_EBX_WBNOINVD: u32 = 1 << 9;
#[cfg(feature = "tdx")]
const CPUID_XSAVE_XSAVEOPT: u32 = 1 << 0;
#[cfg(feature = "tdx")]
const CPUID_XSAVE_XSAVEC: u32 = 1 << 1;
#[cfg(feature = "tdx")]
const CPUID_XSAVE_XSAVES: u32 = 1 << 3;
#[cfg(feature = "tdx")]
const CPUID_6_EAX_ARAT: u32 = 1 << 2;
#[cfg(feature = "tdx")]
const CPUID_XSTATE_XCR0_MASK: u64 = (1 << 0)
    | (1 << 1)
    | (1 << 2)
    | (1 << 3)
    | (1 << 4)
    | (1 << 5)
    | (1 << 6)
    | (1 << 7)
    | (1 << 9)
    | (1 << 17)
    | (1 << 18);
#[cfg(feature = "tdx")]
const CPUID_XSTATE_XSS_MASK: u64 = 1 << 15;
#[cfg(feature = "tdx")]
const TDX_SUPPORTED_KVM_FEATURES_LEGACY: u32 =
    (1 << 1) | (1 << 7) | (1 << 9) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 15);

#[cfg(feature = "tdx")]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct TdxCpuidConfigLegacy {
    leaf: u32,
    sub_leaf: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

#[cfg(feature = "tdx")]
#[repr(C)]
struct TdxCapabilitiesLegacy {
    attrs_fixed0: u64,
    attrs_fixed1: u64,
    xfam_fixed0: u64,
    xfam_fixed1: u64,
    supported_gpaw: u32,
    padding: u32,
    reserved: [u64; 251],
    nr_cpuid_configs: u32,
    cpuid_configs: [TdxCpuidConfigLegacy; TDX_MAX_NR_CPUID_CONFIGS],
}

#[cfg(feature = "tdx")]
impl Default for TdxCapabilitiesLegacy {
    fn default() -> Self {
        Self {
            attrs_fixed0: 0,
            attrs_fixed1: 0,
            xfam_fixed0: 0,
            xfam_fixed1: 0,
            supported_gpaw: 0,
            padding: 0,
            reserved: [0; 251],
            nr_cpuid_configs: TDX_MAX_NR_CPUID_CONFIGS as u32,
            cpuid_configs: [TdxCpuidConfigLegacy::default(); TDX_MAX_NR_CPUID_CONFIGS],
        }
    }
}

/// Convert a 48-byte measurement seed (mr* field) into the `[u64; 6]` shape
/// expected on the KVM_TDX_INIT_VM wire. Bytes are read as native (little-
/// endian on x86) so that the on-wire byte sequence is `mr[0..47]` exactly,
/// matching QEMU's `memcpy(init_vm->mrconfigid, data, data_len)` (raw byte
/// copy, no endianness conversion).
#[cfg(feature = "tdx")]
fn tdx_mr_seed_to_u64x6(seed: &[u8; 48]) -> [u64; 6] {
    let mut out = [0u64; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&seed[i * 8..(i + 1) * 8]);
        *slot = u64::from_ne_bytes(chunk);
    }
    out
}

/// Compose the requested TDX attribute mask from `TdxAttributes` flags.
#[cfg(feature = "tdx")]
fn tdx_requested_attributes(attrs: &TdxAttributes) -> u64 {
    let mut requested = 0u64;
    if attrs.sept_ve_disable {
        requested |= TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
    }
    if attrs.debug {
        requested |= TDX_TD_ATTRIBUTES_DEBUG;
    }
    if attrs.perfmon {
        requested |= TDX_TD_ATTRIBUTES_PERFMON;
    }
    requested
}

#[cfg(feature = "tdx")]
fn tdx_derive_xfam(cpuid: &[kvm_bindings::kvm_cpuid_entry2], supported_xfam: u64) -> u64 {
    let mut xcr0 = 0;
    let mut xss = 0;

    for entry in cpuid {
        if entry.function != 0xd {
            continue;
        }

        match entry.index {
            0 => {
                xcr0 = entry.eax as u64 | ((entry.edx as u64) << 32);
            }
            1 => {
                xss = entry.ecx as u64 | ((entry.edx as u64) << 32);
            }
            _ => {}
        }
    }

    (xcr0 | xss) & supported_xfam
}

#[cfg(feature = "tdx")]
fn tdx_legacy_cpuid_leaf_allowed(function: u32) -> bool {
    matches!(
        function,
        0x0000_0000
            | 0x0000_0001
            | 0x0000_0002
            | 0x0000_0004
            | 0x0000_0005
            | 0x0000_0006
            | 0x0000_0007
            | 0x0000_000b
            | 0x0000_000d
            | 0x0000_0012
            | 0x0000_0014
            | 0x0000_001d
            | 0x0000_001e
            | 0x4000_0000
            | 0x4000_0001
            | 0x8000_0000
            | 0x8000_0001
            | 0x8000_0002
            | 0x8000_0003
            | 0x8000_0004
            | 0x8000_0005
            | 0x8000_0006
            | 0x8000_0008
    )
}

#[cfg(feature = "tdx")]
fn tdx_legacy_cpuid_entry_allowed(entry: &kvm_bindings::kvm_cpuid_entry2) -> bool {
    if !tdx_legacy_cpuid_leaf_allowed(entry.function) {
        return false;
    }

    match entry.function {
        0x0000_0007 => entry.index <= 1,
        0x0000_000b => entry.index <= 2,
        0x0000_000d => matches!(entry.index, 0 | 1 | 2 | 5 | 6 | 7 | 9 | 15 | 17 | 18 | 63),
        _ => true,
    }
}

#[cfg(feature = "tdx")]
#[derive(Copy, Clone, Eq, PartialEq)]
enum TdxCpuidReg {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

#[cfg(feature = "tdx")]
#[derive(Copy, Clone)]
struct TdxCpuidRule {
    fixed0: u32,
    fixed1: u32,
    depends_on_vmm_cap: u32,
    inducing_ve: bool,
    supported_value_on_ve: u32,
}

#[cfg(feature = "tdx")]
fn tdx_legacy_cap_cpuid_config(
    caps: &TdxCapabilitiesLegacy,
    function: u32,
    index: u32,
    reg: TdxCpuidReg,
) -> u32 {
    let mut value = 0;
    let nent = (caps.nr_cpuid_configs as usize).min(TDX_MAX_NR_CPUID_CONFIGS);

    for config in caps.cpuid_configs.iter().take(nent) {
        if config.leaf == function
            && (config.sub_leaf == TDX_CPUID_NO_SUBLEAF || config.sub_leaf == index)
        {
            value = match reg {
                TdxCpuidReg::Eax => config.eax,
                TdxCpuidReg::Ebx => config.ebx,
                TdxCpuidReg::Ecx => config.ecx,
                TdxCpuidReg::Edx => config.edx,
            };
        }
    }

    value
}

#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
fn tdx_host_cpuid_reg(function: u32, index: u32, reg: TdxCpuidReg) -> u32 {
    // SAFETY: CPUID is supported on x86_64 and accepts arbitrary leaves.
    let cpuid = unsafe { std::arch::x86_64::__cpuid_count(function, index) };
    match reg {
        TdxCpuidReg::Eax => cpuid.eax,
        TdxCpuidReg::Ebx => cpuid.ebx,
        TdxCpuidReg::Ecx => cpuid.ecx,
        TdxCpuidReg::Edx => cpuid.edx,
    }
}

#[cfg(feature = "tdx")]
fn tdx_legacy_cpuid_rule(
    caps: &TdxCapabilitiesLegacy,
    function: u32,
    index: u32,
    reg: TdxCpuidReg,
) -> Option<TdxCpuidRule> {
    let mut rule = match (function, index, reg) {
        (0x0000_0001, _, TdxCpuidReg::Edx) => TdxCpuidRule {
            fixed0: (1 << 10) | (1 << 20) | CPUID_1_EDX_IA64,
            fixed1: CPUID_1_EDX_MSR
                | CPUID_1_EDX_PAE
                | CPUID_1_EDX_MCE
                | CPUID_1_EDX_APIC
                | CPUID_1_EDX_MTRR
                | CPUID_1_EDX_MCA
                | CPUID_1_EDX_CLFLUSH
                | CPUID_1_EDX_DTS,
            depends_on_vmm_cap: CPUID_1_EDX_ACPI | CPUID_1_EDX_PBE,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_0001, _, TdxCpuidReg::Ecx) => TdxCpuidRule {
            fixed0: CPUID_1_ECX_VMX | CPUID_1_ECX_SMX | (1 << 16),
            fixed1: CPUID_1_ECX_CX16
                | CPUID_1_ECX_PDCM
                | CPUID_1_ECX_X2APIC
                | CPUID_1_ECX_AES
                | CPUID_1_ECX_XSAVE
                | CPUID_1_ECX_RDRAND
                | CPUID_1_ECX_HYPERVISOR,
            depends_on_vmm_cap: CPUID_1_ECX_EST
                | CPUID_1_ECX_TM2
                | CPUID_1_ECX_XTPR
                | CPUID_1_ECX_DCA,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x8000_0001, _, TdxCpuidReg::Edx) => TdxCpuidRule {
            fixed0: 0,
            fixed1: CPUID_EXT2_NX | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP | CPUID_EXT2_LM,
            depends_on_vmm_cap: 0,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_0007, 0, TdxCpuidReg::Ebx) => TdxCpuidRule {
            fixed0: CPUID_7_0_EBX_TSC_ADJUST | CPUID_7_0_EBX_SGX | CPUID_7_0_EBX_MPX,
            fixed1: CPUID_7_0_EBX_FSGSBASE
                | CPUID_7_0_EBX_RTM
                | CPUID_7_0_EBX_RDSEED
                | CPUID_7_0_EBX_SMAP
                | CPUID_7_0_EBX_CLFLUSHOPT
                | CPUID_7_0_EBX_CLWB
                | CPUID_7_0_EBX_SHA_NI,
            depends_on_vmm_cap: CPUID_7_0_EBX_PQM | CPUID_7_0_EBX_RDT_A,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_0007, 0, TdxCpuidReg::Ecx) => TdxCpuidRule {
            fixed0: CPUID_7_0_ECX_FZM
                | CPUID_7_0_ECX_MAWAU
                | CPUID_7_0_ECX_ENQCMD
                | CPUID_7_0_ECX_SGX_LC,
            fixed1: CPUID_7_0_ECX_MOVDIR64B | CPUID_7_0_ECX_BUS_LOCK_DETECT,
            depends_on_vmm_cap: CPUID_7_0_ECX_TME,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_0007, 0, TdxCpuidReg::Edx) => TdxCpuidRule {
            fixed0: 0,
            fixed1: CPUID_7_0_EDX_SPEC_CTRL
                | CPUID_7_0_EDX_ARCH_CAPABILITIES
                | CPUID_7_0_EDX_CORE_CAPABILITY
                | CPUID_7_0_EDX_SPEC_CTRL_SSBD,
            depends_on_vmm_cap: CPUID_7_0_EDX_PCONFIG,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x8000_0008, _, TdxCpuidReg::Ebx) => TdxCpuidRule {
            fixed0: !CPUID_8000_0008_EBX_WBNOINVD,
            fixed1: CPUID_8000_0008_EBX_WBNOINVD,
            depends_on_vmm_cap: 0,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_000d, 1, TdxCpuidReg::Eax) => TdxCpuidRule {
            fixed0: 0,
            fixed1: CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC | CPUID_XSAVE_XSAVES,
            depends_on_vmm_cap: 0,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_0006, _, TdxCpuidReg::Eax) => TdxCpuidRule {
            fixed0: 0,
            fixed1: 0,
            depends_on_vmm_cap: 0,
            inducing_ve: true,
            supported_value_on_ve: CPUID_6_EAX_ARAT,
        },
        (0x8000_0007, _, TdxCpuidReg::Edx) => TdxCpuidRule {
            fixed0: 0,
            fixed1: 0,
            depends_on_vmm_cap: 0,
            inducing_ve: true,
            supported_value_on_ve: u32::MAX,
        },
        (0x4000_0001, _, TdxCpuidReg::Eax) => TdxCpuidRule {
            fixed0: 0,
            fixed1: 0,
            depends_on_vmm_cap: 0,
            inducing_ve: true,
            supported_value_on_ve: TDX_SUPPORTED_KVM_FEATURES_LEGACY,
        },
        (0x0000_000d, 0, TdxCpuidReg::Eax) => TdxCpuidRule {
            fixed0: (!caps.xfam_fixed0 & CPUID_XSTATE_XCR0_MASK) as u32,
            fixed1: (caps.xfam_fixed1 & CPUID_XSTATE_XCR0_MASK) as u32,
            depends_on_vmm_cap: 0,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_000d, 0, TdxCpuidReg::Edx) => TdxCpuidRule {
            fixed0: ((!caps.xfam_fixed0 & CPUID_XSTATE_XCR0_MASK) >> 32) as u32,
            fixed1: ((caps.xfam_fixed1 & CPUID_XSTATE_XCR0_MASK) >> 32) as u32,
            depends_on_vmm_cap: 0,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_000d, 1, TdxCpuidReg::Ecx) => TdxCpuidRule {
            fixed0: (!caps.xfam_fixed0 & CPUID_XSTATE_XSS_MASK) as u32,
            fixed1: (caps.xfam_fixed1 & CPUID_XSTATE_XSS_MASK) as u32,
            depends_on_vmm_cap: 0,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        (0x0000_000d, 1, TdxCpuidReg::Edx) => TdxCpuidRule {
            fixed0: ((!caps.xfam_fixed0 & CPUID_XSTATE_XSS_MASK) >> 32) as u32,
            fixed1: ((caps.xfam_fixed1 & CPUID_XSTATE_XSS_MASK) >> 32) as u32,
            depends_on_vmm_cap: 0,
            inducing_ve: false,
            supported_value_on_ve: 0,
        },
        _ => return None,
    };

    let config = tdx_legacy_cap_cpuid_config(caps, function, index, reg);
    rule.fixed0 &= !config;
    rule.fixed1 &= !config;

    match (function, reg) {
        (0x0000_0007, TdxCpuidReg::Ecx) => {
            if caps.attrs_fixed0 & (1 << 30) == 0 {
                rule.fixed0 |= CPUID_7_0_ECX_PKS;
            }
            if caps.attrs_fixed1 & (1 << 30) != 0 {
                rule.fixed1 |= CPUID_7_0_ECX_PKS;
            }
            if caps.attrs_fixed0 & (1 << 31) == 0 {
                rule.fixed0 |= CPUID_7_0_ECX_KEY_LOCKER;
            }
            if caps.attrs_fixed1 & (1 << 31) != 0 {
                rule.fixed1 |= CPUID_7_0_ECX_KEY_LOCKER;
            }
        }
        _ => {}
    }

    Some(rule)
}

#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
fn tdx_legacy_supported_cpuid_reg(
    caps: &TdxCapabilitiesLegacy,
    function: u32,
    index: u32,
    reg: TdxCpuidReg,
    vmm_cap: u32,
) -> u32 {
    let Some(rule) = tdx_legacy_cpuid_rule(caps, function, index, reg) else {
        return vmm_cap;
    };

    if rule.inducing_ve {
        return vmm_cap & rule.supported_value_on_ve;
    }

    let mut value = vmm_cap | tdx_host_cpuid_reg(function, index, reg);
    value |= rule.fixed1;
    value &= !rule.fixed0;
    value |= tdx_legacy_cap_cpuid_config(caps, function, index, reg);
    value &= !(rule.depends_on_vmm_cap & !vmm_cap);

    if function == 0x0000_0001 && reg == TdxCpuidReg::Ecx {
        value &= !CPUID_1_ECX_MONITOR;
    }
    if function == 0x0000_0007 && reg == TdxCpuidReg::Ebx {
        value &= !CPUID_7_0_EBX_INTEL_PT;
    }

    value
}

#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
fn tdx_legacy_filter_cpuid_entry(
    caps: &TdxCapabilitiesLegacy,
    entry: &mut kvm_bindings::kvm_cpuid_entry2,
) {
    entry.eax = tdx_legacy_supported_cpuid_reg(
        caps,
        entry.function,
        entry.index,
        TdxCpuidReg::Eax,
        entry.eax,
    );
    entry.ebx = tdx_legacy_supported_cpuid_reg(
        caps,
        entry.function,
        entry.index,
        TdxCpuidReg::Ebx,
        entry.ebx,
    );
    entry.ecx = tdx_legacy_supported_cpuid_reg(
        caps,
        entry.function,
        entry.index,
        TdxCpuidReg::Ecx,
        entry.ecx,
    );
    entry.edx = tdx_legacy_supported_cpuid_reg(
        caps,
        entry.function,
        entry.index,
        TdxCpuidReg::Edx,
        entry.edx,
    );

    match entry.function {
        0x0000_000b => {
            entry.ecx = (entry.ecx & !0xff) | entry.index;
        }
        0x0000_0012 | 0x0000_0014 => {
            entry.eax = 0;
            entry.ebx = 0;
            entry.ecx = 0;
            entry.edx = 0;
        }
        0x4000_0000 => {
            entry.eax = 0x4000_0001;
        }
        _ => {}
    }
}

#[cfg(all(feature = "tdx", target_arch = "x86_64"))]
fn tdx_legacy_cpuid_entries(
    caps: &TdxCapabilitiesLegacy,
    cpuid: &[CpuIdEntry],
) -> Vec<kvm_bindings::kvm_cpuid_entry2> {
    cpuid
        .iter()
        .map(|entry| (*entry).into())
        .filter(tdx_legacy_cpuid_entry_allowed)
        .map(|mut entry| {
            tdx_legacy_filter_cpuid_entry(caps, &mut entry);
            entry
        })
        .collect()
}

#[cfg(feature = "tdx")]
#[repr(C)]
#[derive(Debug)]
pub struct TdxCapabilities {
    pub supported_attrs: u64,
    pub supported_xfam: u64,
    pub kernel_tdvmcallinfo_1_r11: u64,
    pub user_tdvmcallinfo_1_r11: u64,
    pub kernel_tdvmcallinfo_1_r12: u64,
    pub user_tdvmcallinfo_1_r12: u64,
    pub reserved: [u64; 250],
    pub cpuid_nent: u32,
    pub cpuid_padding: u32,
    pub cpuid_configs: [kvm_bindings::kvm_cpuid_entry2; TDX_MAX_NR_CPUID_CONFIGS],
}

#[cfg(feature = "tdx")]
impl Default for TdxCapabilities {
    fn default() -> Self {
        Self {
            supported_attrs: 0,
            supported_xfam: 0,
            kernel_tdvmcallinfo_1_r11: 0,
            user_tdvmcallinfo_1_r11: 0,
            kernel_tdvmcallinfo_1_r12: 0,
            user_tdvmcallinfo_1_r12: 0,
            reserved: [0; 250],
            cpuid_nent: 0,
            cpuid_padding: 0,
            cpuid_configs: [kvm_bindings::kvm_cpuid_entry2::default(); TDX_MAX_NR_CPUID_CONFIGS],
        }
    }
}

#[cfg(feature = "tdx")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct KvmTdxExit {
    pub type_: u32,
    pub pad: u32,
    pub u: KvmTdxExitU,
}

#[cfg(feature = "tdx")]
#[repr(C)]
#[derive(Copy, Clone)]
pub union KvmTdxExitU {
    pub vmcall: KvmTdxExitVmcall,
}

#[cfg(feature = "tdx")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct KvmTdxExitVmcall {
    pub reg_mask: u64,
    pub type_: u64,
    pub subfunction: u64,
    pub in_r12: u64,
    pub in_r13: u64,
    pub in_r14: u64,
    pub in_r15: u64,
    pub in_rbx: u64,
    pub in_rdi: u64,
    pub in_rsi: u64,
    pub in_r8: u64,
    pub in_r9: u64,
    pub in_rdx: u64,
    pub status_code: u64,
    pub out_r11: u64,
    pub out_r12: u64,
    pub out_r13: u64,
    pub out_r14: u64,
    pub out_r15: u64,
    pub out_rbx: u64,
    pub out_rdi: u64,
    pub out_rsi: u64,
    pub out_r8: u64,
    pub out_r9: u64,
    pub out_rdx: u64,
}

impl From<kvm_userspace_memory_region2> for UserMemoryRegion {
    fn from(region: kvm_userspace_memory_region2) -> Self {
        let mut flags = USER_MEMORY_REGION_READ;
        if region.flags & KVM_MEM_READONLY == 0 {
            flags |= USER_MEMORY_REGION_WRITE;
        }
        if region.flags & KVM_MEM_LOG_DIRTY_PAGES != 0 {
            flags |= USER_MEMORY_REGION_LOG_DIRTY;
        }
        if region.flags & KVM_MEM_GUEST_MEMFD != 0 {
            flags |= USER_MEMORY_REGION_GUEST_MEMFD;
        }

        UserMemoryRegion {
            slot: region.slot,
            guest_phys_addr: region.guest_phys_addr,
            memory_size: region.memory_size,
            userspace_addr: region.userspace_addr,
            flags,
            guest_memfd: Some(region.guest_memfd),
            guest_memfd_offset: Some(region.guest_memfd_offset),
        }
    }
}

impl From<UserMemoryRegion> for kvm_userspace_memory_region2 {
    fn from(region: UserMemoryRegion) -> Self {
        assert!(
            region.flags & USER_MEMORY_REGION_READ != 0,
            "KVM mapped memory is always readable"
        );

        let mut flags = 0;
        if region.flags & USER_MEMORY_REGION_WRITE == 0 {
            flags |= KVM_MEM_READONLY;
        }
        if region.flags & USER_MEMORY_REGION_LOG_DIRTY != 0 {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }
        if region.flags & USER_MEMORY_REGION_GUEST_MEMFD != 0 {
            flags |= KVM_MEM_GUEST_MEMFD;
        }

        kvm_userspace_memory_region2 {
            slot: region.slot,
            guest_phys_addr: region.guest_phys_addr,
            memory_size: region.memory_size,
            userspace_addr: region.userspace_addr,
            flags,
            guest_memfd: region.guest_memfd.unwrap_or(0),
            guest_memfd_offset: region.guest_memfd_offset.unwrap_or(0),
            ..Default::default()
        }
    }
}
impl From<kvm_mp_state> for MpState {
    fn from(s: kvm_mp_state) -> Self {
        MpState::Kvm(s)
    }
}

impl From<MpState> for kvm_mp_state {
    fn from(ms: MpState) -> Self {
        match ms {
            MpState::Kvm(s) => s,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("CpuState is not valid"),
        }
    }
}

impl From<kvm_ioctls::IoEventAddress> for IoEventAddress {
    fn from(a: kvm_ioctls::IoEventAddress) -> Self {
        match a {
            kvm_ioctls::IoEventAddress::Pio(x) => Self::Pio(x),
            kvm_ioctls::IoEventAddress::Mmio(x) => Self::Mmio(x),
        }
    }
}

impl From<IoEventAddress> for kvm_ioctls::IoEventAddress {
    fn from(a: IoEventAddress) -> Self {
        match a {
            IoEventAddress::Pio(x) => Self::Pio(x),
            IoEventAddress::Mmio(x) => Self::Mmio(x),
        }
    }
}

impl From<VcpuKvmState> for CpuState {
    fn from(s: VcpuKvmState) -> Self {
        CpuState::Kvm(s)
    }
}

impl From<CpuState> for VcpuKvmState {
    fn from(s: CpuState) -> Self {
        match s {
            CpuState::Kvm(s) => s,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("CpuState is not valid"),
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl From<kvm_clock_data> for ClockData {
    fn from(d: kvm_clock_data) -> Self {
        ClockData::Kvm(d)
    }
}

#[cfg(target_arch = "x86_64")]
impl From<ClockData> for kvm_clock_data {
    fn from(ms: ClockData) -> Self {
        match ms {
            ClockData::Kvm(s) => s,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("CpuState is not valid"),
        }
    }
}

impl From<kvm_bindings::kvm_one_reg> for crate::Register {
    fn from(s: kvm_bindings::kvm_one_reg) -> Self {
        crate::Register::Kvm(s)
    }
}

impl From<crate::Register> for kvm_bindings::kvm_one_reg {
    fn from(e: crate::Register) -> Self {
        match e {
            crate::Register::Kvm(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("Register is not valid"),
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl From<kvm_bindings::kvm_vcpu_init> for crate::VcpuInit {
    fn from(s: kvm_bindings::kvm_vcpu_init) -> Self {
        crate::VcpuInit::Kvm(s)
    }
}

#[cfg(target_arch = "aarch64")]
impl From<crate::VcpuInit> for kvm_bindings::kvm_vcpu_init {
    fn from(e: crate::VcpuInit) -> Self {
        match e {
            crate::VcpuInit::Kvm(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("VcpuInit is not valid"),
        }
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl From<kvm_bindings::RegList> for crate::RegList {
    fn from(s: kvm_bindings::RegList) -> Self {
        crate::RegList::Kvm(s)
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl From<crate::RegList> for kvm_bindings::RegList {
    fn from(e: crate::RegList) -> Self {
        match e {
            crate::RegList::Kvm(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("RegList is not valid"),
        }
    }
}

#[cfg(not(target_arch = "riscv64"))]
impl From<kvm_bindings::kvm_regs> for crate::StandardRegisters {
    fn from(s: kvm_bindings::kvm_regs) -> Self {
        crate::StandardRegisters::Kvm(s)
    }
}

#[cfg(not(target_arch = "riscv64"))]
impl From<crate::StandardRegisters> for kvm_bindings::kvm_regs {
    fn from(e: crate::StandardRegisters) -> Self {
        match e {
            crate::StandardRegisters::Kvm(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("StandardRegisters are not valid"),
        }
    }
}

#[cfg(target_arch = "riscv64")]
impl From<kvm_bindings::kvm_riscv_core> for crate::StandardRegisters {
    fn from(s: kvm_bindings::kvm_riscv_core) -> Self {
        crate::StandardRegisters::Kvm(s)
    }
}

#[cfg(target_arch = "riscv64")]
impl From<crate::StandardRegisters> for kvm_bindings::kvm_riscv_core {
    fn from(e: crate::StandardRegisters) -> Self {
        match e {
            crate::StandardRegisters::Kvm(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("StandardRegisters are not valid"),
        }
    }
}

impl From<kvm_irq_routing_entry> for IrqRoutingEntry {
    fn from(s: kvm_irq_routing_entry) -> Self {
        IrqRoutingEntry::Kvm(s)
    }
}

impl From<IrqRoutingEntry> for kvm_irq_routing_entry {
    fn from(e: IrqRoutingEntry) -> Self {
        match e {
            IrqRoutingEntry::Kvm(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("IrqRoutingEntry is not valid"),
        }
    }
}

struct KvmDirtyLogSlot {
    slot: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    // Following fields are used by kvm_userspace_memory_region2.
    guest_memfd_offset: u64,
    guest_memfd: u32,
}

#[cfg(any(feature = "sev_snp", feature = "tdx"))]
#[derive(Clone, Copy)]
struct KvmGuestMemSlot {
    slot: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    flags: u32,
    guest_memfd_offset: u64,
    guest_memfd: u32,
}

#[cfg(any(feature = "sev_snp", feature = "tdx"))]
const KVM_GUEST_MEMFD_ALLOW_HUGEPAGE_RAW: u64 = 1 << 0;
#[cfg(any(feature = "sev_snp", feature = "tdx"))]
const KVM_GUEST_MEMFD_HUGEPAGE_SIZE: u64 = 2 * 1024 * 1024;

#[cfg(any(feature = "sev_snp", feature = "tdx"))]
fn guest_memfd_create_flags(size: u64, legacy_hugepage: bool) -> u64 {
    if legacy_hugepage && size % KVM_GUEST_MEMFD_HUGEPAGE_SIZE == 0 {
        KVM_GUEST_MEMFD_ALLOW_HUGEPAGE_RAW
    } else {
        0
    }
}

#[cfg(any(feature = "sev_snp", feature = "tdx"))]
fn create_guest_memfd(
    vm_fd: &VmFd,
    size: u64,
    legacy_hugepage: bool,
) -> result::Result<OwnedFd, kvm_ioctls::Error> {
    let flags = guest_memfd_create_flags(size, legacy_hugepage);
    let create = |flags| {
        vm_fd.create_guest_memfd(kvm_create_guest_memfd {
            size,
            flags,
            ..Default::default()
        })
    };

    match create(flags) {
        // SAFETY: KVM returned a new owned file descriptor.
        Ok(fd) => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
        Err(e) if flags != 0 && e.errno() == libc::EINVAL => {
            // Older kernels may expose guest_memfd without accepting the hugepage
            // flag. Fall back to the baseline ABI in that case.
            create(0).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        }
        Err(e) => Err(e),
    }
}

/// Wrapper over KVM VM ioctls.
pub struct KvmVm {
    fd: Arc<VmFd>,
    #[cfg(all(feature = "tdx", target_arch = "x86_64"))]
    kvm_fd: RawFd,
    #[cfg(target_arch = "x86_64")]
    msrs: Vec<MsrEntry>,
    #[cfg(all(feature = "sev_snp", target_arch = "x86_64"))]
    sev_fd: Option<x86_64::sev::SevFd>,
    dirty_log_slots: RwLock<HashMap<u32, KvmDirtyLogSlot>>,
    guest_memfds: Option<Arc<RwLock<HashMap<u32, OwnedFd>>>>,
    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    guest_memfd_legacy_hugepage: bool,
    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    guest_mem_slots: Option<Arc<RwLock<HashMap<u32, KvmGuestMemSlot>>>>,
    #[cfg(feature = "tdx")]
    tdx_legacy_vm_type: bool,
}

impl KvmVm {
    ///
    /// Creates an emulated device in the kernel.
    ///
    /// See the documentation for `KVM_CREATE_DEVICE`.
    fn create_device(&self, device: &mut CreateDevice) -> vm::Result<vfio_ioctls::VfioDeviceFd> {
        let device_fd = self
            .fd
            .create_device(device)
            .map_err(|e| vm::HypervisorVmError::CreateDevice(e.into()))?;
        Ok(VfioDeviceFd::new_from_kvm(device_fd))
    }

    /// Create a `KVM_DEV_TYPE_VFIO` anchor device on this VM.
    ///
    /// This is the device that VFIO group/cdev fds get attached to via
    /// `KVM_DEV_VFIO_FILE_ADD` so that KVM can track which VFIO ranges are
    /// pinned by the IOMMU. CH normally relies on `vfio-ioctls` to wire this
    /// up automatically (it calls `KVM_DEV_VFIO_FILE_ADD/DEL` internally on
    /// `VfioContainer`/`VfioIommufd` when given a passthrough device handle),
    /// but this helper exists for callers that want to drive the attachment
    /// directly.
    pub fn create_kvm_vfio_device(&self) -> vm::Result<DeviceFd> {
        let mut vfio_dev = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };
        self.fd
            .create_device(&mut vfio_dev)
            .map_err(|e| vm::HypervisorVmError::CreateDevice(e.into()))
    }

    /// Add a VFIO group / cdev fd to a `KVM_DEV_TYPE_VFIO` device using
    /// `KVM_DEV_VFIO_FILE_ADD`.
    pub fn kvm_vfio_add_fd(&self, dev: &DeviceFd, fd: RawFd) -> vm::Result<()> {
        let fd_ptr = &fd as *const RawFd;
        let attr = DeviceAttr {
            flags: 0,
            group: KVM_DEV_VFIO_FILE,
            attr: u64::from(KVM_DEV_VFIO_FILE_ADD),
            addr: fd_ptr as u64,
        };
        dev.set_device_attr(&attr)
            .map_err(|e| vm::HypervisorVmError::SetVfioDeviceFd(e.into()))
    }

    /// Remove a VFIO group / cdev fd from a `KVM_DEV_TYPE_VFIO` device using
    /// `KVM_DEV_VFIO_FILE_DEL`.
    pub fn kvm_vfio_del_fd(&self, dev: &DeviceFd, fd: RawFd) -> vm::Result<()> {
        let fd_ptr = &fd as *const RawFd;
        let attr = DeviceAttr {
            flags: 0,
            group: KVM_DEV_VFIO_FILE,
            attr: u64::from(KVM_DEV_VFIO_FILE_DEL),
            addr: fd_ptr as u64,
        };
        dev.set_device_attr(&attr)
            .map_err(|e| vm::HypervisorVmError::SetVfioDeviceFd(e.into()))
    }

    /// Checks if a particular `Cap` is available.
    pub fn check_extension(&self, c: Cap) -> bool {
        self.fd.check_extension(c)
    }

    #[cfg(target_arch = "x86_64")]
    /// Translates the MSI extended destination ID bits according to the logic
    /// found in the Linux kernel's KVM MSI handling in kvm_msi_to_lapic_irq()/x86_msi_msg_get_destid():
    /// https://github.com/torvalds/linux/blob/3957a5720157264dcc41415fbec7c51c4000fc2d/arch/x86/kvm/irq.c#L266
    /// https://github.com/torvalds/linux/blob/3957a5720157264dcc41415fbec7c51c4000fc2d/arch/x86/kernel/apic/apic.c#L2306
    ///
    /// This function moves bits [11, 5] from `address_lo` to bits [46, 40] in the combined 64-bit
    /// address, but only if the Remappable Format (RF) bit (bit 4) in `address_lo` is
    /// not set and `address_hi` is zero.
    ///
    /// The function is roughly equivalent to `uint64_t kvm_swizzle_msi_ext_dest_id(uint64_t address)` in
    /// qemu/target/i386/kvm/kvm.c:
    /// https://github.com/qemu/qemu/blob/88f72048d2f5835a1b9eaba690c7861393aef283/target/i386/kvm/kvm.c#L6258
    fn translate_msi_ext_dest_id(mut address_lo: u32, mut address_hi: u32) -> (u32, u32) {
        // Mask for extracting the RF (Remappable Format) bit from address_lo.
        // In the MSI specification, this is bit 4. See
        // VT-d spec section "Interrupt Requests in Remappable Format"
        const REMAPPABLE_FORMAT_BIT_MASK: u32 = 0x10;
        let remappable_format_bit_is_set = (address_lo & REMAPPABLE_FORMAT_BIT_MASK) != 0;

        // Only perform the bit swizzling if the RF bit is unset and the upper
        // 32 bits of the address are all zero. This identifies the legacy format.
        if address_hi == 0 && !remappable_format_bit_is_set {
            // "Move" the bits [11,5] to bits [46,40]. This is a shift of 35 bits, but
            // since address is already split up into lo and hi, it's only a shift of
            // 3 (35 - 32) within hi.
            // "Move" via getting the bits via mask, zeroing out that range, and then
            // ORing them back in at the correct location. The destination was already
            // checked to be all zeroes.
            const EXT_ID_MASK: u32 = 0xfe0;
            const EXT_ID_SHIFT: u32 = 3;
            let ext_id = address_lo & EXT_ID_MASK;
            address_lo &= !EXT_ID_MASK;
            address_hi |= ext_id << EXT_ID_SHIFT;
        }

        (address_lo, address_hi)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn translate_msi_ext_dest_id(address_lo: u32, address_hi: u32) -> (u32, u32) {
        (address_lo, address_hi)
    }

    /// Set user memory region to use guest_memfd when available.
    /// guest_memfd is available on host linux kernel v6.8+
    ///
    /// # Safety
    ///
    /// `region.userspace_addr` must point to `region.memory_size` bytes of
    /// memory that will stay mapped until the slot is removed via
    /// `remove_user_memory_region`. The memory region must
    /// be uniquely owned by the caller, as mapping it into the guest
    /// effectively creates a long-lived mutable reference.
    unsafe fn set_user_memory_region(
        &self,
        region: kvm_userspace_memory_region2,
    ) -> Result<(), errno::Error> {
        if self.guest_memfds.is_some() {
            // SAFETY: Safe as the caller guarantees that region is safe to map
            // the guest and is non-overlapping.
            unsafe { self.fd.set_user_memory_region2(region) }
        } else {
            // SAFETY: Safe because guest regions are guaranteed not to overlap.
            unsafe {
                self.fd.set_user_memory_region(kvm_userspace_memory_region {
                    slot: region.slot,
                    guest_phys_addr: region.guest_phys_addr,
                    userspace_addr: region.userspace_addr,
                    flags: region.flags,
                    memory_size: region.memory_size,
                })
            }
        }
    }

    /// Get flag for kvm_userspace_memory_region based on memfd support.
    fn get_kvm_userspace_memory_region_flag(&self, flag: u32) -> u32 {
        flag | if self.guest_memfds.is_some() {
            KVM_MEM_GUEST_MEMFD
        } else {
            0
        }
    }
}

/// Implementation of Vm trait for KVM
///
/// # Examples
///
/// ```
/// # use hypervisor::kvm::KvmHypervisor;
/// # use hypervisor::HypervisorVmConfig;
/// # use std::sync::Arc;
/// let kvm = KvmHypervisor::new().unwrap();
/// let hypervisor = Arc::new(kvm);
/// let vm = hypervisor.create_vm(HypervisorVmConfig::default()).expect("new VM fd creation failed");
/// ```
impl vm::Vm for KvmVm {
    #[cfg(all(feature = "sev_snp", target_arch = "x86_64"))]
    fn sev_snp_init(&self, guest_policy: igvm_defs::SnpPolicy) -> vm::Result<()> {
        self.sev_fd
            .as_ref()
            .unwrap()
            .launch_start(&self.fd, guest_policy)
            .map_err(|e| vm::HypervisorVmError::InitializeSevSnp(e.into()))
    }

    #[cfg(all(feature = "sev_snp", target_arch = "x86_64"))]
    fn import_isolated_pages(
        &self,
        page_type: u32,
        page_size: u32,
        // host page frame numbers
        pfns: &[u64],
        uaddrs: &[u64],
    ) -> vm::Result<()> {
        if pfns.is_empty() {
            return Ok(());
        }
        assert_eq!(pfns.len(), uaddrs.len());
        // VMSA pages are not supported by launch_update
        // https://elixir.bootlin.com/linux/v6.11/source/arch/x86/kvm/svm/sev.c#L2377
        if page_type == sev::SNP_PAGE_TYPE_VMSA {
            return Ok(());
        }
        for i in 0..pfns.len() {
            self.fd
                .set_memory_attributes(kvm_memory_attributes {
                    address: pfns[i] << sev::GPA_METADATA_SHIFT_OFFSET,
                    size: page_size as u64,
                    attributes: kvm_bindings::KVM_MEMORY_ATTRIBUTE_PRIVATE as u64,
                    // Flags must be zero o/w error (flags aren't being used here yet)
                    flags: 0,
                })
                .map_err(|e| vm::HypervisorVmError::ImportIsolatedPages(e.into()))?;
            self.sev_fd
                .as_ref()
                .unwrap()
                .launch_update(&self.fd, uaddrs[i], page_size as u64, pfns[i], page_type)
                .map_err(|e| vm::HypervisorVmError::ImportIsolatedPages(e.into()))?;
        }

        Ok(())
    }

    #[cfg(all(feature = "sev_snp", target_arch = "x86_64"))]
    fn complete_isolated_import(
        &self,
        snp_id_block: igvm_defs::IGVM_VHS_SNP_ID_BLOCK,
        host_data: [u8; 32],
        id_block_enabled: u8,
    ) -> vm::Result<()> {
        self.sev_fd
            .as_ref()
            .unwrap()
            .launch_finish(
                &self.fd,
                host_data,
                id_block_enabled,
                snp_id_block.author_key_enabled,
            )
            .map_err(|e| vm::HypervisorVmError::CompleteIsolatedImport(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the one-page region in the VM's address space.
    ///
    fn set_identity_map_address(&self, address: u64) -> vm::Result<()> {
        self.fd
            .set_identity_map_address(address)
            .map_err(|e| vm::HypervisorVmError::SetIdentityMapAddress(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the three-page region in the VM's address space.
    ///
    fn set_tss_address(&self, offset: usize) -> vm::Result<()> {
        self.fd
            .set_tss_address(offset)
            .map_err(|e| vm::HypervisorVmError::SetTssAddress(e.into()))
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    ///
    /// Creates an in-kernel interrupt controller.
    ///
    fn create_irq_chip(&self) -> vm::Result<()> {
        self.fd
            .create_irq_chip()
            .map_err(|e| vm::HypervisorVmError::CreateIrq(e.into()))
    }

    ///
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        self.fd
            .register_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))
    }

    ///
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        self.fd
            .unregister_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::UnregisterIrqFd(e.into()))
    }

    ///
    /// Creates a VcpuFd object from a vcpu RawFd.
    ///
    fn create_vcpu(
        &self,
        id: u32,
        vm_ops: Option<Arc<dyn VmOps>>,
    ) -> vm::Result<Box<dyn cpu::Vcpu>> {
        let fd = self
            .fd
            .create_vcpu(id as u64)
            .map_err(|e| vm::HypervisorVmError::CreateVcpu(e.into()))?;

        #[cfg(target_arch = "x86_64")]
        // Safety: `xsave_size` will not change after vcpu creation because:
        // 1. `xsave_size` depends on cpuid
        // 2. The only factor that affects cpuid is xsave permission, obtained via
        // `ARCH_GET_XCOMP_GUEST_PERM`
        // 3. This permission is already acquired before vcpu creation
        // Therefore, cpuid remains unchanged after vcpu creation, and so does `xsave_size`.
        //
        // First vCPU allocation locks the permissions of  `ARCH_GET_XCOMP_GUEST_PERM`.
        let xsave_size = self.fd.check_extension_int(Cap::Xsave2);
        let vcpu = KvmVcpu {
            fd,
            #[cfg(target_arch = "x86_64")]
            msrs: self.msrs.clone(),
            vm_ops,
            #[cfg(target_arch = "x86_64")]
            hyperv_synic: AtomicBool::new(false),
            #[cfg(target_arch = "x86_64")]
            xsave_size,
            #[cfg(all(feature = "tdx", target_arch = "x86_64"))]
            kvm_fd: self.kvm_fd,
            #[cfg(any(feature = "sev_snp", feature = "tdx"))]
            vm_fd: self.fd.clone(),
            #[cfg(any(feature = "sev_snp", feature = "tdx"))]
            guest_memfds: self.guest_memfds.clone(),
            #[cfg(any(feature = "sev_snp", feature = "tdx"))]
            guest_memfd_legacy_hugepage: self.guest_memfd_legacy_hugepage,
            #[cfg(any(feature = "sev_snp", feature = "tdx"))]
            guest_mem_slots: self.guest_mem_slots.clone(),
            #[cfg(feature = "tdx")]
            tdx_legacy_cpuid: self.tdx_legacy_vm_type,
            #[cfg(feature = "tdx")]
            tdx_fw_cfg_dma_hi: 0,
            #[cfg(feature = "tdx")]
            tdx_pending_shared_2m_ranges: Mutex::new(HashMap::new()),
        };
        Ok(Box::new(vcpu))
    }

    #[cfg(target_arch = "aarch64")]
    ///
    /// Creates a virtual GIC device.
    ///
    fn create_vgic(&self, config: &VgicConfig) -> vm::Result<Arc<Mutex<dyn Vgic>>> {
        let gic_device = KvmGicV3Its::new(self, config)
            .map_err(|e| vm::HypervisorVmError::CreateVgic(anyhow!("Vgic error {e:?}")))?;
        Ok(Arc::new(Mutex::new(gic_device)))
    }

    #[cfg(target_arch = "riscv64")]
    ///
    /// Creates a virtual AIA device.
    ///
    fn create_vaia(&self, config: &VaiaConfig) -> vm::Result<Arc<Mutex<dyn Vaia>>> {
        let aia_device = KvmAiaImsics::new(self, config)
            .map_err(|e| vm::HypervisorVmError::CreateVaia(anyhow!("Vaia error {e:?}")))?;
        Ok(Arc::new(Mutex::new(aia_device)))
    }

    ///
    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<vm::DataMatch>,
    ) -> vm::Result<()> {
        let addr = &kvm_ioctls::IoEventAddress::from(*addr);
        if let Some(dm) = datamatch {
            match dm {
                vm::DataMatch::DataMatch32(kvm_dm32) => self
                    .fd
                    .register_ioevent(fd, addr, kvm_dm32)
                    .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into())),
                vm::DataMatch::DataMatch64(kvm_dm64) => self
                    .fd
                    .register_ioevent(fd, addr, kvm_dm64)
                    .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into())),
            }
        } else {
            self.fd
                .register_ioevent(fd, addr, NoDatamatch)
                .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into()))
        }
    }

    ///
    /// Unregisters an event from a certain address it has been previously registered to.
    ///
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> vm::Result<()> {
        let addr = &kvm_ioctls::IoEventAddress::from(*addr);
        self.fd
            .unregister_ioevent(fd, addr, NoDatamatch)
            .map_err(|e| vm::HypervisorVmError::UnregisterIoEvent(e.into()))
    }

    ///
    /// Constructs a routing entry
    ///
    fn make_routing_entry(&self, gsi: u32, config: &InterruptSourceConfig) -> IrqRoutingEntry {
        match &config {
            InterruptSourceConfig::MsiIrq(cfg) => {
                let mut kvm_route = kvm_irq_routing_entry {
                    gsi,
                    type_: KVM_IRQ_ROUTING_MSI,
                    ..Default::default()
                };

                let (address_lo, address_hi) =
                    Self::translate_msi_ext_dest_id(cfg.low_addr, cfg.high_addr);

                kvm_route.u.msi.address_lo = address_lo;
                kvm_route.u.msi.address_hi = address_hi;

                kvm_route.u.msi.data = cfg.data;

                if self.check_extension(crate::kvm::Cap::MsiDevid) {
                    // On AArch64, there is limitation on the range of the 'devid',
                    // it cannot be greater than 65536 (the max of u16).
                    //
                    // BDF cannot be used directly, because 'segment' is in high
                    // 16 bits. The layout of the u32 BDF is:
                    // |---- 16 bits ----|-- 8 bits --|-- 5 bits --|-- 3 bits --|
                    // |      segment    |     bus    |   device   |  function  |
                    //
                    // Now that we support 1 bus only in a segment, we can build a
                    // 'devid' by replacing the 'bus' bits with the low 8 bits of
                    // 'segment' data.
                    // This way we can resolve the range checking problem and give
                    // different `devid` to all the devices. Limitation is that at
                    // most 256 segments can be supported.
                    //
                    let modified_devid = ((cfg.devid & 0x00ff_0000) >> 8) | cfg.devid & 0xff;

                    kvm_route.flags = KVM_MSI_VALID_DEVID;
                    kvm_route.u.msi.__bindgen_anon_1.devid = modified_devid;
                }
                kvm_route.into()
            }
            InterruptSourceConfig::LegacyIrq(cfg) => {
                let mut kvm_route = kvm_irq_routing_entry {
                    gsi,
                    type_: KVM_IRQ_ROUTING_IRQCHIP,
                    ..Default::default()
                };
                kvm_route.u.irqchip.irqchip = cfg.irqchip;
                kvm_route.u.irqchip.pin = cfg.pin;

                kvm_route.into()
            }
        }
    }

    ///
    /// Sets the GSI routing table entries, overwriting any previously set
    /// entries, as per the `KVM_SET_GSI_ROUTING` ioctl.
    ///
    fn set_gsi_routing(&self, entries: &[IrqRoutingEntry]) -> vm::Result<()> {
        let entries: Vec<kvm_irq_routing_entry> = entries
            .iter()
            .map(|entry| match entry {
                IrqRoutingEntry::Kvm(e) => *e,
                #[allow(unreachable_patterns)]
                _ => panic!("IrqRoutingEntry type is wrong"),
            })
            .collect();

        let irq_routing =
            kvm_bindings::fam_wrappers::KvmIrqRouting::from_entries(&entries).unwrap();

        self.fd
            .set_gsi_routing(&irq_routing)
            .map_err(|e| vm::HypervisorVmError::SetGsiRouting(e.into()))
    }

    /// Creates a guest physical memory region.
    ///
    /// # Safety
    ///
    /// `userspace_addr` must point to `memory_size` bytes of memory
    /// that will stay mapped until a successful call to
    /// `remove_user_memory_region().`  Freeing them with `munmap()`
    /// before then will cause undefined guest behavior but at least
    /// should not cause undefined behavior in the host.  In theory,
    /// at least.
    unsafe fn create_user_memory_region(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: usize,
        userspace_addr: *mut u8,
        readonly: bool,
        log_dirty_pages: bool,
    ) -> vm::Result<()> {
        let mut flags = 0;
        if readonly {
            flags |= KVM_MEM_READONLY;
        }
        if log_dirty_pages {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }

        const _: () = assert!(core::mem::size_of::<usize>() <= core::mem::size_of::<u64>());

        // Create a per-region guest_memfd when supported.
        // Each region gets its own fd sized exactly to memory_size
        let guest_memfd = if let Some(memfds) = &self.guest_memfds {
            let fd = create_guest_memfd(
                &self.fd,
                memory_size as u64,
                self.guest_memfd_legacy_hugepage,
            )
            .map_err(|e| vm::HypervisorVmError::CreateUserMemory(e.into()))?;
            let raw_fd = fd.as_raw_fd() as u32;
            memfds.write().unwrap().insert(slot, fd);
            raw_fd
        } else {
            0
        };

        let mut region = kvm_userspace_memory_region2 {
            slot,
            flags: self.get_kvm_userspace_memory_region_flag(flags),
            guest_phys_addr,
            memory_size: memory_size as u64,
            userspace_addr: userspace_addr as usize as u64,
            #[cfg(not(target_arch = "riscv64"))]
            guest_memfd,
            // Each guest_memfd is per-region and sized to memory_size,
            // so the region's data always starts at offset 0.
            guest_memfd_offset: 0,
            ..Default::default()
        };
        if (region.flags & KVM_MEM_LOG_DIRTY_PAGES) != 0 {
            if (region.flags & KVM_MEM_READONLY) != 0 {
                return Err(vm::HypervisorVmError::CreateUserMemory(anyhow!(
                    "Error creating regions with both 'dirty-pages-log' and 'read-only'."
                )));
            }

            // Keep track of the regions that need dirty pages log
            self.dirty_log_slots.write().unwrap().insert(
                region.slot,
                KvmDirtyLogSlot {
                    slot: region.slot,
                    guest_phys_addr: region.guest_phys_addr,
                    memory_size: region.memory_size,
                    userspace_addr: region.userspace_addr,
                    guest_memfd_offset: region.guest_memfd_offset,
                    guest_memfd: region.guest_memfd,
                },
            );

            // Always create guest physical memory region without `KVM_MEM_LOG_DIRTY_PAGES`.
            // For regions that need this flag, dirty pages log will be turned on in `start_dirty_log`.
            region.flags = self.get_kvm_userspace_memory_region_flag(0);
        }

        // SAFETY: Safe because caller promised this is safe.
        unsafe {
            self.set_user_memory_region(region)
                .map_err(|e| vm::HypervisorVmError::CreateUserMemory(e.into()))?;
        }

        if self.guest_memfds.is_some() {
            #[cfg(any(feature = "sev_snp", feature = "tdx"))]
            if let Some(guest_mem_slots) = &self.guest_mem_slots {
                guest_mem_slots.write().unwrap().insert(
                    region.slot,
                    KvmGuestMemSlot {
                        slot: region.slot,
                        guest_phys_addr: region.guest_phys_addr,
                        memory_size: region.memory_size,
                        userspace_addr: region.userspace_addr,
                        flags: region.flags,
                        guest_memfd_offset: region.guest_memfd_offset,
                        guest_memfd: region.guest_memfd,
                    },
                );
            }

            self.fd
                .set_memory_attributes(kvm_memory_attributes {
                    address: region.guest_phys_addr,
                    size: region.memory_size,
                    attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as u64,
                    flags: 0,
                })
                .map_err(|e| vm::HypervisorVmError::CreateUserMemory(e.into()))?;
        }
        Ok(())
    }

    /// Removes a guest physical memory region.
    ///
    /// # Safety
    ///
    /// `userspace_addr` must point to `memory_size` bytes of memory,
    /// and `add_user_memory_region()` must have been successfully called.
    unsafe fn remove_user_memory_region(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: usize,
        userspace_addr: *mut u8,
        readonly: bool,
        log_dirty_pages: bool,
    ) -> vm::Result<()> {
        let mut flags = 0;
        if readonly {
            flags |= KVM_MEM_READONLY;
        }
        if log_dirty_pages {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }

        const _: () = assert!(core::mem::size_of::<usize>() <= core::mem::size_of::<u64>());

        let mut region = kvm_userspace_memory_region2 {
            slot,
            guest_phys_addr,
            memory_size: memory_size as u64,
            userspace_addr: userspace_addr as usize as u64,
            flags,
            ..Default::default()
        };

        // Remove the corresponding entry from "self.dirty_log_slots" if needed
        self.dirty_log_slots.write().unwrap().remove(&region.slot);

        // Setting the size to 0 means "remove"
        region.memory_size = 0;
        // SAFETY: Safe because caller promised this is safe.
        unsafe {
            self.set_user_memory_region(region)
                .map_err(|e| vm::HypervisorVmError::RemoveUserMemory(e.into()))?;
        }

        // Close the per-region guest_memfd if one was created for this slot
        if let Some(memfds) = &self.guest_memfds {
            memfds.write().unwrap().remove(&slot);
        }
        #[cfg(any(feature = "sev_snp", feature = "tdx"))]
        if let Some(guest_mem_slots) = &self.guest_mem_slots {
            guest_mem_slots.write().unwrap().remove(&slot);
        }

        Ok(())
    }

    ///
    /// Returns the preferred CPU target type which can be emulated by KVM on underlying host.
    ///
    #[cfg(target_arch = "aarch64")]
    fn get_preferred_target(&self, kvi: &mut crate::VcpuInit) -> vm::Result<()> {
        let mut kvm_kvi: kvm_bindings::kvm_vcpu_init = (*kvi).into();
        self.fd
            .get_preferred_target(&mut kvm_kvi)
            .map_err(|e| vm::HypervisorVmError::GetPreferredTarget(e.into()))?;
        *kvi = kvm_kvi.into();
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn enable_split_irq(&self) -> vm::Result<()> {
        // Create split irqchip
        // Only the local APIC is emulated in kernel, both PICs and IOAPIC
        // are not.
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_SPLIT_IRQCHIP,
            ..Default::default()
        };
        cap.args[0] = NUM_IOAPIC_PINS as u64;
        self.fd
            .enable_cap(&cap)
            .map_err(|e| vm::HypervisorVmError::EnableSplitIrq(e.into()))?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn create_pit2(&self) -> vm::Result<()> {
        self.fd
            .create_pit2(kvm_pit_config::default())
            .map_err(|e| vm::HypervisorVmError::CreatePit(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    fn enable_x2apic_api(&self) -> vm::Result<()> {
        // From https://docs.kernel.org/virt/kvm/api.html:
        // On x86, kvm_msi::address_hi is ignored unless the KVM_X2APIC_API_USE_32BIT_IDS feature of
        // KVM_CAP_X2APIC_API capability is enabled. If it is enabled, address_hi bits 31-8
        // provide bits 31-8 of the destination id. Bits 7-0 of address_hi must be zero.

        // Thus KVM_X2APIC_API_USE_32BIT_IDS in combination with KVM_FEATURE_MSI_EXT_DEST_ID allows
        // the guest to target interrupts to cpus with APIC IDs > 254.

        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_X2APIC_API,
            ..Default::default()
        };
        cap.args[0] =
            (KVM_X2APIC_API_USE_32BIT_IDS | KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK) as u64;
        self.fd
            .enable_cap(&cap)
            .map_err(|e| vm::HypervisorVmError::EnableX2ApicApi(e.into()))?;
        Ok(())
    }

    /// Retrieve guest clock.
    #[cfg(target_arch = "x86_64")]
    fn get_clock(&self) -> vm::Result<ClockData> {
        Ok(self
            .fd
            .get_clock()
            .map_err(|e| vm::HypervisorVmError::GetClock(e.into()))?
            .into())
    }

    /// Set guest clock.
    #[cfg(target_arch = "x86_64")]
    fn set_clock(&self, data: &ClockData) -> vm::Result<()> {
        let data = (*data).into();
        self.fd
            .set_clock(&data)
            .map_err(|e| vm::HypervisorVmError::SetClock(e.into()))
    }

    /// Create a device that is used for passthrough
    fn create_passthrough_device(&self) -> vm::Result<VfioDeviceFd> {
        let mut vfio_dev = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        self.create_device(&mut vfio_dev)
            .map_err(|e| vm::HypervisorVmError::CreatePassthroughDevice(e.into()))
    }

    ///
    /// Start logging dirty pages
    ///
    fn start_dirty_log(&self) -> vm::Result<()> {
        let dirty_log_slots = self.dirty_log_slots.read().unwrap();
        for (_, s) in dirty_log_slots.iter() {
            let region = kvm_userspace_memory_region2 {
                slot: s.slot,
                guest_phys_addr: s.guest_phys_addr,
                memory_size: s.memory_size,
                userspace_addr: s.userspace_addr,
                flags: self.get_kvm_userspace_memory_region_flag(KVM_MEM_LOG_DIRTY_PAGES),
                guest_memfd: s.guest_memfd,
                guest_memfd_offset: s.guest_memfd_offset,
                ..Default::default()
            };
            // SAFETY: Safe because guest regions are guaranteed not to overlap.
            unsafe {
                self.set_user_memory_region(region)
                    .map_err(|e| vm::HypervisorVmError::StartDirtyLog(e.into()))?;
            }
        }

        Ok(())
    }

    ///
    /// Stop logging dirty pages
    ///
    fn stop_dirty_log(&self) -> vm::Result<()> {
        let dirty_log_slots = self.dirty_log_slots.read().unwrap();
        for (_, s) in dirty_log_slots.iter() {
            let region = kvm_userspace_memory_region2 {
                slot: s.slot,
                guest_phys_addr: s.guest_phys_addr,
                memory_size: s.memory_size,
                userspace_addr: s.userspace_addr,
                flags: self.get_kvm_userspace_memory_region_flag(0),
                guest_memfd: s.guest_memfd,
                guest_memfd_offset: s.guest_memfd_offset,
                ..Default::default()
            };
            // SAFETY: Safe because guest regions are guaranteed not to overlap.
            unsafe {
                self.set_user_memory_region(region)
                    .map_err(|e| vm::HypervisorVmError::StartDirtyLog(e.into()))?;
            }
        }

        Ok(())
    }

    ///
    /// Get dirty pages bitmap (one bit per page)
    ///
    fn get_dirty_log(&self, slot: u32, _base_gpa: u64, memory_size: u64) -> vm::Result<Vec<u64>> {
        self.fd
            .get_dirty_log(slot, memory_size as usize)
            .map_err(|e| vm::HypervisorVmError::GetDirtyLog(e.into()))
    }

    ///
    /// Initialize TDX for this VM
    ///
    #[cfg(feature = "tdx")]
    fn tdx_init(
        &self,
        cpuid: &[CpuIdEntry],
        max_vcpus: u32,
        attrs: &TdxAttributes,
    ) -> vm::Result<()> {
        if self.tdx_legacy_vm_type {
            for (cap, arg0) in [
                (KVM_CAP_EXCEPTION_PAYLOAD_RAW, 1),
                (KVM_CAP_X86_TRIPLE_FAULT_EVENT_RAW, 1),
                (KVM_CAP_X86_NOTIFY_VMEXIT_RAW, 3),
                (KVM_CAP_X86_USER_SPACE_MSR_RAW, 4),
            ] {
                self.fd
                    .enable_cap(&kvm_enable_cap {
                        cap,
                        args: [arg0, 0, 0, 0],
                        ..Default::default()
                    })
                    .map_err(|e| vm::HypervisorVmError::InitializeTdx(e.into()))?;
            }

            for cap in [KVM_CAP_MAX_VCPU_ID_RAW, KVM_CAP_MAX_VCPUS_RAW] {
                self.fd
                    .enable_cap(&kvm_enable_cap {
                        cap,
                        args: [max_vcpus.into(), 0, 0, 0],
                        ..Default::default()
                    })
                    .map_err(|e| vm::HypervisorVmError::InitializeTdx(e.into()))?;
            }
        }

        // QEMU's TDX path programs the VM TSC frequency before KVM_TDX_INIT_VM.
        // Passing 0 asks KVM to use the host TSC frequency.
        let ret = unsafe { ioctl_with_val(&self.fd.as_raw_fd(), KVM_SET_TSC_KHZ_VM(), 0) };
        if ret < 0 {
            return Err(vm::HypervisorVmError::InitializeTdx(
                std::io::Error::last_os_error().into(),
            ));
        }

        if self.tdx_legacy_vm_type {
            let mut caps = TdxCapabilitiesLegacy::default();
            tdx_command(
                &self.fd.as_raw_fd(),
                TdxCommand::Capabilities,
                0,
                &mut caps as *mut _ as *const _,
            )
            .map_err(vm::HypervisorVmError::InitializeTdx)?;

            let mut tdx_cpuid = tdx_legacy_cpuid_entries(&caps, cpuid);
            let cpuid_nent = tdx_cpuid.len();

            tdx_cpuid.resize(
                TDX_MAX_NR_CPUID_CONFIGS,
                kvm_bindings::kvm_cpuid_entry2::default(),
            );

            #[repr(C)]
            struct TdxInitVmLegacy {
                attributes: u64,
                mrconfigid: [u64; 6],
                mrowner: [u64; 6],
                mrownerconfig: [u64; 6],
                reserved: [u64; 1004],
                cpuid_nent: u32,
                cpuid_padding: u32,
                cpuid_entries: [kvm_bindings::kvm_cpuid_entry2; TDX_MAX_NR_CPUID_CONFIGS],
            }

            info!(
                "TDX legacy caps: attrs_fixed0={:#x} attrs_fixed1={:#x} \
                 xfam_fixed0={:#x} xfam_fixed1={:#x} supported_gpaw={:#x} \
                 nr_cpuid_configs={}",
                caps.attrs_fixed0,
                caps.attrs_fixed1,
                caps.xfam_fixed0,
                caps.xfam_fixed1,
                caps.supported_gpaw,
                caps.nr_cpuid_configs,
            );

            // Mirrors QEMU `tdx_validate_attributes` against legacy KVM TDX
            // caps. Legacy ABI exposes `attrs_fixed0` (mask of bits *allowed*
            // to be variable) and `attrs_fixed1` (mask of bits *forced to 1*),
            // so the actual TD attributes are
            //   `(requested & attrs_fixed0) | attrs_fixed1`.
            let requested_attrs = tdx_requested_attributes(attrs);
            let attributes = (requested_attrs & caps.attrs_fixed0) | caps.attrs_fixed1;
            if attributes != requested_attrs {
                info!(
                    "TDX legacy attributes adjusted by caps: requested={:#x} \
                     actual={:#x} fixed0={:#x} fixed1={:#x}",
                    requested_attrs, attributes, caps.attrs_fixed0, caps.attrs_fixed1,
                );
            }

            // xfam: explicit override goes through `xfam_fixed0/1` validation,
            // otherwise derive from CPUID (legacy path historically omitted
            // the xfam field — KVM treats the absent struct slot as zero,
            // which matches how `tdx_legacy_cpuid_entries` shaped CPUID 0xd
            // before this commit; preserve that for the no-override case to
            // keep byte-for-byte compatibility with `9263242fc`).
            let xfam_legacy: Option<u64> = match attrs.xfam {
                Some(v) => {
                    if (v & !caps.xfam_fixed0) != 0 {
                        warn!(
                            "TDX xfam request {:#x} contains bits forbidden by xfam_fixed0={:#x}",
                            v, caps.xfam_fixed0,
                        );
                    }
                    if (v & caps.xfam_fixed1) != caps.xfam_fixed1 {
                        warn!(
                            "TDX xfam request {:#x} missing bits required by xfam_fixed1={:#x}",
                            v, caps.xfam_fixed1,
                        );
                    }
                    Some(v)
                }
                None => None,
            };

            let mrconfigid = tdx_mr_seed_to_u64x6(&attrs.mrconfigid);
            let mrowner = tdx_mr_seed_to_u64x6(&attrs.mrowner);
            let mrownerconfig = tdx_mr_seed_to_u64x6(&attrs.mrownerconfig);

            let data = TdxInitVmLegacy {
                attributes,
                mrconfigid,
                mrowner,
                mrownerconfig,
                reserved: [0; 1004],
                cpuid_nent: cpuid_nent as u32,
                cpuid_padding: 0,
                cpuid_entries: tdx_cpuid.as_slice().try_into().unwrap(),
            };

            info!(
                "TDX legacy KVM_TDX_INIT_VM: requested_attributes={:#x} \
                 attributes={:#x} xfam_override={:?} cpuid_nent={} \
                 mrconfigid={:?} mrowner={:?} mrownerconfig={:?}",
                requested_attrs,
                data.attributes,
                xfam_legacy,
                data.cpuid_nent,
                data.mrconfigid,
                data.mrowner,
                data.mrownerconfig,
            );

            tdx_command(
                &self.fd.as_raw_fd(),
                TdxCommand::InitVm,
                0,
                &data as *const _ as *const _,
            )
            .map_err(vm::HypervisorVmError::InitializeTdx)?;
            info!("TDX legacy KVM_TDX_INIT_VM: success");
            return Ok(());
        }

        let cpuid: Vec<kvm_bindings::kvm_cpuid_entry2> =
            cpuid.iter().map(|e| (*e).into()).collect();

        let mut caps = TdxCapabilities {
            cpuid_nent: TDX_MAX_NR_CPUID_CONFIGS as u32,
            ..Default::default()
        };
        tdx_command(
            &self.fd.as_raw_fd(),
            TdxCommand::Capabilities,
            0,
            &mut caps as *mut _ as *const _,
        )
        .map_err(vm::HypervisorVmError::InitializeTdx)?;

        info!(
            "TDX caps: supported_attrs={:#x} supported_xfam={:#x} \
             kernel_tdvmcallinfo_1_r11={:#x} kernel_tdvmcallinfo_1_r12={:#x} \
             user_tdvmcallinfo_1_r11={:#x} user_tdvmcallinfo_1_r12={:#x} \
             cpuid_nent={}",
            caps.supported_attrs,
            caps.supported_xfam,
            caps.kernel_tdvmcallinfo_1_r11,
            caps.kernel_tdvmcallinfo_1_r12,
            caps.user_tdvmcallinfo_1_r11,
            caps.user_tdvmcallinfo_1_r12,
            caps.cpuid_nent,
        );

        // QEMU `tdx_validate_attributes` (new ABI) only checks
        // `requested & ~supported_attrs == 0`. We mask defensively as well
        // (matches `let attributes = requested & caps.supported_attrs`) and
        // log when caps trimmed any bit so attestation reviewers can spot the
        // adjustment without re-running the VM.
        let requested_attrs = tdx_requested_attributes(attrs);
        let attributes = requested_attrs & caps.supported_attrs;
        if attributes != requested_attrs {
            info!(
                "TDX attributes adjusted by caps: requested={:#x} actual={:#x} \
                 supported_attrs={:#x}",
                requested_attrs, attributes, caps.supported_attrs,
            );
        }

        // xfam: user override goes through `supported_xfam` mask only (legacy
        // had `xfam_fixed0/1`, new ABI collapses to a single `supported_xfam`
        // — see QEMU `setup_td_xfam`). Derive from CPUID when no override.
        let xfam = match attrs.xfam {
            Some(v) => {
                let masked = v & caps.supported_xfam;
                if masked != v {
                    info!(
                        "TDX xfam adjusted by caps: requested={:#x} actual={:#x} \
                         supported_xfam={:#x}",
                        v, masked, caps.supported_xfam,
                    );
                }
                masked
            }
            None => tdx_derive_xfam(&cpuid, caps.supported_xfam),
        };

        let caps_cpuid_nent = (caps.cpuid_nent as usize).min(TDX_MAX_NR_CPUID_CONFIGS);
        let mut tdx_cpuid: Vec<kvm_bindings::kvm_cpuid_entry2> = cpuid
            .into_iter()
            .filter_map(|mut entry| {
                caps.cpuid_configs[..caps_cpuid_nent]
                    .iter()
                    .find(|mask| mask.function == entry.function && mask.index == entry.index)
                    .map(|mask| {
                        entry.eax &= mask.eax;
                        entry.ebx &= mask.ebx;
                        entry.ecx &= mask.ecx;
                        entry.edx &= mask.edx;
                        entry
                    })
            })
            .collect();
        let cpuid_nent = tdx_cpuid.len();
        tdx_cpuid.resize(
            TDX_MAX_NR_CPUID_CONFIGS,
            kvm_bindings::kvm_cpuid_entry2::default(),
        );

        #[repr(C)]
        struct TdxInitVm {
            attributes: u64,
            xfam: u64,
            mrconfigid: [u64; 6],
            mrowner: [u64; 6],
            mrownerconfig: [u64; 6],
            reserved: [u64; 12],
            cpuid_nent: u32,
            cpuid_padding: u32,
            cpuid_entries: [kvm_bindings::kvm_cpuid_entry2; TDX_MAX_NR_CPUID_CONFIGS],
        }
        let mrconfigid = tdx_mr_seed_to_u64x6(&attrs.mrconfigid);
        let mrowner = tdx_mr_seed_to_u64x6(&attrs.mrowner);
        let mrownerconfig = tdx_mr_seed_to_u64x6(&attrs.mrownerconfig);
        let data = TdxInitVm {
            attributes,
            xfam,
            mrconfigid,
            mrowner,
            mrownerconfig,
            reserved: [0; 12],
            cpuid_nent: cpuid_nent as u32,
            cpuid_padding: 0,
            cpuid_entries: tdx_cpuid.as_slice().try_into().unwrap(),
        };

        info!(
            "TDX KVM_TDX_INIT_VM: requested_attributes={:#x} attributes={:#x} \
             xfam={:#x} cpuid_nent={} mrconfigid={:?} mrowner={:?} \
             mrownerconfig={:?}",
            requested_attrs,
            data.attributes,
            data.xfam,
            data.cpuid_nent,
            data.mrconfigid,
            data.mrowner,
            data.mrownerconfig,
        );

        tdx_command(
            &self.fd.as_raw_fd(),
            TdxCommand::InitVm,
            0,
            &data as *const _ as *const _,
        )
        .map_err(vm::HypervisorVmError::InitializeTdx)?;
        info!("TDX KVM_TDX_INIT_VM: success");
        Ok(())
    }

    ///
    /// Finalize the TDX setup for this VM
    ///
    #[cfg(feature = "tdx")]
    fn tdx_finalize(&self) -> vm::Result<()> {
        tdx_command(
            &self.fd.as_raw_fd(),
            TdxCommand::Finalize,
            0,
            std::ptr::null(),
        )
        .map_err(vm::HypervisorVmError::FinalizeTdx)
    }

    /// Initialize memory regions for the TDX VM
    ///
    /// # Safety
    ///
    /// `host_address` must be valid for `size` bytes
    #[cfg(feature = "tdx")]
    unsafe fn tdx_init_memory_region(
        &self,
        host_address: *mut u8,
        guest_address: u64,
        size: usize,
        measure: bool,
    ) -> vm::Result<()> {
        if self.tdx_legacy_vm_type {
            #[repr(C)]
            struct KvmMemoryMapping {
                base_gfn: u64,
                nr_pages: u64,
                flags: u64,
                source: u64,
            }
            let data = KvmMemoryMapping {
                base_gfn: guest_address >> 12,
                nr_pages: (size / 4096).try_into().unwrap(),
                flags: 0,
                source: 0,
            };

            if !measure {
                return Ok(());
            }

            return tdx_command(
                &self.fd.as_raw_fd(),
                TdxCommand::InitMemRegion,
                0,
                &data as *const _ as *const _,
            )
            .map_err(vm::HypervisorVmError::InitMemRegionTdx);
        }

        #[repr(C)]
        struct TdxInitMemRegion {
            host_address: u64,
            guest_address: u64,
            pages: u64,
        }
        let data = TdxInitMemRegion {
            host_address: host_address as _,
            guest_address,
            pages: (size / 4096).try_into().unwrap(),
        };

        tdx_command(
            &self.fd.as_raw_fd(),
            TdxCommand::InitMemRegion,
            u32::from(measure),
            &data as *const _ as *const _,
        )
        .map_err(vm::HypervisorVmError::InitMemRegionTdx)
    }

    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    fn set_memory_attributes(&self, address: u64, size: u64, attributes: u64) -> vm::Result<()> {
        self.fd
            .set_memory_attributes(kvm_bindings::kvm_memory_attributes {
                address,
                size,
                attributes,
                flags: 0,
            })
            .map_err(|e| vm::HypervisorVmError::SetMemoryAttributes(e.into()))
    }

    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    fn share_memory_region(&self, address: u64, size: u64) -> vm::Result<()> {
        self.set_memory_attributes(address, size, 0)?;

        let Some(guest_memfds) = &self.guest_memfds else {
            return Ok(());
        };
        let Some(guest_mem_slots) = &self.guest_mem_slots else {
            return Ok(());
        };

        let end = address.checked_add(size).ok_or_else(|| {
            vm::HypervisorVmError::SetMemoryAttributes(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "guest_memfd range overflow",
            ))
        })?;

        let slots: Vec<KvmGuestMemSlot> =
            guest_mem_slots.read().unwrap().values().copied().collect();
        let memfds = guest_memfds.read().unwrap();

        for slot in slots {
            let slot_start = slot.guest_phys_addr;
            let slot_end = slot
                .guest_phys_addr
                .checked_add(slot.memory_size)
                .ok_or_else(|| {
                    vm::HypervisorVmError::SetMemoryAttributes(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "guest_memfd slot overflow",
                    ))
                })?;

            let punch_start = std::cmp::max(address, slot_start);
            let punch_end = std::cmp::min(end, slot_end);
            if punch_start >= punch_end {
                continue;
            }

            let fd = memfds.get(&slot.slot).ok_or_else(|| {
                vm::HypervisorVmError::SetMemoryAttributes(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("missing guest_memfd for slot {}", slot.slot),
                ))
            })?;

            let offset = slot.guest_memfd_offset + (punch_start - slot_start);
            let length = punch_end - punch_start;
            let ret = unsafe {
                libc::fallocate64(
                    fd.as_raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    offset as libc::off64_t,
                    length as libc::off64_t,
                )
            };
            if ret != 0 {
                return Err(vm::HypervisorVmError::SetMemoryAttributes(
                    std::io::Error::last_os_error(),
                ));
            }
        }

        Ok(())
    }

    #[cfg(feature = "tdx")]
    fn tdx_init_uses_boot_vcpu_cpuid(&self) -> bool {
        self.tdx_legacy_vm_type
    }

    /// Downcast to the underlying KvmVm type
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "tdx")]
fn tdx_command(
    fd: &RawFd,
    command: TdxCommand,
    flags: u32,
    data: *const libc::c_void,
) -> std::result::Result<(), std::io::Error> {
    #[repr(C)]
    struct TdxIoctlCmd {
        id: u32,
        flags: u32,
        data: u64,
        error: u64,
        unused: u64,
    }
    let cmd = TdxIoctlCmd {
        id: command as u32,
        flags,
        data: data as _,
        error: 0,
        unused: 0,
    };
    loop {
        // SAFETY: FFI call. All input parameters are valid.
        let ret = unsafe {
            ioctl_with_val(
                fd,
                KVM_MEMORY_ENCRYPT_OP(),
                &cmd as *const TdxIoctlCmd as std::os::raw::c_ulong,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        return Ok(());
    }
}

/// Wrapper over KVM system ioctls.
pub struct KvmHypervisor {
    kvm: Kvm,
}

impl KvmHypervisor {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Retrieve the list of MSRs supported by the hypervisor.
    ///
    fn get_msr_list(&self) -> hypervisor::Result<MsrList> {
        let mut indices = self
            .kvm
            .get_msr_index_list()
            .map_err(|e| hypervisor::HypervisorError::GetMsrList(e.into()))?
            .as_slice()
            .to_vec();

        // KVM_GET_MSR_INDEX_LIST does not include MTRR MSRs, but firmware may update them before an early boot snapshot.
        indices.extend(MTRR_MSR_INDICES);

        let mut msr_list = MsrList::new(indices.len())
            .map_err(|e| hypervisor::HypervisorError::GetMsrList(e.into()))?;
        msr_list.as_mut_slice().copy_from_slice(&indices);

        Ok(msr_list)
    }

    #[cfg(all(feature = "tdx", target_arch = "x86_64"))]
    fn tdx_vm_type(&self) -> u64 {
        let supported = self.kvm.check_extension_raw(KVM_CAP_VM_TYPES_RAW) as u64;
        let current = KVM_X86_TDX_VM.into();

        if supported & (1u64 << current) != 0 {
            current
        } else if supported & (1u64 << KVM_X86_TDX_VM_LEGACY) != 0 {
            warn!(
                "host KVM supports legacy TDX VM type {} instead of kvm-bindings value {}",
                KVM_X86_TDX_VM_LEGACY, current
            );
            KVM_X86_TDX_VM_LEGACY
        } else {
            current
        }
    }
}

/// Enum for KVM related error
#[derive(Debug, Error)]
pub enum KvmError {
    #[error("Capability missing: {0:?}")]
    CapabilityMissing(Cap),
}

pub type KvmResult<T> = result::Result<T, KvmError>;

impl KvmHypervisor {
    /// Create a hypervisor based on Kvm
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> hypervisor::Result<Arc<dyn hypervisor::Hypervisor>> {
        let kvm_obj = Kvm::new().map_err(|e| hypervisor::HypervisorError::VmCreate(e.into()))?;
        let api_version = kvm_obj.get_api_version();

        if api_version != kvm_bindings::KVM_API_VERSION as i32 {
            return Err(hypervisor::HypervisorError::IncompatibleApiVersion);
        }

        Ok(Arc::new(KvmHypervisor { kvm: kvm_obj }))
    }

    /// Check if the hypervisor is available
    pub fn is_available() -> hypervisor::Result<bool> {
        match std::fs::metadata("/dev/kvm") {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(hypervisor::HypervisorError::HypervisorAvailableCheck(
                err.into(),
            )),
        }
    }
}

/// Implementation of Hypervisor trait for KVM
///
/// # Examples
///
/// ```
/// # use hypervisor::kvm::KvmHypervisor;
/// # use hypervisor::HypervisorVmConfig;
/// # use std::sync::Arc;
/// let kvm = KvmHypervisor::new().unwrap();
/// let hypervisor = Arc::new(kvm);
/// let vm = hypervisor.create_vm(HypervisorVmConfig::default()).expect("new VM fd creation failed");
/// ```
impl hypervisor::Hypervisor for KvmHypervisor {
    ///
    /// Returns the type of the hypervisor
    ///
    fn hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Kvm
    }

    /// Create a KVM vm object of a specific VM type and return the object as Vm trait object
    ///
    /// # Examples
    ///
    /// ```
    /// # use hypervisor::kvm::KvmHypervisor;
    /// # use hypervisor::kvm::KvmVm;
    /// # use hypervisor::HypervisorVmConfig;
    /// let hypervisor = KvmHypervisor::new().unwrap();
    /// let vm = hypervisor.create_vm(HypervisorVmConfig::default()).unwrap();
    /// ```
    fn create_vm(&self, _config: HypervisorVmConfig) -> hypervisor::Result<Arc<dyn vm::Vm>> {
        let fd: VmFd;

        #[allow(unused_mut)]
        #[allow(unused_assignments)]
        let mut vm_type: u64 = 0; // Create with default platform type

        // When KVM supports Cap::ArmVmIPASize, it is better to get the IPA
        // size from the host and use that when creating the VM, which may
        // avoid unnecessary VM creation failures.
        #[cfg(target_arch = "aarch64")]
        if self.kvm.check_extension(Cap::ArmVmIPASize) {
            vm_type = self.kvm.get_host_ipa_limit().try_into().unwrap();
        }

        #[cfg(target_arch = "x86_64")]
        {
            vm_type = KVM_X86_DEFAULT_VM.into();

            #[cfg(feature = "sev_snp")]
            if _config.sev_snp_enabled {
                vm_type = KVM_X86_SNP_VM.into();
            }

            #[cfg(feature = "tdx")]
            if _config.tdx_enabled {
                vm_type = self.tdx_vm_type();
            }
        }

        loop {
            match self.kvm.create_vm_with_type(vm_type) {
                Ok(res) => fd = res,
                Err(e) => {
                    if e.errno() == libc::EINTR {
                        // If the error returned is EINTR, which means the
                        // ioctl has been interrupted, we have to retry as
                        // this can't be considered as a regular error.
                        continue;
                    }
                    return Err(hypervisor::HypervisorError::VmCreate(e.into()));
                }
            }
            break;
        }

        #[cfg(target_arch = "x86_64")]
        {
            let msr_list = self.get_msr_list()?;
            let num_msrs = msr_list.as_fam_struct_ref().nmsrs as usize;
            let mut msrs = vec![
                MsrEntry {
                    ..Default::default()
                };
                num_msrs
            ];
            let indices = msr_list.as_slice();
            for (pos, index) in indices.iter().enumerate() {
                msrs[pos].index = *index;
            }

            #[allow(unused_mut)]
            let mut guest_memfds = None;
            #[cfg(any(feature = "sev_snp", feature = "tdx"))]
            let mut guest_mem_slots = None;
            #[cfg(any(feature = "sev_snp", feature = "tdx"))]
            // Upstream kernels advertise KVM_CAP_GUEST_MEMFD_FLAGS, where bit 0
            // is GUEST_MEMFD_FLAG_MMAP. Older tdxlab kernels return 0 here and
            // use bit 0 as KVM_GUEST_MEMFD_ALLOW_HUGEPAGE instead.
            let guest_memfd_legacy_hugepage = _config.tdx_enabled
                && self.kvm.check_extension_raw(KVM_CAP_GUEST_MEMFD_FLAGS_RAW) == 0;
            if (_config.tdx_enabled || {
                #[cfg(feature = "sev_snp")]
                {
                    _config.sev_snp_enabled
                }
                #[cfg(not(feature = "sev_snp"))]
                {
                    false
                }
            }) && fd.check_extension(Cap::GuestMemfd)
            {
                guest_memfds = Some(Arc::new(RwLock::new(HashMap::new())));
                #[cfg(any(feature = "sev_snp", feature = "tdx"))]
                {
                    guest_mem_slots = Some(Arc::new(RwLock::new(HashMap::new())));
                }
            }

            let exit_hypercall_cap_mask =
                self.kvm.check_extension_int(crate::kvm::Cap::ExitHypercall);
            let enable_hypercall = {
                #[cfg(feature = "tdx")]
                {
                    _config.tdx_enabled
                }
                #[cfg(all(not(feature = "tdx"), feature = "sev_snp"))]
                {
                    _config.sev_snp_enabled
                }
                #[cfg(all(not(feature = "tdx"), not(feature = "sev_snp")))]
                {
                    false
                }
            } || {
                #[cfg(feature = "sev_snp")]
                {
                    _config.sev_snp_enabled
                }
                #[cfg(not(feature = "sev_snp"))]
                {
                    false
                }
            };
            if enable_hypercall && exit_hypercall_cap_mask > 0 {
                const KVM_HC_MAP_GPA_RANGE: u64 = 12;
                let cap = kvm_bindings::kvm_enable_cap {
                    cap: kvm_bindings::KVM_CAP_EXIT_HYPERCALL,
                    args: [1u64 << KVM_HC_MAP_GPA_RANGE, 0, 0, 0],
                    ..Default::default()
                };
                fd.enable_cap(&cap)
                    .map_err(|e| hypervisor::HypervisorError::VmCreate(e.into()))?;
            }

            #[cfg(feature = "sev_snp")]
            let sev_fd = {
                let sev_snp_enabled = vm_type == KVM_X86_SNP_VM as u64;
                if sev_snp_enabled {
                    let sev_dev = x86_64::sev::SevFd::new("/dev/sev")
                        .map_err(|e| hypervisor::HypervisorError::SevSnpCapabilities(e.into()))?;
                    sev_dev
                        .init2(&fd, _config.vmsa_features)
                        .map_err(|e| hypervisor::HypervisorError::VmCreate(e.into()))?;
                    Some(sev_dev)
                } else {
                    None
                }
            };

            Ok(Arc::new(KvmVm {
                fd: Arc::new(fd),
                #[cfg(all(feature = "tdx", target_arch = "x86_64"))]
                kvm_fd: self.kvm.as_raw_fd(),
                msrs,
                dirty_log_slots: RwLock::new(HashMap::new()),
                #[cfg(feature = "sev_snp")]
                sev_fd,
                guest_memfds,
                #[cfg(any(feature = "sev_snp", feature = "tdx"))]
                guest_memfd_legacy_hugepage,
                #[cfg(any(feature = "sev_snp", feature = "tdx"))]
                guest_mem_slots,
                #[cfg(feature = "tdx")]
                tdx_legacy_vm_type: _config.tdx_enabled && vm_type == KVM_X86_TDX_VM_LEGACY,
            }))
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        {
            Ok(Arc::new(KvmVm {
                fd: Arc::new(fd),
                dirty_log_slots: RwLock::new(HashMap::new()),
                guest_memfds: None,
                #[cfg(any(feature = "sev_snp", feature = "tdx"))]
                guest_memfd_legacy_hugepage: false,
                #[cfg(any(feature = "sev_snp", feature = "tdx"))]
                guest_mem_slots: None,
            }))
        }
    }

    fn check_required_extensions(&self) -> hypervisor::Result<()> {
        check_required_kvm_extensions(&self.kvm)
            .map_err(|e| hypervisor::HypervisorError::CheckExtensions(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to get the system supported CPUID values.
    ///
    fn get_supported_cpuid(&self) -> hypervisor::Result<Vec<CpuIdEntry>> {
        let kvm_cpuid = self
            .kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| hypervisor::HypervisorError::GetCpuId(e.into()))?;

        let v = kvm_cpuid.as_slice().iter().map(|e| (*e).into()).collect();

        Ok(v)
    }

    #[cfg(target_arch = "aarch64")]
    ///
    /// Retrieve AArch64 host maximum IPA size supported by KVM.
    ///
    fn get_host_ipa_limit(&self) -> i32 {
        self.kvm.get_host_ipa_limit()
    }

    ///
    /// Retrieve TDX capabilities
    ///
    #[cfg(feature = "tdx")]
    fn tdx_capabilities(&self) -> hypervisor::Result<TdxCapabilities> {
        let vm_fd = self
            .kvm
            .create_vm_with_type(self.tdx_vm_type())
            .map_err(|e| hypervisor::HypervisorError::TdxCapabilities(e.into()))?;

        let mut data = TdxCapabilities {
            cpuid_nent: TDX_MAX_NR_CPUID_CONFIGS as u32,
            ..Default::default()
        };

        tdx_command(
            &vm_fd.as_raw_fd(),
            TdxCommand::Capabilities,
            0,
            &mut data as *mut _ as *const _,
        )
        .map_err(|e| hypervisor::HypervisorError::TdxCapabilities(e.into()))?;

        Ok(data)
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    ///
    /// Get the number of supported hardware breakpoints
    ///
    fn get_guest_debug_hw_bps(&self) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            4
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.kvm.get_guest_debug_hw_bps() as usize
        }
    }

    /// Get maximum number of vCPUs
    fn get_max_vcpus(&self) -> u32 {
        self.kvm.get_max_vcpus().min(u32::MAX as usize) as u32
    }
}

/// Vcpu struct for KVM
pub struct KvmVcpu {
    fd: VcpuFd,
    #[cfg(target_arch = "x86_64")]
    msrs: Vec<MsrEntry>,
    vm_ops: Option<Arc<dyn vm::VmOps>>,
    #[cfg(target_arch = "x86_64")]
    hyperv_synic: AtomicBool,
    #[cfg(target_arch = "x86_64")]
    xsave_size: i32,
    #[cfg(all(feature = "tdx", target_arch = "x86_64"))]
    kvm_fd: RawFd,
    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    vm_fd: Arc<VmFd>,
    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    guest_memfds: Option<Arc<RwLock<HashMap<u32, OwnedFd>>>>,
    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    guest_memfd_legacy_hugepage: bool,
    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    guest_mem_slots: Option<Arc<RwLock<HashMap<u32, KvmGuestMemSlot>>>>,
    #[cfg(feature = "tdx")]
    tdx_legacy_cpuid: bool,
    #[cfg(feature = "tdx")]
    tdx_fw_cfg_dma_hi: u32,
    #[cfg(feature = "tdx")]
    tdx_pending_shared_2m_ranges: Mutex<HashMap<u64, [u64; 8]>>,
}

/// Implementation of Vcpu trait for KVM
///
/// # Examples
///
/// ```
/// # use hypervisor::kvm::KvmHypervisor;
/// # use hypervisor::HypervisorVmConfig;
/// # use std::sync::Arc;
/// let kvm = KvmHypervisor::new().unwrap();
/// let hypervisor = Arc::new(kvm);
/// let vm = hypervisor.create_vm(HypervisorVmConfig::default()).expect("new VM fd creation failed");
/// let vcpu = vm.create_vcpu(0, None).unwrap();
/// ```
impl cpu::Vcpu for KvmVcpu {
    ///
    /// Downcast to the underlying KvmVcpu type
    ///
    fn as_any(&self) -> &dyn Any {
        self
    }

    ///
    /// Returns StandardRegisters with default value set
    ///
    fn create_standard_regs(&self) -> StandardRegisters {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            kvm_bindings::kvm_regs::default().into()
        }
        #[cfg(target_arch = "riscv64")]
        {
            kvm_bindings::kvm_riscv_core::default().into()
        }
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU general purpose registers.
    ///
    fn get_regs(&self) -> cpu::Result<StandardRegisters> {
        Ok(self
            .fd
            .get_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetStandardRegs(e.into()))?
            .into())
    }

    ///
    /// Returns the vCPU general purpose registers.
    /// The `KVM_GET_REGS` ioctl is not available on AArch64, `KVM_GET_ONE_REG`
    /// is used to get registers one by one.
    ///
    #[cfg(target_arch = "aarch64")]
    fn get_regs(&self) -> cpu::Result<StandardRegisters> {
        let mut state = kvm_regs::default();
        let mut off = offset_of!(user_pt_regs, regs);
        // There are 31 user_pt_regs:
        // https://elixir.bootlin.com/linux/v4.14.174/source/arch/arm64/include/uapi/asm/ptrace.h#L72
        // These actually are the general-purpose registers of the Armv8-a
        // architecture (i.e x0-x30 if used as a 64bit register or w0-30 when used as a 32bit register).
        for i in 0..31 {
            let mut bytes = [0_u8; 8];
            self.fd
                .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), &mut bytes)
                .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
            state.regs.regs[i] = u64::from_le_bytes(bytes);
            off += std::mem::size_of::<u64>();
        }

        // We are now entering the "Other register" section of the ARMv8-a architecture.
        // First one, stack pointer.
        let off = offset_of!(user_pt_regs, sp);
        let mut bytes = [0_u8; 8];
        self.fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), &mut bytes)
            .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
        state.regs.sp = u64::from_le_bytes(bytes);

        // Second one, the program counter.
        let off = offset_of!(user_pt_regs, pc);
        let mut bytes = [0_u8; 8];
        self.fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), &mut bytes)
            .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
        state.regs.pc = u64::from_le_bytes(bytes);

        // Next is the processor state.
        let off = offset_of!(user_pt_regs, pstate);
        let mut bytes = [0_u8; 8];
        self.fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), &mut bytes)
            .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
        state.regs.pstate = u64::from_le_bytes(bytes);

        // The stack pointer associated with EL1
        let off = offset_of!(kvm_regs, sp_el1);
        let mut bytes = [0_u8; 8];
        self.fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), &mut bytes)
            .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
        state.sp_el1 = u64::from_le_bytes(bytes);

        // Exception Link Register for EL1, when taking an exception to EL1, this register
        // holds the address to which to return afterwards.
        let off = offset_of!(kvm_regs, elr_el1);
        let mut bytes = [0_u8; 8];
        self.fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), &mut bytes)
            .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
        state.elr_el1 = u64::from_le_bytes(bytes);

        // Saved Program Status Registers, there are 5 of them used in the kernel.
        let mut off = offset_of!(kvm_regs, spsr);
        for i in 0..KVM_NR_SPSR as usize {
            let mut bytes = [0_u8; 8];
            self.fd
                .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), &mut bytes)
                .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
            state.spsr[i] = u64::from_le_bytes(bytes);
            off += std::mem::size_of::<u64>();
        }

        // Now moving on to floating point registers which are stored in the user_fpsimd_state in the kernel:
        // https://elixir.bootlin.com/linux/v4.9.62/source/arch/arm64/include/uapi/asm/kvm.h#L53
        let mut off = offset_of!(kvm_regs, fp_regs.vregs);
        for i in 0..32 {
            let mut bytes = [0_u8; 16];
            self.fd
                .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U128, off), &mut bytes)
                .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
            state.fp_regs.vregs[i] = u128::from_le_bytes(bytes);
            off += mem::size_of::<u128>();
        }

        // Floating-point Status Register
        let off = offset_of!(kvm_regs, fp_regs.fpsr);
        let mut bytes = [0_u8; 4];
        self.fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U32, off), &mut bytes)
            .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
        state.fp_regs.fpsr = u32::from_le_bytes(bytes);

        // Floating-point Control Register
        let off = offset_of!(kvm_regs, fp_regs.fpcr);
        let mut bytes = [0_u8; 4];
        self.fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U32, off), &mut bytes)
            .map_err(|e| cpu::HypervisorCpuError::GetAarchCoreRegister(e.into()))?;
        state.fp_regs.fpcr = u32::from_le_bytes(bytes);
        Ok(state.into())
    }

    #[cfg(target_arch = "riscv64")]
    ///
    /// Returns the RISC-V vCPU core registers.
    /// The `KVM_GET_REGS` ioctl is not available on RISC-V 64-bit,
    /// `KVM_GET_ONE_REG` is used to get registers one by one.
    ///
    fn get_regs(&self) -> cpu::Result<StandardRegisters> {
        let mut state = kvm_riscv_core::default();

        /// Macro used to extract RISC-V register data from KVM Vcpu according
        /// to `$reg_name` provided to `state`.
        macro_rules! riscv64_get_one_reg_from_vcpu {
            (mode) => {
                let off = offset_of!(kvm_riscv_core, mode);
                let mut bytes = [0_u8; 8];
                self.fd
                    .get_one_reg(riscv64_reg_id!(KVM_REG_RISCV_CORE, off), &mut bytes)
                    .map_err(|e| cpu::HypervisorCpuError::GetRiscvCoreRegister(e.into()))?;
                state.mode = u64::from_le_bytes(bytes);
            };
            ($reg_name:ident) => {
                let off = offset_of!(kvm_riscv_core, regs.$reg_name);
                let mut bytes = [0_u8; 8];
                self.fd
                    .get_one_reg(riscv64_reg_id!(KVM_REG_RISCV_CORE, off), &mut bytes)
                    .map_err(|e| cpu::HypervisorCpuError::GetRiscvCoreRegister(e.into()))?;
                state.regs.$reg_name = u64::from_le_bytes(bytes);
            };
        }

        riscv64_get_one_reg_from_vcpu!(pc);
        riscv64_get_one_reg_from_vcpu!(ra);
        riscv64_get_one_reg_from_vcpu!(sp);
        riscv64_get_one_reg_from_vcpu!(gp);
        riscv64_get_one_reg_from_vcpu!(tp);
        riscv64_get_one_reg_from_vcpu!(t0);
        riscv64_get_one_reg_from_vcpu!(t1);
        riscv64_get_one_reg_from_vcpu!(t2);
        riscv64_get_one_reg_from_vcpu!(s0);
        riscv64_get_one_reg_from_vcpu!(s1);
        riscv64_get_one_reg_from_vcpu!(a0);
        riscv64_get_one_reg_from_vcpu!(a1);
        riscv64_get_one_reg_from_vcpu!(a2);
        riscv64_get_one_reg_from_vcpu!(a3);
        riscv64_get_one_reg_from_vcpu!(a4);
        riscv64_get_one_reg_from_vcpu!(a5);
        riscv64_get_one_reg_from_vcpu!(a6);
        riscv64_get_one_reg_from_vcpu!(a7);
        riscv64_get_one_reg_from_vcpu!(s2);
        riscv64_get_one_reg_from_vcpu!(s3);
        riscv64_get_one_reg_from_vcpu!(s4);
        riscv64_get_one_reg_from_vcpu!(s5);
        riscv64_get_one_reg_from_vcpu!(s6);
        riscv64_get_one_reg_from_vcpu!(s7);
        riscv64_get_one_reg_from_vcpu!(s8);
        riscv64_get_one_reg_from_vcpu!(s9);
        riscv64_get_one_reg_from_vcpu!(s10);
        riscv64_get_one_reg_from_vcpu!(s11);
        riscv64_get_one_reg_from_vcpu!(t3);
        riscv64_get_one_reg_from_vcpu!(t4);
        riscv64_get_one_reg_from_vcpu!(t5);
        riscv64_get_one_reg_from_vcpu!(t6);
        riscv64_get_one_reg_from_vcpu!(mode);

        Ok(state.into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU general purpose registers using the `KVM_SET_REGS` ioctl.
    ///
    fn set_regs(&self, regs: &StandardRegisters) -> cpu::Result<()> {
        let regs = (*regs).into();
        self.fd
            .set_regs(&regs)
            .map_err(|e| cpu::HypervisorCpuError::SetStandardRegs(e.into()))
    }

    ///
    /// Sets the vCPU general purpose registers.
    /// The `KVM_SET_REGS` ioctl is not available on AArch64, `KVM_SET_ONE_REG`
    /// is used to set registers one by one.
    ///
    #[cfg(target_arch = "aarch64")]
    fn set_regs(&self, state: &StandardRegisters) -> cpu::Result<()> {
        // The function follows the exact identical order from `state`. Look there
        // for some additional info on registers.
        let kvm_regs_state: kvm_regs = (*state).into();
        let mut off = offset_of!(user_pt_regs, regs);
        for i in 0..31 {
            self.fd
                .set_one_reg(
                    arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
                    &kvm_regs_state.regs.regs[i].to_le_bytes(),
                )
                .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;
            off += std::mem::size_of::<u64>();
        }

        let off = offset_of!(user_pt_regs, sp);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
                &kvm_regs_state.regs.sp.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;

        let off = offset_of!(user_pt_regs, pc);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
                &kvm_regs_state.regs.pc.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;

        let off = offset_of!(user_pt_regs, pstate);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
                &kvm_regs_state.regs.pstate.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;

        let off = offset_of!(kvm_regs, sp_el1);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
                &kvm_regs_state.sp_el1.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;

        let off = offset_of!(kvm_regs, elr_el1);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
                &kvm_regs_state.elr_el1.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;

        let mut off = offset_of!(kvm_regs, spsr);
        for i in 0..KVM_NR_SPSR as usize {
            self.fd
                .set_one_reg(
                    arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
                    &kvm_regs_state.spsr[i].to_le_bytes(),
                )
                .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;
            off += std::mem::size_of::<u64>();
        }

        let mut off = offset_of!(kvm_regs, fp_regs.vregs);
        for i in 0..32 {
            self.fd
                .set_one_reg(
                    arm64_core_reg_id!(KVM_REG_SIZE_U128, off),
                    &kvm_regs_state.fp_regs.vregs[i].to_le_bytes(),
                )
                .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;
            off += mem::size_of::<u128>();
        }

        let off = offset_of!(kvm_regs, fp_regs.fpsr);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U32, off),
                &kvm_regs_state.fp_regs.fpsr.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;

        let off = offset_of!(kvm_regs, fp_regs.fpcr);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U32, off),
                &kvm_regs_state.fp_regs.fpcr.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;
        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    ///
    /// Sets the RISC-V vCPU core registers.
    /// The `KVM_SET_REGS` ioctl is not available on RISC-V 64-bit,
    /// `KVM_SET_ONE_REG` is used to set registers one by one.
    ///
    fn set_regs(&self, state: &StandardRegisters) -> cpu::Result<()> {
        // The function follows the exact identical order from `state`. Look there
        // for some additional info on registers.
        let kvm_regs_state: kvm_riscv_core = (*state).into();

        /// Macro used to set value of specific RISC-V `$reg_name` stored in
        /// `state` to KVM Vcpu.
        macro_rules! riscv64_set_one_reg_to_vcpu {
            (mode) => {
                let off = offset_of!(kvm_riscv_core, mode);
                self.fd
                    .set_one_reg(
                        riscv64_reg_id!(KVM_REG_RISCV_CORE, off),
                        &kvm_regs_state.mode.to_le_bytes(),
                    )
                    .map_err(|e| cpu::HypervisorCpuError::SetRiscvCoreRegister(e.into()))?;
            };
            ($reg_name:ident) => {
                let off = offset_of!(kvm_riscv_core, regs.$reg_name);
                self.fd
                    .set_one_reg(
                        riscv64_reg_id!(KVM_REG_RISCV_CORE, off),
                        &kvm_regs_state.regs.$reg_name.to_le_bytes(),
                    )
                    .map_err(|e| cpu::HypervisorCpuError::SetRiscvCoreRegister(e.into()))?;
            };
        }

        riscv64_set_one_reg_to_vcpu!(pc);
        riscv64_set_one_reg_to_vcpu!(ra);
        riscv64_set_one_reg_to_vcpu!(sp);
        riscv64_set_one_reg_to_vcpu!(gp);
        riscv64_set_one_reg_to_vcpu!(tp);
        riscv64_set_one_reg_to_vcpu!(t0);
        riscv64_set_one_reg_to_vcpu!(t1);
        riscv64_set_one_reg_to_vcpu!(t2);
        riscv64_set_one_reg_to_vcpu!(s0);
        riscv64_set_one_reg_to_vcpu!(s1);
        riscv64_set_one_reg_to_vcpu!(a0);
        riscv64_set_one_reg_to_vcpu!(a1);
        riscv64_set_one_reg_to_vcpu!(a2);
        riscv64_set_one_reg_to_vcpu!(a3);
        riscv64_set_one_reg_to_vcpu!(a4);
        riscv64_set_one_reg_to_vcpu!(a5);
        riscv64_set_one_reg_to_vcpu!(a6);
        riscv64_set_one_reg_to_vcpu!(a7);
        riscv64_set_one_reg_to_vcpu!(s2);
        riscv64_set_one_reg_to_vcpu!(s3);
        riscv64_set_one_reg_to_vcpu!(s4);
        riscv64_set_one_reg_to_vcpu!(s5);
        riscv64_set_one_reg_to_vcpu!(s6);
        riscv64_set_one_reg_to_vcpu!(s7);
        riscv64_set_one_reg_to_vcpu!(s8);
        riscv64_set_one_reg_to_vcpu!(s9);
        riscv64_set_one_reg_to_vcpu!(s10);
        riscv64_set_one_reg_to_vcpu!(s11);
        riscv64_set_one_reg_to_vcpu!(t3);
        riscv64_set_one_reg_to_vcpu!(t4);
        riscv64_set_one_reg_to_vcpu!(t5);
        riscv64_set_one_reg_to_vcpu!(t6);
        riscv64_set_one_reg_to_vcpu!(mode);

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU special registers.
    ///
    fn get_sregs(&self) -> cpu::Result<SpecialRegisters> {
        Ok(self
            .fd
            .get_sregs()
            .map_err(|e| cpu::HypervisorCpuError::GetSpecialRegs(e.into()))?
            .into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU special registers using the `KVM_SET_SREGS` ioctl.
    ///
    fn set_sregs(&self, sregs: &SpecialRegisters) -> cpu::Result<()> {
        let sregs = (*sregs).into();
        self.fd
            .set_sregs(&sregs)
            .map_err(|e| cpu::HypervisorCpuError::SetSpecialRegs(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    fn get_fpu(&self) -> cpu::Result<FpuState> {
        Ok(self
            .fd
            .get_fpu()
            .map_err(|e| cpu::HypervisorCpuError::GetFloatingPointRegs(e.into()))?
            .into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the floating point state (FPU) of a vCPU using the `KVM_SET_FPU` ioctl.
    ///
    fn set_fpu(&self, fpu: &FpuState) -> cpu::Result<()> {
        let fpu: kvm_bindings::kvm_fpu = (*fpu).clone().into();
        self.fd
            .set_fpu(&fpu)
            .map_err(|e| cpu::HypervisorCpuError::SetFloatingPointRegs(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to setup the CPUID registers.
    ///
    fn set_cpuid2(&self, cpuid: &[CpuIdEntry]) -> cpu::Result<()> {
        #[cfg(feature = "tdx")]
        if self.tdx_legacy_cpuid {
            let mut caps = TdxCapabilitiesLegacy::default();
            tdx_command(
                &self.vm_fd.as_raw_fd(),
                TdxCommand::Capabilities,
                0,
                &mut caps as *mut _ as *const _,
            )
            .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))?;

            let cpuid = tdx_legacy_cpuid_entries(&caps, cpuid);
            let kvm_cpuid = <CpuId>::from_entries(&cpuid).map_err(|_| {
                cpu::HypervisorCpuError::SetCpuid(anyhow!("failed to create CpuId"))
            })?;

            let mut supported_mcg_cap: u64 = 0;
            // SAFETY: KVM_X86_GET_MCE_CAP_SUPPORTED writes the supported MCG capability bits.
            let ret = unsafe {
                libc::ioctl(
                    self.kvm_fd,
                    KVM_X86_GET_MCE_CAP_SUPPORTED_RAW,
                    &mut supported_mcg_cap,
                )
            };
            if ret < 0 {
                return Err(cpu::HypervisorCpuError::SetCpuid(
                    std::io::Error::last_os_error().into(),
                ));
            }

            let mut mcg_cap = DEFAULT_MCG_CAP & (supported_mcg_cap | MCG_CAP_BANKS_MASK);
            // SAFETY: KVM_X86_SETUP_MCE takes a pointer to a u64 MCG capability value.
            let ret =
                unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_X86_SETUP_MCE_RAW, &mut mcg_cap) };
            if ret < 0 {
                return Err(cpu::HypervisorCpuError::SetCpuid(
                    std::io::Error::last_os_error().into(),
                ));
            }

            let slots: Vec<KvmGuestMemSlot> = self
                .guest_mem_slots
                .as_ref()
                .map(|slots| slots.read().unwrap().values().copied().collect())
                .unwrap_or_default();

            for slot in &slots {
                self.vm_fd
                    .set_memory_attributes(kvm_memory_attributes {
                        address: slot.guest_phys_addr,
                        size: slot.memory_size,
                        attributes: 0,
                        flags: 0,
                    })
                    .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))?;

                let region = kvm_userspace_memory_region2 {
                    slot: slot.slot,
                    memory_size: 0,
                    ..Default::default()
                };
                // SAFETY: Removing a registered KVM memslot by setting its size to 0.
                unsafe {
                    self.vm_fd
                        .set_user_memory_region2(region)
                        .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))?;
                }
            }
            if let Some(guest_memfds) = &self.guest_memfds {
                let mut guest_memfds = guest_memfds.write().unwrap();
                for slot in &slots {
                    guest_memfds.remove(&slot.slot);
                }
            }

            let set_cpuid_result = self
                .fd
                .set_cpuid2(&kvm_cpuid)
                .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()));

            let mut restore_result = Ok(());
            for slot in &slots {
                let mut slot = *slot;
                if let Some(guest_memfds) = &self.guest_memfds {
                    let fd = match create_guest_memfd(
                        &self.vm_fd,
                        slot.memory_size,
                        self.guest_memfd_legacy_hugepage,
                    ) {
                        Ok(fd) => fd,
                        Err(e) => {
                            restore_result = Err(cpu::HypervisorCpuError::SetCpuid(e.into()));
                            break;
                        }
                    };
                    slot.guest_memfd = fd.as_raw_fd() as u32;
                    guest_memfds.write().unwrap().insert(slot.slot, fd);
                    if let Some(guest_mem_slots) = &self.guest_mem_slots {
                        guest_mem_slots.write().unwrap().insert(slot.slot, slot);
                    }
                }
                let region = kvm_userspace_memory_region2 {
                    slot: slot.slot,
                    guest_phys_addr: slot.guest_phys_addr,
                    memory_size: slot.memory_size,
                    userspace_addr: slot.userspace_addr,
                    flags: slot.flags,
                    guest_memfd: slot.guest_memfd,
                    guest_memfd_offset: slot.guest_memfd_offset,
                    ..Default::default()
                };
                // SAFETY: Restoring the same non-overlapping memslot that was removed above.
                if let Err(e) = unsafe { self.vm_fd.set_user_memory_region2(region) } {
                    restore_result = Err(cpu::HypervisorCpuError::SetCpuid(e.into()));
                    break;
                }
                if let Err(e) = self.vm_fd.set_memory_attributes(kvm_memory_attributes {
                    address: slot.guest_phys_addr,
                    size: slot.memory_size,
                    attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as u64,
                    flags: 0,
                }) {
                    restore_result = Err(cpu::HypervisorCpuError::SetCpuid(e.into()));
                    break;
                }
            }

            set_cpuid_result?;
            restore_result?;
            return Ok(());
        }

        #[cfg(feature = "tdx")]
        let cpuid: Vec<kvm_bindings::kvm_cpuid_entry2> =
            cpuid.iter().map(|e| (*e).into()).collect();
        #[cfg(not(feature = "tdx"))]
        let cpuid: Vec<kvm_bindings::kvm_cpuid_entry2> =
            cpuid.iter().map(|e| (*e).into()).collect();
        let kvm_cpuid = <CpuId>::from_entries(&cpuid)
            .map_err(|_| cpu::HypervisorCpuError::SetCpuid(anyhow!("failed to create CpuId")))?;

        self.fd
            .set_cpuid2(&kvm_cpuid)
            .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to enable HyperV SynIC
    ///
    fn enable_hyperv_synic(&self) -> cpu::Result<()> {
        // Update the information about Hyper-V SynIC being enabled and
        // emulated as it will influence later which MSRs should be saved.
        self.hyperv_synic.store(true, Ordering::Release);

        let cap = kvm_enable_cap {
            cap: KVM_CAP_HYPERV_SYNIC,
            ..Default::default()
        };
        self.fd
            .enable_cap(&cap)
            .map_err(|e| cpu::HypervisorCpuError::EnableHyperVSyncIc(e.into()))
    }

    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    #[cfg(target_arch = "x86_64")]
    fn get_cpuid2(&self, num_entries: usize) -> cpu::Result<Vec<CpuIdEntry>> {
        let kvm_cpuid = self
            .fd
            .get_cpuid2(num_entries)
            .map_err(|e| cpu::HypervisorCpuError::GetCpuid(e.into()))?;

        let v = kvm_cpuid.as_slice().iter().map(|e| (*e).into()).collect();

        Ok(v)
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn get_lapic(&self) -> cpu::Result<LapicState> {
        Ok(self
            .fd
            .get_lapic()
            .map_err(|e| cpu::HypervisorCpuError::GetlapicState(e.into()))?
            .into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn set_lapic(&self, klapic: &LapicState) -> cpu::Result<()> {
        let klapic: kvm_bindings::kvm_lapic_state = (*klapic).clone().into();
        self.fd
            .set_lapic(&klapic)
            .map_err(|e| cpu::HypervisorCpuError::SetLapicState(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    fn get_msrs(&self, msrs: &mut Vec<MsrEntry>) -> cpu::Result<usize> {
        let kvm_msrs: Vec<kvm_msr_entry> = msrs.iter().map(|e| (*e).into()).collect();
        let mut kvm_msrs = MsrEntries::from_entries(&kvm_msrs).unwrap();
        let succ = self
            .fd
            .get_msrs(&mut kvm_msrs)
            .map_err(|e| cpu::HypervisorCpuError::GetMsrEntries(e.into()))?;

        msrs[..succ].copy_from_slice(
            &kvm_msrs.as_slice()[..succ]
                .iter()
                .map(|e| (*e).into())
                .collect::<Vec<MsrEntry>>(),
        );

        Ok(succ)
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    fn set_msrs(&self, msrs: &[MsrEntry]) -> cpu::Result<usize> {
        let kvm_msrs: Vec<kvm_msr_entry> = msrs.iter().map(|e| (*e).into()).collect();
        let kvm_msrs = MsrEntries::from_entries(&kvm_msrs).unwrap();
        self.fd
            .set_msrs(&kvm_msrs)
            .map_err(|e| cpu::HypervisorCpuError::SetMsrEntries(e.into()))
    }

    ///
    /// Returns the vcpu's current "multiprocessing state".
    ///
    fn get_mp_state(&self) -> cpu::Result<MpState> {
        Ok(self
            .fd
            .get_mp_state()
            .map_err(|e| cpu::HypervisorCpuError::GetMpState(e.into()))?
            .into())
    }

    ///
    /// Sets the vcpu's current "multiprocessing state".
    ///
    fn set_mp_state(&self, mp_state: MpState) -> cpu::Result<()> {
        self.fd
            .set_mp_state(mp_state.into())
            .map_err(|e| cpu::HypervisorCpuError::SetMpState(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Translates guest virtual address to guest physical address using the `KVM_TRANSLATE` ioctl.
    ///
    fn translate_gva(&self, gva: u64, _flags: u64) -> cpu::Result<(u64, u32)> {
        let tr = self
            .fd
            .translate_gva(gva)
            .map_err(|e| cpu::HypervisorCpuError::TranslateVirtualAddress(e.into()))?;
        // tr.valid is set if the GVA is mapped to valid GPA.
        match tr.valid {
            0 => Err(cpu::HypervisorCpuError::TranslateVirtualAddress(anyhow!(
                "Invalid GVA: {gva:#x}"
            ))),
            _ => Ok((tr.physical_address, 0)),
        }
    }

    ///
    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    fn run(&mut self) -> std::result::Result<cpu::VmExit, cpu::HypervisorCpuError> {
        match self.fd.run() {
            Ok(run) => match run {
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoIn(addr, data) => {
                    if let Some(vm_ops) = &self.vm_ops {
                        let ret = vm_ops.pio_read(addr.into(), data);
                        #[cfg(feature = "tdx")]
                        if self.tdx_legacy_cpuid {
                            let n = TDX_IO_EXIT_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
                            if tdx_should_log_io(n, addr) {
                                info!("TDX_IO in port={addr:#x} len={} data={data:x?}", data.len());
                            }
                        }
                        return ret
                            .map(|_| cpu::VmExit::Ignore)
                            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()));
                    }

                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    let data = data.to_vec();
                    #[cfg(feature = "tdx")]
                    if self.tdx_legacy_cpuid {
                        if data.len() == 4 && (addr == 0x514 || addr == 0x518) {
                            let mut buf = [0u8; 4];
                            buf.copy_from_slice(&data);
                            let val = u32::from_be_bytes(buf);
                            if addr == 0x514 {
                                self.tdx_fw_cfg_dma_hi = val;
                            } else {
                                let dma_address =
                                    ((self.tdx_fw_cfg_dma_hi as u64) << 32) | val as u64;
                                let start = dma_address & !0xfffu64;
                                self.convert_guest_memory_region(start, 0x1000, false)?;
                            }
                        }
                        if addr == 0x64 && data.first().copied() == Some(0xfe) {
                            match self.fd.get_regs() {
                                Ok(regs) => warn!(
                                    "TDX i8042 reset PIO at rip={:#x} rsp={:#x} rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x}",
                                    regs.rip,
                                    regs.rsp,
                                    regs.rax,
                                    regs.rbx,
                                    regs.rcx,
                                    regs.rdx,
                                    regs.rsi,
                                    regs.rdi
                                ),
                                Err(e) => warn!("TDX i8042 reset PIO; failed to read regs: {e}"),
                            }
                        }
                        let n = TDX_IO_EXIT_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
                        if tdx_should_log_io(n, addr) {
                            info!(
                                "TDX_IO out port={addr:#x} len={} data={data:x?}",
                                data.len()
                            );
                        }
                    }
                    if let Some(vm_ops) = &self.vm_ops {
                        return vm_ops
                            .pio_write(addr.into(), &data)
                            .map(|_| cpu::VmExit::Ignore)
                            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()));
                    }

                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoapicEoi(vector) => Ok(cpu::VmExit::IoapicEoi(vector)),
                #[cfg(target_arch = "x86_64")]
                VcpuExit::Shutdown | VcpuExit::Hlt => Ok(cpu::VmExit::Reset),

                #[cfg(target_arch = "aarch64")]
                VcpuExit::SystemEvent(event_type, flags) => {
                    use kvm_bindings::{KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
                    // On Aarch64, when the VM is shutdown, run() returns
                    // VcpuExit::SystemEvent with reason KVM_SYSTEM_EVENT_SHUTDOWN
                    if event_type == KVM_SYSTEM_EVENT_RESET {
                        Ok(cpu::VmExit::Reset)
                    } else if event_type == KVM_SYSTEM_EVENT_SHUTDOWN {
                        Ok(cpu::VmExit::Shutdown)
                    } else {
                        Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                            "Unexpected system event with type 0x{event_type:x}, flags 0x{flags:x?}",
                        )))
                    }
                }

                VcpuExit::MmioRead(addr, data) => {
                    if let Some(vm_ops) = &self.vm_ops {
                        let ret = vm_ops.mmio_read(addr, data);
                        #[cfg(all(feature = "tdx", target_arch = "x86_64"))]
                        if self.tdx_legacy_cpuid {
                            let n = TDX_IO_EXIT_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
                            if n < 512 {
                                info!(
                                    "TDX_MMIO read addr={addr:#x} len={} data={data:x?}",
                                    data.len()
                                );
                            }
                        }
                        return ret
                            .map(|_| cpu::VmExit::Ignore)
                            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()));
                    }

                    Ok(cpu::VmExit::Ignore)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    #[cfg(all(feature = "tdx", target_arch = "x86_64"))]
                    if self.tdx_legacy_cpuid {
                        let n = TDX_IO_EXIT_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
                        if n < 512 {
                            info!(
                                "TDX_MMIO write addr={addr:#x} len={} data={data:x?}",
                                data.len()
                            );
                        }
                    }
                    if let Some(vm_ops) = &self.vm_ops {
                        return vm_ops
                            .mmio_write(addr, data)
                            .map(|_| cpu::VmExit::Ignore)
                            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()));
                    }

                    Ok(cpu::VmExit::Ignore)
                }
                VcpuExit::Hyperv => Ok(cpu::VmExit::Hyperv),
                #[cfg(feature = "tdx")]
                VcpuExit::Unsupported(reason)
                    if reason == KVM_EXIT_TDX || reason == KVM_EXIT_TDX_LEGACY =>
                {
                    Ok(cpu::VmExit::Tdx)
                }
                VcpuExit::Debug(_) => Ok(cpu::VmExit::Debug),
                #[cfg(any(feature = "sev_snp", feature = "tdx"))]
                VcpuExit::Hypercall(hypercall) => {
                    // https://docs.kernel.org/virt/kvm/x86/hypercalls.html#kvm-hc-map-gpa-range
                    const KVM_HC_MAP_GPA_RANGE: u64 = 12;
                    let (nr, args, ret_ptr) = {
                        let ret_ptr = hypercall.ret as *mut u64;
                        (hypercall.nr, hypercall.args, ret_ptr)
                    };
                    debug!(
                        "VcpuExit::Hypercall nr={} args=[{:#x}, {:#x}, {:#x}]",
                        nr, args[0], args[1], args[2]
                    );
                    // 4th bit of attributes argument is encrypted page bit
                    match nr {
                        KVM_HC_MAP_GPA_RANGE => {
                            // guest physical address of start page
                            let address = args[0];
                            // num pages to map from start address
                            let num_pages = args[1];
                            // bits[0-3]  = page size encoding
                            // bits[4]   = 1 if private, 0 if shared
                            // bits[5-63] = zero
                            let attributes = args[2];
                            // TODO: Add 2mb page support
                            const PAGE_SIZE_4K: u64 = 4096;
                            let size = num_pages * PAGE_SIZE_4K;
                            // bit 4 = private attribute encoding
                            const PRIVATE_ENCODING_BITMASK: u64 = 0b10000;
                            debug!(
                                "KVM_HC_MAP_GPA_RANGE: address={address:#x}, pages={num_pages}, attributes={attributes:#x}"
                            );
                            let private = attributes & PRIVATE_ENCODING_BITMASK > 0;
                            self.convert_guest_memory_region(address, size, private)?;
                            unsafe {
                                *ret_ptr = 0;
                            }

                            Ok(cpu::VmExit::Ignore)
                        }
                        _ => {
                            unsafe {
                                *ret_ptr = u64::MAX;
                            }
                            Ok(cpu::VmExit::Ignore)
                        }
                    }
                }

                #[cfg(any(feature = "sev_snp", feature = "tdx"))]
                VcpuExit::MemoryFault { flags, gpa, size } => {
                    debug!("VcpuExit::MemoryFault: flags={flags:#x}, gpa={gpa:#x}, size={size:#x}");

                    const KVM_MEMORY_EXIT_FLAG_PRIVATE: u64 =
                        kvm_bindings::KVM_MEMORY_EXIT_FLAG_PRIVATE as u64;

                    if flags & !KVM_MEMORY_EXIT_FLAG_PRIVATE != 0 {
                        return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                            "VcpuExit::MemoryFault: unknown flags {flags:#x}"
                        )));
                    }

                    let private = flags & KVM_MEMORY_EXIT_FLAG_PRIVATE != 0;

                    #[cfg(feature = "tdx")]
                    if self.tdx_legacy_cpuid {
                        if !private {
                            let mut flushed_fault = false;
                            for (flush_start, flush_size) in
                                self.take_all_tdx_pending_shared_ranges()
                            {
                                if gpa >= flush_start && gpa < flush_start + flush_size {
                                    flushed_fault = true;
                                }
                                self.convert_guest_memory_region(flush_start, flush_size, false)?;
                            }
                            if !flushed_fault {
                                self.convert_guest_memory_region(gpa, size, false)?;
                            }
                        } else {
                            self.convert_guest_memory_region(gpa, size, true)?;
                        }
                        return Ok(cpu::VmExit::Ignore);
                    }

                    self.convert_guest_memory_region(gpa, size, private)?;
                    Ok(cpu::VmExit::Ignore)
                }

                r => {
                    let exit_debug = format!("{r:?}");
                    let kvm_run = self.fd.get_kvm_run();
                    let raw_exit_reason = (*kvm_run).exit_reason;
                    // SAFETY: for KVM_EXIT_UNKNOWN the hw union member is active.
                    let hardware_exit_reason =
                        unsafe { (*kvm_run).__bindgen_anon_1.hw.hardware_exit_reason };
                    warn!(
                        "KVM_RUN unexpected exit reason: {exit_debug}, raw_exit_reason={raw_exit_reason}, hardware_exit_reason={hardware_exit_reason:#x}"
                    );
                    Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                        "Unexpected exit reason on vcpu run: {exit_debug}"
                    )))
                }
            },

            Err(ref e) => match e.errno() {
                libc::EAGAIN | libc::EINTR => Ok(cpu::VmExit::Ignore),
                _ => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "VCPU error {e:?}"
                ))),
            },
        }
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Let the guest know that it has been paused, which prevents from
    /// potential soft lockups when being resumed.
    ///
    fn notify_guest_clock_paused(&self) -> cpu::Result<()> {
        if let Err(e) = self.fd.kvmclock_ctrl() {
            // Linux kernel returns -EINVAL if the PV clock isn't yet initialised
            // which could be because we're still in firmware or the guest doesn't
            // use KVM clock.
            if e.errno() != libc::EINVAL {
                return Err(cpu::HypervisorCpuError::NotifyGuestClockPaused(e.into()));
            }
        }

        Ok(())
    }

    #[cfg(not(target_arch = "riscv64"))]
    ///
    /// Sets debug registers to set hardware breakpoints and/or enable single step.
    ///
    fn set_guest_debug(
        &self,
        addrs: &[vm_memory::GuestAddress],
        singlestep: bool,
    ) -> cpu::Result<()> {
        let mut dbg = kvm_guest_debug {
            #[cfg(target_arch = "x86_64")]
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP,
            #[cfg(target_arch = "aarch64")]
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW,
            ..Default::default()
        };
        if singlestep {
            dbg.control |= KVM_GUESTDBG_SINGLESTEP;
        }

        // Set the debug registers.
        // Here we assume that the number of addresses do not exceed what
        // `Hypervisor::get_guest_debug_hw_bps()` specifies.
        #[cfg(target_arch = "x86_64")]
        {
            // Set bits 9 and 10.
            // bit 9: GE (global exact breakpoint enable) flag.
            // bit 10: always 1.
            dbg.arch.debugreg[7] = 0x0600;

            for (i, addr) in addrs.iter().enumerate() {
                dbg.arch.debugreg[i] = addr.0;
                // Set global breakpoint enable flag
                dbg.arch.debugreg[7] |= 2 << (i * 2);
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            for (i, addr) in addrs.iter().enumerate() {
                // DBGBCR_EL1 (Debug Breakpoint Control Registers, D13.3.2):
                // bit 0: 1 (Enabled)
                // bit 1~2: 0b11 (PMC = EL1/EL0)
                // bit 5~8: 0b1111 (BAS = AArch64)
                // others: 0
                dbg.arch.dbg_bcr[i] = 0b1u64 | 0b110u64 | 0b1_1110_0000u64;
                // DBGBVR_EL1 (Debug Breakpoint Value Registers, D13.3.3):
                // bit 2~52: VA[2:52]
                dbg.arch.dbg_bvr[i] = (!0u64 >> 11) & addr.0;
            }
        }
        self.fd
            .set_guest_debug(&dbg)
            .map_err(|e| cpu::HypervisorCpuError::SetDebugRegs(e.into()))
    }

    #[cfg(target_arch = "aarch64")]
    fn vcpu_get_finalized_features(&self) -> i32 {
        kvm_bindings::KVM_ARM_VCPU_SVE as i32
    }

    #[cfg(target_arch = "aarch64")]
    fn vcpu_set_processor_features(
        &self,
        vm: &dyn crate::Vm,
        kvi: &mut crate::VcpuInit,
        id: u32,
    ) -> cpu::Result<()> {
        use std::arch::is_aarch64_feature_detected;
        #[allow(clippy::nonminimal_bool)]
        let sve_supported =
            is_aarch64_feature_detected!("sve") || is_aarch64_feature_detected!("sve2");

        let mut kvm_kvi: kvm_bindings::kvm_vcpu_init = (*kvi).into();

        // We already checked that the capability is supported.
        kvm_kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        if vm
            .as_any()
            .downcast_ref::<crate::kvm::KvmVm>()
            .unwrap()
            .check_extension(Cap::ArmPmuV3)
        {
            kvm_kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PMU_V3;
        }

        if sve_supported
            && vm
                .as_any()
                .downcast_ref::<crate::kvm::KvmVm>()
                .unwrap()
                .check_extension(Cap::ArmSve)
        {
            kvm_kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_SVE;
        }

        // Non-boot cpus are powered off initially.
        if id > 0 {
            kvm_kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        *kvi = kvm_kvi.into();

        Ok(())
    }

    ///
    /// Return VcpuInit with default value set
    ///
    #[cfg(target_arch = "aarch64")]
    fn create_vcpu_init(&self) -> crate::VcpuInit {
        kvm_bindings::kvm_vcpu_init::default().into()
    }

    #[cfg(target_arch = "aarch64")]
    fn vcpu_init(&self, kvi: &crate::VcpuInit) -> cpu::Result<()> {
        let kvm_kvi: kvm_bindings::kvm_vcpu_init = (*kvi).into();
        self.fd
            .vcpu_init(&kvm_kvi)
            .map_err(|e| cpu::HypervisorCpuError::VcpuInit(e.into()))
    }

    #[cfg(target_arch = "aarch64")]
    fn vcpu_finalize(&self, feature: i32) -> cpu::Result<()> {
        self.fd
            .vcpu_finalize(&feature)
            .map_err(|e| cpu::HypervisorCpuError::VcpuFinalize(e.into()))
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    ///
    /// Gets a list of the guest registers that are supported for the
    /// KVM_GET_ONE_REG/KVM_SET_ONE_REG calls.
    ///
    fn get_reg_list(&self, reg_list: &mut RegList) -> cpu::Result<()> {
        let mut kvm_reg_list: kvm_bindings::RegList = reg_list.clone().into();
        self.fd
            .get_reg_list(&mut kvm_reg_list)
            .map_err(|e: kvm_ioctls::Error| cpu::HypervisorCpuError::GetRegList(e.into()))?;
        *reg_list = kvm_reg_list.into();
        Ok(())
    }

    ///
    /// Gets the value of a system register
    ///
    #[cfg(target_arch = "aarch64")]
    fn get_sys_reg(&self, sys_reg: u32) -> cpu::Result<u64> {
        //
        // Arm Architecture Reference Manual defines the encoding of
        // AArch64 system registers, see
        // https://developer.arm.com/documentation/ddi0487 (chapter D12).
        // While KVM defines another ID for each AArch64 system register,
        // which is used in calling `KVM_G/SET_ONE_REG` to access a system
        // register of a guest.
        // A mapping exists between the Arm standard encoding and the KVM ID.
        // This function takes the standard u32 ID as input parameter, converts
        // it to the corresponding KVM ID, and call `KVM_GET_ONE_REG` API to
        // get the value of the system parameter.
        //
        let id: u64 = KVM_REG_ARM64
            | KVM_REG_SIZE_U64
            | KVM_REG_ARM64_SYSREG as u64
            | ((((sys_reg) >> 5)
                & (KVM_REG_ARM64_SYSREG_OP0_MASK
                    | KVM_REG_ARM64_SYSREG_OP1_MASK
                    | KVM_REG_ARM64_SYSREG_CRN_MASK
                    | KVM_REG_ARM64_SYSREG_CRM_MASK
                    | KVM_REG_ARM64_SYSREG_OP2_MASK)) as u64);
        let mut bytes = [0_u8; 8];
        self.fd
            .get_one_reg(id, &mut bytes)
            .map_err(|e| cpu::HypervisorCpuError::GetSysRegister(e.into()))?;
        Ok(u64::from_le_bytes(bytes))
    }

    ///
    /// Gets the value of a non-core register
    ///
    #[cfg(target_arch = "riscv64")]
    fn get_non_core_reg(&self, _non_core_reg: u32) -> cpu::Result<u64> {
        unimplemented!()
    }

    ///
    /// Configure core registers for a given CPU.
    ///
    #[cfg(target_arch = "aarch64")]
    fn setup_regs(&self, cpu_id: u32, boot_ip: u64, fdt_start: u64) -> cpu::Result<()> {
        // Get the register index of the PSTATE (Processor State) register.
        let pstate = offset_of!(kvm_regs, regs.pstate);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U64, pstate),
                &regs::PSTATE_FAULT_BITS_64.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;

        // Other vCPUs are powered off initially awaiting PSCI wakeup.
        if cpu_id == 0 {
            // Setting the PC (Processor Counter) to the current program address (kernel address).
            let pc = offset_of!(kvm_regs, regs.pc);
            self.fd
                .set_one_reg(
                    arm64_core_reg_id!(KVM_REG_SIZE_U64, pc),
                    &boot_ip.to_le_bytes(),
                )
                .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;

            // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
            // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
            // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
            // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
            let regs0 = offset_of!(kvm_regs, regs.regs);
            self.fd
                .set_one_reg(
                    arm64_core_reg_id!(KVM_REG_SIZE_U64, regs0),
                    &fdt_start.to_le_bytes(),
                )
                .map_err(|e| cpu::HypervisorCpuError::SetAarchCoreRegister(e.into()))?;
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    ///
    /// Configure registers for a given RISC-V CPU.
    ///
    fn setup_regs(&self, cpu_id: u32, boot_ip: u64, fdt_start: u64) -> cpu::Result<()> {
        // Setting the A0 () to the hartid of this CPU.
        let a0 = offset_of!(kvm_riscv_core, regs.a0);
        self.fd
            .set_one_reg(
                riscv64_reg_id!(KVM_REG_RISCV_CORE, a0),
                &u64::from(cpu_id).to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetRiscvCoreRegister(e.into()))?;

        // Setting the PC (Processor Counter) to the current program address (kernel address).
        let pc = offset_of!(kvm_riscv_core, regs.pc);
        self.fd
            .set_one_reg(
                riscv64_reg_id!(KVM_REG_RISCV_CORE, pc),
                &boot_ip.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetRiscvCoreRegister(e.into()))?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        //
        // In an earlier version of https://www.kernel.org/doc/Documentation/arch/riscv/boot.rst:
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 64 kilobytes in size."
        let a1 = offset_of!(kvm_riscv_core, regs.a1);
        self.fd
            .set_one_reg(
                riscv64_reg_id!(KVM_REG_RISCV_CORE, a1),
                &fdt_start.to_le_bytes(),
            )
            .map_err(|e| cpu::HypervisorCpuError::SetRiscvCoreRegister(e.into()))?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Get the current CPU state
    ///
    /// Ordering requirements:
    ///
    /// KVM_GET_MP_STATE calls kvm_apic_accept_events(), which might modify
    /// vCPU/LAPIC state. As such, it must be done before most everything
    /// else, otherwise we cannot restore everything and expect it to work.
    ///
    /// KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
    /// still running.
    ///
    /// KVM_GET_LAPIC may change state of LAPIC before returning it.
    ///
    /// GET_VCPU_EVENTS should probably be last to save. The code looks as
    /// it might as well be affected by internal state modifications of the
    /// GET ioctls.
    ///
    /// SREGS saves/restores a pending interrupt, similar to what
    /// VCPU_EVENTS also does.
    ///
    /// GET_MSRS requires a prepopulated data structure to do something
    /// meaningful. For SET_MSRS it will then contain good data.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use hypervisor::kvm::KvmHypervisor;
    /// # use std::sync::Arc;
    /// # use hypervisor::HypervisorVmConfig;
    /// let kvm = KvmHypervisor::new().unwrap();
    /// let hv = Arc::new(kvm);
    /// let vm = hv.create_vm(HypervisorVmConfig::default()).expect("new VM fd creation failed");
    /// vm.enable_split_irq().unwrap();
    /// let vcpu = vm.create_vcpu(0, None).unwrap();
    /// let state = vcpu.state().unwrap();
    /// ```
    fn state(&self) -> cpu::Result<CpuState> {
        let cpuid = self.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
        let mp_state = self.get_mp_state()?.into();
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let xsave = if self.xsave_size > 0 {
            self.get_xsave2()?
        } else {
            self.get_xsave()?
        };
        let xcrs = self.get_xcrs()?;
        let lapic_state = self.get_lapic()?;
        let fpu = self.get_fpu()?;
        let nested_state = self.nested_state()?;

        // Try to get all MSRs based on the list previously retrieved from KVM.
        // If the number of MSRs obtained from GET_MSRS is different from the
        // expected amount, we fallback onto a slower method by getting MSRs
        // by chunks. This is the only way to make sure we try to get as many
        // MSRs as possible, even if some MSRs are not supported.
        let mut msr_entries = self.msrs.clone();

        // Save extra MSRs if the Hyper-V synthetic interrupt controller is
        // emulated.
        let hyperv_synic = self.hyperv_synic.load(Ordering::Acquire);
        if hyperv_synic {
            let hyperv_synic_msrs = vec![
                0x40000020, 0x40000021, 0x40000080, 0x40000081, 0x40000082, 0x40000083, 0x40000084,
                0x40000090, 0x40000091, 0x40000092, 0x40000093, 0x40000094, 0x40000095, 0x40000096,
                0x40000097, 0x40000098, 0x40000099, 0x4000009a, 0x4000009b, 0x4000009c, 0x4000009d,
                0x4000009e, 0x4000009f, 0x400000b0, 0x400000b1, 0x400000b2, 0x400000b3, 0x400000b4,
                0x400000b5, 0x400000b6, 0x400000b7,
            ];
            for index in hyperv_synic_msrs {
                let msr = kvm_msr_entry {
                    index,
                    ..Default::default()
                };
                msr_entries.push(msr.into());
            }
        }

        let expected_num_msrs = msr_entries.len();
        let num_msrs = self.get_msrs(&mut msr_entries)?;
        let msrs = if num_msrs == expected_num_msrs {
            msr_entries
        } else {
            let mut faulty_msr_index = num_msrs;
            let mut msr_entries_tmp = msr_entries[..faulty_msr_index].to_vec();

            loop {
                warn!(
                    "Detected faulty MSR 0x{:x} while getting MSRs",
                    msr_entries[faulty_msr_index].index
                );

                // Skip the first bad MSR
                let start_pos = faulty_msr_index + 1;

                let mut sub_msr_entries = msr_entries[start_pos..].to_vec();
                let num_msrs = self.get_msrs(&mut sub_msr_entries)?;

                msr_entries_tmp.extend(&sub_msr_entries[..num_msrs]);

                if num_msrs == sub_msr_entries.len() {
                    break;
                }

                faulty_msr_index = start_pos + num_msrs;
            }

            msr_entries_tmp
        };

        let vcpu_events = self.get_vcpu_events()?;
        let tsc_khz = self.tsc_khz()?;

        Ok(VcpuKvmState {
            cpuid,
            msrs,
            vcpu_events,
            regs: regs.into(),
            sregs: sregs.into(),
            fpu,
            lapic_state,
            xsave,
            xcrs,
            mp_state,
            tsc_khz,
            nested_state,
            hyperv_synic,
        }
        .into())
    }

    ///
    /// Get the current AArch64 CPU state
    ///
    #[cfg(target_arch = "aarch64")]
    fn state(&self) -> cpu::Result<CpuState> {
        let mut state = VcpuKvmState {
            mp_state: self.get_mp_state()?.into(),
            ..Default::default()
        };
        // Get core registers
        state.core_regs = self.get_regs()?.into();

        // Get systerm register
        // Call KVM_GET_REG_LIST to get all registers available to the guest.
        // For ArmV8 there are around 500 registers.
        let mut sys_regs: Vec<kvm_bindings::kvm_one_reg> = Vec::new();
        let mut reg_list = kvm_bindings::RegList::new(500).unwrap();
        self.fd
            .get_reg_list(&mut reg_list)
            .map_err(|e| cpu::HypervisorCpuError::GetRegList(e.into()))?;

        // At this point reg_list should contain: core registers and system
        // registers.
        // The register list contains the number of registers and their ids. We
        // will be needing to call KVM_GET_ONE_REG on each id in order to save
        // all of them. We carve out from the list  the core registers which are
        // represented in the kernel by kvm_regs structure and for which we can
        // calculate the id based on the offset in the structure.
        reg_list.retain(|regid| is_system_register(*regid));

        // Now, for the rest of the registers left in the previously fetched
        // register list, we are simply calling KVM_GET_ONE_REG.
        let indices = reg_list.as_slice();
        for index in indices.iter() {
            let mut bytes = [0_u8; 8];
            self.fd
                .get_one_reg(*index, &mut bytes)
                .map_err(|e| cpu::HypervisorCpuError::GetSysRegister(e.into()))?;
            sys_regs.push(kvm_bindings::kvm_one_reg {
                id: *index,
                addr: u64::from_le_bytes(bytes),
            });
        }

        state.sys_regs = sys_regs;

        Ok(state.into())
    }

    #[cfg(target_arch = "riscv64")]
    ///
    /// Get the current RISC-V 64-bit CPU state
    ///
    fn state(&self) -> cpu::Result<CpuState> {
        let mut state = VcpuKvmState {
            mp_state: self.get_mp_state()?.into(),
            ..Default::default()
        };
        // Get core registers
        state.core_regs = self.get_regs()?.into();

        // Get non-core register
        // Call KVM_GET_REG_LIST to get all registers available to the guest.
        // For RISC-V 64-bit there are around 200 registers.
        let mut sys_regs: Vec<kvm_bindings::kvm_one_reg> = Vec::new();
        let mut reg_list = kvm_bindings::RegList::new(200).unwrap();
        self.fd
            .get_reg_list(&mut reg_list)
            .map_err(|e| cpu::HypervisorCpuError::GetRegList(e.into()))?;

        // At this point reg_list should contain:
        // - core registers
        // - config registers
        // - timer registers
        // - control and status registers
        // - AIA control and status registers
        // - smstateen control and status registers
        // - sbi_sta control and status registers.
        //
        // The register list contains the number of registers and their ids. We
        // will be needing to call KVM_GET_ONE_REG on each id in order to save
        // all of them. We carve out from the list the core registers which are
        // represented in the kernel by `kvm_riscv_core` structure and for which
        // we can calculate the id based on the offset in the structure.
        reg_list.retain(|regid| is_non_core_register(*regid));

        // Now, for the rest of the registers left in the previously fetched
        // register list, we are simply calling KVM_GET_ONE_REG.
        let indices = reg_list.as_slice();
        for index in indices.iter() {
            let mut bytes = [0_u8; 8];
            self.fd
                .get_one_reg(*index, &mut bytes)
                .map_err(|e| cpu::HypervisorCpuError::GetSysRegister(e.into()))?;
            sys_regs.push(kvm_bindings::kvm_one_reg {
                id: *index,
                addr: u64::from_le_bytes(bytes),
            });
        }

        state.non_core_regs = sys_regs;

        Ok(state.into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Restore the previously saved CPU state
    ///
    /// Ordering requirements:
    ///
    /// KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
    /// still running.
    ///
    /// Some SET ioctls (like set_mp_state) depend on kvm_vcpu_is_bsp(), so
    /// if we ever change the BSP, we have to do that before restoring anything.
    /// The same seems to be true for CPUID stuff.
    ///
    /// SREGS saves/restores a pending interrupt, similar to what
    /// VCPU_EVENTS also does.
    ///
    /// SET_REGS clears pending exceptions unconditionally, thus, it must be
    /// done before SET_VCPU_EVENTS, which restores it.
    ///
    /// SET_LAPIC must come after SET_SREGS, because the latter restores
    /// the apic base msr.
    ///
    /// SET_LAPIC must come before SET_MSRS, because the TSC deadline MSR
    /// only restores successfully, when the LAPIC is correctly configured.
    ///
    /// Arguments: CpuState
    /// # Example
    ///
    /// ```rust
    /// # use hypervisor::kvm::KvmHypervisor;
    /// # use hypervisor::HypervisorVmConfig;
    /// # use std::sync::Arc;
    /// let kvm = KvmHypervisor::new().unwrap();
    /// let hv = Arc::new(kvm);
    /// let vm = hv.create_vm(HypervisorVmConfig::default()).expect("new VM fd creation failed");
    /// vm.enable_split_irq().unwrap();
    /// let vcpu = vm.create_vcpu(0, None).unwrap();
    /// let state = vcpu.state().unwrap();
    /// vcpu.set_state(&state).unwrap();
    /// ```
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        let state: VcpuKvmState = state.clone().into();
        self.set_cpuid2(&state.cpuid)?;
        self.set_mp_state(state.mp_state.into())?;
        self.set_regs(&state.regs.into())?;
        self.set_sregs(&state.sregs.into())?;
        if self.xsave_size > 0 {
            self.set_xsave2(&state.xsave)?;
        } else {
            self.set_xsave(&state.xsave)?;
        }
        self.set_xcrs(&state.xcrs)?;
        self.set_lapic(&state.lapic_state)?;
        self.set_fpu(&state.fpu)?;
        if let Some(nested_state) = state.nested_state {
            self.set_nested_state(&nested_state)?;
        }

        if let Some(freq) = state.tsc_khz {
            self.set_tsc_khz(freq)?;
        }

        if state.hyperv_synic {
            self.enable_hyperv_synic()?;
        }

        // Try to set all MSRs previously stored.
        // If the number of MSRs set from SET_MSRS is different from the
        // expected amount, we fallback onto a slower method by setting MSRs
        // by chunks. This is the only way to make sure we try to set as many
        // MSRs as possible, even if some MSRs are not supported.
        let expected_num_msrs = state.msrs.len();
        let num_msrs = self.set_msrs(&state.msrs)?;
        if num_msrs != expected_num_msrs {
            let mut faulty_msr_index = num_msrs;

            loop {
                warn!(
                    "Detected faulty MSR 0x{:x} while setting MSRs",
                    state.msrs[faulty_msr_index].index
                );

                // Skip the first bad MSR
                let start_pos = faulty_msr_index + 1;

                let sub_msr_entries = &state.msrs[start_pos..];

                let num_msrs = self.set_msrs(sub_msr_entries)?;

                if num_msrs == sub_msr_entries.len() {
                    break;
                }

                faulty_msr_index = start_pos + num_msrs;
            }
        }

        self.set_vcpu_events(&state.vcpu_events)?;

        Ok(())
    }

    ///
    /// Restore the previously saved AArch64 CPU state
    ///
    #[cfg(target_arch = "aarch64")]
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        let state: VcpuKvmState = state.clone().into();
        // Set core registers
        self.set_regs(&state.core_regs.into())?;
        // Set system registers
        for reg in &state.sys_regs {
            self.fd
                .set_one_reg(reg.id, &reg.addr.to_le_bytes())
                .map_err(|e| cpu::HypervisorCpuError::SetSysRegister(e.into()))?;
        }

        self.set_mp_state(state.mp_state.into())?;

        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    ///
    /// Restore the previously saved RISC-V 64-bit CPU state
    ///
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        let state: VcpuKvmState = state.clone().into();
        // Set core registers
        self.set_regs(&state.core_regs.into())?;
        // Set system registers
        for reg in &state.non_core_regs {
            self.fd
                .set_one_reg(reg.id, &reg.addr.to_le_bytes())
                .map_err(|e| cpu::HypervisorCpuError::SetSysRegister(e.into()))?;
        }

        self.set_mp_state(state.mp_state.into())?;

        Ok(())
    }

    ///
    /// Initialize TDX for this CPU
    ///
    #[cfg(feature = "tdx")]
    fn tdx_init(&self, hob_address: u64) -> cpu::Result<()> {
        // On 32-bit, the next cast would clobber the high 32 bits.
        #[cfg(not(target_pointer_width = "64"))]
        compile_error!("32-bit TDX not supported");
        let hob_address = hob_address as *const _;

        tdx_command(&self.fd.as_raw_fd(), TdxCommand::InitVcpu, 0, hob_address)
            .map_err(cpu::HypervisorCpuError::InitializeTdx)
    }

    #[cfg(feature = "tdx")]
    unsafe fn tdx_init_memory_region(
        &self,
        host_address: *mut u8,
        guest_address: u64,
        size: usize,
        measure: bool,
    ) -> cpu::Result<()> {
        if self.tdx_legacy_cpuid {
            #[repr(C)]
            struct KvmMemoryMapping {
                base_gfn: u64,
                nr_pages: u64,
                flags: u64,
                source: u64,
            }

            let mut mapping = KvmMemoryMapping {
                base_gfn: guest_address >> 12,
                nr_pages: (size / 4096).try_into().unwrap(),
                flags: 0,
                source: host_address as u64,
            };

            loop {
                // SAFETY: KVM reads the mapping descriptor and pins pages from source.
                let ret = unsafe {
                    libc::ioctl(
                        self.fd.as_raw_fd(),
                        KVM_MEMORY_MAPPING_RAW,
                        &mut mapping as *mut KvmMemoryMapping,
                    )
                };
                if ret == 0 {
                    break;
                }

                let err = std::io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
                    continue;
                }

                return Err(cpu::HypervisorCpuError::InitializeTdx(err));
            }

            if measure {
                let extend = KvmMemoryMapping {
                    base_gfn: guest_address >> 12,
                    nr_pages: (size / 4096).try_into().unwrap(),
                    flags: 0,
                    source: 0,
                };

                tdx_command(
                    &self.vm_fd.as_raw_fd(),
                    TdxCommand::InitMemRegion,
                    0,
                    &extend as *const _ as *const _,
                )
                .map_err(cpu::HypervisorCpuError::InitializeTdx)?;
            }

            return Ok(());
        }

        #[repr(C)]
        struct TdxInitMemRegion {
            host_address: u64,
            guest_address: u64,
            pages: u64,
        }
        let data = TdxInitMemRegion {
            host_address: host_address as _,
            guest_address,
            pages: (size / 4096).try_into().unwrap(),
        };

        tdx_command(
            &self.fd.as_raw_fd(),
            TdxCommand::InitMemRegion,
            u32::from(measure),
            &data as *const _ as *const _,
        )
        .map_err(cpu::HypervisorCpuError::InitializeTdx)
    }

    ///
    /// Set the "immediate_exit" state
    ///
    fn set_immediate_exit(&mut self, exit: bool) {
        self.fd.set_kvm_immediate_exit(exit.into());
    }

    ///
    /// Returns the details about TDX exit reason
    ///
    #[cfg(feature = "tdx")]
    fn get_tdx_exit_details(&mut self) -> cpu::Result<TdxExitDetails> {
        let kvm_run = self.fd.get_kvm_run();
        // SAFETY: accessing a union field in a valid structure
        let tdx_vmcall = unsafe {
            &mut (*((&mut kvm_run.__bindgen_anon_1) as *mut kvm_run__bindgen_ty_1
                as *mut KvmTdxExit))
                .u
                .vmcall
        };

        tdx_vmcall.status_code = TDG_VP_VMCALL_INVALID_OPERAND;

        if tdx_vmcall.type_ != 0 {
            return Err(cpu::HypervisorCpuError::UnknownTdxVmCall);
        }

        match tdx_vmcall.subfunction {
            TDG_VP_VMCALL_MAP_GPA => {
                if !self.tdx_legacy_cpuid {
                    return Err(cpu::HypervisorCpuError::UnknownTdxVmCall);
                }
                debug!(
                    "TDX VMCALL MAP_GPA: r12={:#x} r13={:#x} r14={:#x} r15={:#x} rbx={:#x} rdx={:#x}",
                    tdx_vmcall.in_r12,
                    tdx_vmcall.in_r13,
                    tdx_vmcall.in_r14,
                    tdx_vmcall.in_r15,
                    tdx_vmcall.in_rbx,
                    tdx_vmcall.in_rdx,
                );
                Ok(TdxExitDetails::MapGpa)
            }
            TDG_VP_VMCALL_GET_QUOTE => Ok(TdxExitDetails::GetQuote {
                gpa: tdx_vmcall.in_r12,
                size: tdx_vmcall.in_r13,
            }),
            TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT => {
                Ok(TdxExitDetails::SetupEventNotifyInterrupt {
                    vector: tdx_vmcall.in_r12,
                })
            }
            _ => Err(cpu::HypervisorCpuError::UnknownTdxVmCall),
        }
    }

    ///
    /// Set the status code for TDX exit
    ///
    #[cfg(feature = "tdx")]
    fn handle_tdx_map_gpa(&mut self, shared_gpa_mask: u64) -> cpu::Result<TdxExitStatus> {
        let kvm_run = self.fd.get_kvm_run();
        // SAFETY: accessing a union field in a valid structure
        let tdx_vmcall = unsafe {
            &mut (*((&mut kvm_run.__bindgen_anon_1) as *mut kvm_run__bindgen_ty_1
                as *mut KvmTdxExit))
                .u
                .vmcall
        };

        if tdx_vmcall.type_ != 0 || tdx_vmcall.subfunction != TDG_VP_VMCALL_MAP_GPA {
            return Err(cpu::HypervisorCpuError::UnknownTdxVmCall);
        }

        let raw_address = tdx_vmcall.in_r12;
        let size = tdx_vmcall.in_r13;
        let private = raw_address & shared_gpa_mask == 0;
        let address = raw_address & !shared_gpa_mask;

        debug!(
            "TDX MAP_GPA: raw_address={raw_address:#x}, address={address:#x}, size={size:#x}, private={private}"
        );

        if size == 0 {
            return Ok(TdxExitStatus::Success);
        }

        if address & 0xfff != 0 || size & 0xfff != 0 {
            return Ok(TdxExitStatus::AlignError);
        }

        let host_addr_bits = unsafe { std::arch::x86_64::__cpuid(0x8000_0008).eax };
        let host_phys_bits = host_addr_bits & 0xff;
        let phys_limit = 1u64.checked_shl(host_phys_bits).unwrap_or(0);
        if phys_limit != 0
            && (address >= phys_limit
                || address
                    .checked_add(size)
                    .is_none_or(|end| end >= phys_limit))
        {
            return Ok(TdxExitStatus::InvalidOperand);
        }

        if self.tdx_legacy_cpuid && !private {
            for (flush_start, flush_size) in self.take_all_tdx_pending_shared_ranges() {
                self.convert_guest_memory_region(flush_start, flush_size, false)?;
            }
        }

        let convert_size = std::cmp::min(size, TDX_MAP_GPA_MAX_LEN);

        // Linux TDX guests issue TDG.VP.VMCALL<MapGPA> with:
        //   r12 = start GPA (shared bit encoded in the GPA for private->shared)
        //   r13 = range length in bytes
        // The host must update KVM memory attributes and punch holes in guest_memfd
        // for shared ranges so the mapping actually becomes visible to the VMM.
        self.convert_guest_memory_region(address, convert_size, private)?;

        if convert_size < size {
            let mut next_address = address + convert_size;
            if !private {
                next_address |= shared_gpa_mask;
            }
            Ok(TdxExitStatus::Retry(next_address))
        } else {
            Ok(TdxExitStatus::Success)
        }
    }

    #[cfg(feature = "tdx")]
    fn set_tdx_status(&mut self, status: TdxExitStatus) {
        let kvm_run = self.fd.get_kvm_run();
        // SAFETY: accessing a union field in a valid structure
        let tdx_vmcall = unsafe {
            &mut (*((&mut kvm_run.__bindgen_anon_1) as *mut kvm_run__bindgen_ty_1
                as *mut KvmTdxExit))
                .u
                .vmcall
        };

        tdx_vmcall.status_code = match status {
            TdxExitStatus::Success => TDG_VP_VMCALL_SUCCESS,
            TdxExitStatus::InvalidOperand => TDG_VP_VMCALL_INVALID_OPERAND,
            TdxExitStatus::AlignError => TDG_VP_VMCALL_ALIGN_ERROR,
            TdxExitStatus::Retry(next_address) => {
                tdx_vmcall.out_r11 = next_address;
                TDG_VP_VMCALL_RETRY
            }
        };
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Return the list of initial MSR entries for a VCPU
    ///
    fn boot_msr_entries(&self) -> &'static [MsrEntry] {
        use crate::arch::x86::{MTRR_ENABLE, MTRR_MEM_TYPE_WB, msr_index};

        &[
            msr!(msr_index::MSR_IA32_SYSENTER_CS),
            msr!(msr_index::MSR_IA32_SYSENTER_ESP),
            msr!(msr_index::MSR_IA32_SYSENTER_EIP),
            msr!(msr_index::MSR_STAR),
            msr!(msr_index::MSR_CSTAR),
            msr!(msr_index::MSR_LSTAR),
            msr!(msr_index::MSR_KERNEL_GS_BASE),
            msr!(msr_index::MSR_SYSCALL_MASK),
            msr!(msr_index::MSR_IA32_TSC),
            msr_data!(
                msr_index::MSR_IA32_MISC_ENABLE,
                msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64
            ),
            msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
        ]
    }

    #[cfg(target_arch = "aarch64")]
    fn has_pmu_support(&self) -> bool {
        let cpu_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: u64::from(kvm_bindings::KVM_ARM_VCPU_PMU_V3_INIT),
            addr: 0x0,
            flags: 0,
        };
        self.fd.has_device_attr(&cpu_attr).is_ok()
    }

    #[cfg(target_arch = "aarch64")]
    fn init_pmu(&self, irq: u32) -> cpu::Result<()> {
        let cpu_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: u64::from(kvm_bindings::KVM_ARM_VCPU_PMU_V3_INIT),
            addr: 0x0,
            flags: 0,
        };
        let cpu_attr_irq = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: u64::from(kvm_bindings::KVM_ARM_VCPU_PMU_V3_IRQ),
            addr: &irq as *const u32 as u64,
            flags: 0,
        };
        self.fd
            .set_device_attr(&cpu_attr_irq)
            .map_err(|_| cpu::HypervisorCpuError::InitializePmu)?;
        self.fd
            .set_device_attr(&cpu_attr)
            .map_err(|_| cpu::HypervisorCpuError::InitializePmu)
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Get the frequency of the TSC if available
    ///
    fn tsc_khz(&self) -> cpu::Result<Option<u32>> {
        match self.fd.get_tsc_khz() {
            Err(e) => {
                if e.errno() == libc::EIO {
                    Ok(None)
                } else {
                    Err(cpu::HypervisorCpuError::GetTscKhz(e.into()))
                }
            }
            Ok(v) => Ok(Some(v)),
        }
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the frequency of the TSC if available
    ///
    fn set_tsc_khz(&self, freq: u32) -> cpu::Result<()> {
        match self.fd.set_tsc_khz(freq) {
            Err(e) => {
                if e.errno() == libc::EIO {
                    Ok(())
                } else {
                    Err(cpu::HypervisorCpuError::SetTscKhz(e.into()))
                }
            }
            Ok(_) => Ok(()),
        }
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Trigger NMI interrupt
    ///
    fn nmi(&self) -> cpu::Result<()> {
        match self.fd.nmi() {
            Err(e) => {
                if e.errno() == libc::EIO {
                    Ok(())
                } else {
                    Err(cpu::HypervisorCpuError::Nmi(e.into()))
                }
            }
            Ok(_) => Ok(()),
        }
    }

    #[cfg(feature = "sev_snp")]
    fn set_sev_control_register(&self, _vmsa_pfn: u64) -> cpu::Result<()> {
        Ok(())
    }

    #[cfg(feature = "sev_snp")]
    fn setup_sev_snp_regs(&self, vmsa: igvm::snp_defs::SevVmsa) -> cpu::Result<()> {
        let mut sregs = self
            .fd
            .get_sregs()
            .map_err(|e: kvm_ioctls::Error| cpu::HypervisorCpuError::GetSpecialRegs(e.into()))?;
        sregs.cs = make_segment(vmsa.cs);
        sregs.ds = make_segment(vmsa.ds);
        sregs.es = make_segment(vmsa.es);
        sregs.fs = make_segment(vmsa.fs);
        sregs.gs = make_segment(vmsa.gs);
        sregs.ss = make_segment(vmsa.ss);
        sregs.tr = make_segment(vmsa.tr);
        sregs.ldt = make_segment(vmsa.ldtr);

        sregs.cr0 = vmsa.cr0;
        sregs.cr4 = vmsa.cr4;
        sregs.cr3 = vmsa.cr3;
        sregs.efer = vmsa.efer;

        sregs.idt.base = vmsa.idtr.base;
        sregs.idt.limit = vmsa
            .idtr
            .limit
            .try_into()
            .map_err(|e: std::num::TryFromIntError| {
                cpu::HypervisorCpuError::SetSpecialRegs(anyhow!(e))
            })?;
        sregs.gdt.base = vmsa.gdtr.base;
        sregs.gdt.limit = vmsa
            .gdtr
            .limit
            .try_into()
            .map_err(|e: std::num::TryFromIntError| {
                cpu::HypervisorCpuError::SetSpecialRegs(anyhow!(e))
            })?;
        self.fd
            .set_sregs(&sregs)
            .map_err(|e: kvm_ioctls::Error| cpu::HypervisorCpuError::SetSpecialRegs(e.into()))?;

        let mut regs = self
            .fd
            .get_regs()
            .map_err(|e: kvm_ioctls::Error| cpu::HypervisorCpuError::GetRegister(e.into()))?;
        regs.rip = vmsa.rip;
        regs.rdx = vmsa.rdx;
        regs.rflags = vmsa.rflags;
        regs.rsp = vmsa.rsp;
        regs.rax = vmsa.rax;
        regs.rbx = vmsa.rbx;
        regs.rcx = vmsa.rcx;
        regs.rbp = vmsa.rbp;
        regs.rsi = vmsa.rsi;
        regs.rdi = vmsa.rdi;
        regs.r8 = vmsa.r8;
        regs.r9 = vmsa.r9;
        regs.r10 = vmsa.r10;
        regs.r11 = vmsa.r11;
        regs.r12 = vmsa.r12;
        regs.r13 = vmsa.r13;
        regs.r14 = vmsa.r14;
        regs.r15 = vmsa.r15;

        self.fd
            .set_regs(&regs)
            .map_err(|e: kvm_ioctls::Error| cpu::HypervisorCpuError::SetRegister(e.into()))?;

        Ok(())
    }
}

impl KvmVcpu {
    /// TDX-only: fan out a guest page state change to the VMM listener
    /// registry through `VmOps`. Best-effort: if `vm_ops` is absent
    /// the call is a no-op (mirrors the rest of `KvmVcpu` which
    /// gracefully handles a missing `vm_ops`).
    #[cfg(feature = "tdx")]
    fn notify_memory_state_change(&self, address: u64, size: u64, private: bool) {
        if let Some(vm_ops) = &self.vm_ops {
            vm_ops.notify_memory_state_change(address, size, private);
        }
    }

    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    pub fn convert_guest_memory_region(
        &self,
        address: u64,
        size: u64,
        private: bool,
    ) -> cpu::Result<()> {
        let attributes = if private {
            KVM_MEMORY_ATTRIBUTE_PRIVATE as u64
        } else {
            0u64
        };

        let end = address.checked_add(size).ok_or_else(|| {
            cpu::HypervisorCpuError::RunVcpu(anyhow!("guest memory conversion range overflow"))
        })?;

        // TDX-only: drop IOMMU mappings before the host backing for the
        // range disappears.
        #[cfg(feature = "tdx")]
        if private {
            self.notify_memory_state_change(address, size, true);
        }

        let Some(guest_mem_slots) = &self.guest_mem_slots else {
            self.vm_fd
                .set_memory_attributes(kvm_memory_attributes {
                    address,
                    size,
                    attributes,
                    flags: 0,
                })
                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

            // TDX-only: pages just became shared; let listeners
            // populate IOMMU mappings before we punch the private
            // backing.
            #[cfg(feature = "tdx")]
            if !private {
                self.notify_memory_state_change(address, size, false);
            }

            if !private {
                self.punch_hole_guest_memfd(address, size)?;
            } else {
                self.discard_userspace_memory(address, size)?;
            }
            return Ok(());
        };

        let mut slots: Vec<KvmGuestMemSlot> = guest_mem_slots
            .read()
            .unwrap()
            .values()
            .copied()
            .filter(|slot| {
                slot.guest_phys_addr < end
                    && slot
                        .guest_phys_addr
                        .checked_add(slot.memory_size)
                        .is_some_and(|slot_end| slot_end > address)
            })
            .collect();
        slots.sort_by_key(|slot| slot.guest_phys_addr);

        if !private {
            self.vm_fd
                .set_memory_attributes(kvm_memory_attributes {
                    address,
                    size,
                    attributes,
                    flags: 0,
                })
                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

            // TDX-only: full range is now shared in KVM; notify
            // listeners so they can DMA-map the host VA before we
            // start punching the per-slot private backing.
            #[cfg(feature = "tdx")]
            self.notify_memory_state_change(address, size, false);
        }

        if slots.is_empty() {
            if private {
                return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "attempted to convert non-guest-memfd range to private: address={address:#x}, size={size:#x}"
                )));
            }

            debug!(
                "Converted non-guest-memfd range to shared: address={address:#x}, size={size:#x}"
            );
            return Ok(());
        }

        let mut covered_until = address;
        for slot in slots {
            let slot_end = slot
                .guest_phys_addr
                .checked_add(slot.memory_size)
                .ok_or_else(|| {
                    cpu::HypervisorCpuError::RunVcpu(anyhow!("guest_memfd slot overflow"))
                })?;
            let range_start = std::cmp::max(address, slot.guest_phys_addr);
            let range_end = std::cmp::min(end, slot_end);
            if range_start >= range_end {
                continue;
            }

            if private && range_start > covered_until {
                return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "attempted to convert non-guest-memfd hole to private: address={address:#x}, size={size:#x}, hole_start={covered_until:#x}, hole_end={range_start:#x}"
                )));
            }

            if private {
                self.vm_fd
                    .set_memory_attributes(kvm_memory_attributes {
                        address: range_start,
                        size: range_end - range_start,
                        attributes,
                        flags: 0,
                    })
                    .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
            }

            if !private {
                self.punch_hole_guest_memfd(range_start, range_end - range_start)?;
            } else {
                self.discard_userspace_memory(range_start, range_end - range_start)?;
            }

            covered_until = covered_until.max(range_end);
        }

        if private && covered_until < end {
            return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                "attempted to convert trailing non-guest-memfd hole to private: address={address:#x}, size={size:#x}, covered_until={covered_until:#x}"
            )));
        }

        Ok(())
    }

    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    fn discard_userspace_memory(&self, address: u64, size: u64) -> cpu::Result<()> {
        let Some(guest_mem_slots) = &self.guest_mem_slots else {
            return Ok(());
        };

        let end = address.checked_add(size).ok_or_else(|| {
            cpu::HypervisorCpuError::RunVcpu(anyhow!("userspace memory discard range overflow"))
        })?;

        let slots: Vec<KvmGuestMemSlot> =
            guest_mem_slots.read().unwrap().values().copied().collect();

        for slot in slots {
            let slot_start = slot.guest_phys_addr;
            let slot_end = slot
                .guest_phys_addr
                .checked_add(slot.memory_size)
                .ok_or_else(|| {
                    cpu::HypervisorCpuError::RunVcpu(anyhow!("guest memory slot overflow"))
                })?;

            let discard_start = std::cmp::max(address, slot_start);
            let discard_end = std::cmp::min(end, slot_end);
            if discard_start >= discard_end {
                continue;
            }

            let host_addr = slot
                .userspace_addr
                .checked_add(discard_start - slot_start)
                .ok_or_else(|| {
                    cpu::HypervisorCpuError::RunVcpu(anyhow!("userspace address overflow"))
                })?;
            let length = discard_end - discard_start;

            // P4.5: punch a hole in the shared backend so the
            // file-backed (memfd / hugetlbfs) blocks are actually
            // released, mirroring QEMU's `ram_block_discard_range`.
            // MADV_REMOVE is equivalent to fallocate(PUNCH_HOLE) on
            // the underlying file. For anonymous backings the kernel
            // returns EINVAL; fall back to MADV_DONTNEED in that
            // case so anon-shared CH guests keep working.
            let ret = unsafe {
                libc::madvise(
                    host_addr as *mut libc::c_void,
                    length as libc::size_t,
                    libc::MADV_REMOVE,
                )
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                let raw = err.raw_os_error().unwrap_or(0);
                if raw == libc::EINVAL || raw == libc::ENOSYS || raw == libc::EOPNOTSUPP {
                    let ret2 = unsafe {
                        libc::madvise(
                            host_addr as *mut libc::c_void,
                            length as libc::size_t,
                            libc::MADV_DONTNEED,
                        )
                    };
                    if ret2 != 0 {
                        return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                            "userspace memory discard failed (MADV_DONTNEED fallback): {}",
                            std::io::Error::last_os_error()
                        )));
                    }
                } else {
                    return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                        "userspace memory discard failed (MADV_REMOVE): {err}"
                    )));
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "tdx")]
    fn take_all_tdx_pending_shared_ranges(&self) -> Vec<(u64, u64)> {
        const MAP_GPA_PAGE_SIZE: u64 = 4096;
        const MAP_GPA_PAGES_PER_BATCH: usize = 512;

        let mut ranges = self.tdx_pending_shared_2m_ranges.lock().unwrap();
        let pending: Vec<(u64, [u64; 8])> = ranges.drain().collect();
        let mut flush_ranges = Vec::new();

        for (range_start, bitmap) in pending {
            let is_set =
                |index: usize| -> bool { bitmap[index / 64] & (1u64 << (index % 64)) != 0 };

            let mut page = 0;
            while page < MAP_GPA_PAGES_PER_BATCH {
                if !is_set(page) {
                    page += 1;
                    continue;
                }

                let first_page = page;
                page += 1;
                while page < MAP_GPA_PAGES_PER_BATCH && is_set(page) {
                    page += 1;
                }

                flush_ranges.push((
                    range_start + first_page as u64 * MAP_GPA_PAGE_SIZE,
                    (page - first_page) as u64 * MAP_GPA_PAGE_SIZE,
                ));
            }
        }

        flush_ranges.sort_by_key(|(start, _)| *start);
        flush_ranges
    }

    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    fn punch_hole_guest_memfd(&self, address: u64, size: u64) -> cpu::Result<()> {
        let Some(guest_memfds) = &self.guest_memfds else {
            return Ok(());
        };
        let Some(guest_mem_slots) = &self.guest_mem_slots else {
            return Ok(());
        };

        let end = address.checked_add(size).ok_or_else(|| {
            cpu::HypervisorCpuError::RunVcpu(anyhow!("guest_memfd range overflow"))
        })?;

        let slots: Vec<KvmGuestMemSlot> =
            guest_mem_slots.read().unwrap().values().copied().collect();
        let memfds = guest_memfds.read().unwrap();

        for slot in slots {
            let slot_start = slot.guest_phys_addr;
            let slot_end = slot
                .guest_phys_addr
                .checked_add(slot.memory_size)
                .ok_or_else(|| {
                    cpu::HypervisorCpuError::RunVcpu(anyhow!("guest_memfd slot overflow"))
                })?;

            let punch_start = std::cmp::max(address, slot_start);
            let punch_end = std::cmp::min(end, slot_end);
            if punch_start >= punch_end {
                continue;
            }

            let fd = memfds.get(&slot.slot).ok_or_else(|| {
                cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "missing guest_memfd for slot {}",
                    slot.slot
                ))
            })?;

            let offset = slot.guest_memfd_offset + (punch_start - slot_start);
            let length = punch_end - punch_start;
            let ret = unsafe {
                libc::fallocate64(
                    fd.as_raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    offset as libc::off64_t,
                    length as libc::off64_t,
                )
            };
            if ret != 0 {
                return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "guest_memfd punch hole failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        Ok(())
    }

    #[cfg(any(feature = "sev_snp", feature = "tdx"))]
    fn allocate_guest_memfd(&self, address: u64, size: u64) -> cpu::Result<()> {
        warn!("allocate_guest_memfd: address={address:#x}, size={size:#x}");
        let Some(guest_memfds) = &self.guest_memfds else {
            warn!("allocate_guest_memfd: guest_memfds is None");
            return Ok(());
        };
        let Some(guest_mem_slots) = &self.guest_mem_slots else {
            warn!("allocate_guest_memfd: guest_mem_slots is None");
            return Ok(());
        };

        let end = address.checked_add(size).ok_or_else(|| {
            cpu::HypervisorCpuError::RunVcpu(anyhow!("guest_memfd range overflow"))
        })?;

        let slots: Vec<KvmGuestMemSlot> =
            guest_mem_slots.read().unwrap().values().copied().collect();
        let memfds = guest_memfds.read().unwrap();

        for slot in slots {
            let slot_start = slot.guest_phys_addr;
            let slot_end = slot
                .guest_phys_addr
                .checked_add(slot.memory_size)
                .ok_or_else(|| {
                    cpu::HypervisorCpuError::RunVcpu(anyhow!("guest_memfd slot overflow"))
                })?;

            let alloc_start = std::cmp::max(address, slot_start);
            let alloc_end = std::cmp::min(end, slot_end);
            if alloc_start >= alloc_end {
                continue;
            }

            let fd = memfds.get(&slot.slot).ok_or_else(|| {
                cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "missing guest_memfd for slot {}",
                    slot.slot
                ))
            })?;

            let offset = slot.guest_memfd_offset + (alloc_start - slot_start);
            let length = alloc_end - alloc_start;
            let ret = unsafe {
                libc::fallocate64(
                    fd.as_raw_fd(),
                    0,
                    offset as libc::off64_t,
                    length as libc::off64_t,
                )
            };

            if ret != 0 {
                return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "guest_memfd allocate failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xsave struct".
    ///
    fn get_xsave(&self) -> cpu::Result<XsaveState> {
        Ok(self
            .fd
            .get_xsave()
            .map_err(|e| cpu::HypervisorCpuError::GetXsaveState(e.into()))?
            .into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xsave struct".
    ///
    fn set_xsave(&self, xsave: &XsaveState) -> cpu::Result<()> {
        let xsave: kvm_bindings::kvm_xsave = (*xsave)
            .clone()
            .try_into()
            .map_err(|e: XsaveStateError| cpu::HypervisorCpuError::GetXsaveState(e.into()))?;
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_xsave struct
        // when calling the kvm-ioctl library function.
        unsafe {
            self.fd
                .set_xsave(&xsave)
                .map_err(|e| cpu::HypervisorCpuError::SetXsaveState(e.into()))
        }
    }

    #[cfg(target_arch = "x86_64")]
    /// X86 specific call that returns the vcpu's current "xsave struct" using the extended
    /// xsave2 interface which supports larger state buffers (>4KB) for features like Intel AMX.
    ///
    /// This method requires KVM_CAP_XSAVE2 capability and uses KVM_GET_XSAVE2 ioctl.
    /// The xsave parameter must be allocated with sufficient size based on the value
    /// returned by KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2).
    pub fn get_xsave2(&self) -> cpu::Result<XsaveState> {
        assert!(
            self.xsave_size > 0,
            "'xsave_size' must be initialized via 'KVM_CAP_XSAVE2' first"
        );
        let fam_size = (self.xsave_size as usize - size_of::<kvm_bindings::kvm_xsave>())
            .div_ceil(size_of::<<kvm_xsave2 as FamStruct>::Entry>());
        let mut xsave =
            xsave2::new(fam_size).map_err(|e| cpu::HypervisorCpuError::GetXsaveState(e.into()))?;
        // SAFETY: The caller guarantees that xsave is allocated with enough space
        unsafe {
            self.fd
                .get_xsave2(&mut xsave)
                .map_err(|e| cpu::HypervisorCpuError::GetXsaveState(e.into()))?;
        }
        Ok((&xsave).into())
    }

    #[cfg(target_arch = "x86_64")]
    /// X86 specific call that sets the vcpu's current "xsave struct" using the extended
    /// xsave2 interface which supports larger state buffers (>4KB) for features like Intel AMX.
    ///
    /// This method uses KVM_SET_XSAVE ioctl but with extended buffer support when
    /// KVM_CAP_XSAVE2 is available.
    pub fn set_xsave2(&self, xsave_state: &XsaveState) -> cpu::Result<()> {
        assert!(
            self.xsave_size > 0,
            "'xsave_size' must be initialized via 'KVM_CAP_XSAVE2' first"
        );
        let xsave = xsave_state
            .to_xsave2()
            .map_err(|e| cpu::HypervisorCpuError::SetXsaveState(e.into()))?;
        // SAFETY: The caller guarantees that xsave contains valid data
        unsafe {
            self.fd
                .set_xsave2(&xsave)
                .map_err(|e| cpu::HypervisorCpuError::SetXsaveState(e.into()))
        }
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    fn get_xcrs(&self) -> cpu::Result<ExtendedControlRegisters> {
        self.fd
            .get_xcrs()
            .map_err(|e| cpu::HypervisorCpuError::GetXcsr(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xcrs".
    ///
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> cpu::Result<()> {
        self.fd
            .set_xcrs(xcrs)
            .map_err(|e| cpu::HypervisorCpuError::SetXcsr(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    fn get_vcpu_events(&self) -> cpu::Result<VcpuEvents> {
        self.fd
            .get_vcpu_events()
            .map_err(|e| cpu::HypervisorCpuError::GetVcpuEvents(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets pending exceptions, interrupts, and NMIs as well as related states
    /// of the vcpu.
    ///
    fn set_vcpu_events(&self, events: &VcpuEvents) -> cpu::Result<()> {
        self.fd
            .set_vcpu_events(events)
            .map_err(|e| cpu::HypervisorCpuError::SetVcpuEvents(e.into()))
    }

    /// Get the state of the nested guest from the current vCPU,
    /// if there is any.
    #[cfg(target_arch = "x86_64")]
    fn nested_state(&self) -> cpu::Result<Option<KvmNestedStateBuffer>> {
        let mut buffer = KvmNestedStateBuffer::empty();

        let maybe_size = self
            .fd
            .nested_state(&mut buffer)
            .map_err(|e| cpu::HypervisorCpuError::GetNestedState(e.into()))?;

        if let Some(_size) = maybe_size {
            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// Sets the state of the nested guest for the current vCPU.
    #[cfg(target_arch = "x86_64")]
    fn set_nested_state(&self, state: &KvmNestedStateBuffer) -> cpu::Result<()> {
        self.fd
            .set_nested_state(state)
            .map_err(|e| cpu::HypervisorCpuError::GetNestedState(e.into()))
    }
}

#[cfg(test)]
mod unit_tests {
    #[test]
    #[cfg(target_arch = "riscv64")]
    fn test_get_and_set_regs() {
        use super::*;

        let kvm = KvmHypervisor::new().unwrap();
        let hypervisor = Arc::new(kvm);
        let vm = hypervisor
            .create_vm(HypervisorVmConfig::default())
            .expect("new VM fd creation failed");
        let vcpu0 = vm.create_vcpu(0, None).unwrap();

        let core_regs = StandardRegisters::from(kvm_riscv_core {
            regs: kvm_bindings::user_regs_struct {
                pc: 0x00,
                ra: 0x01,
                sp: 0x02,
                gp: 0x03,
                tp: 0x04,
                t0: 0x05,
                t1: 0x06,
                t2: 0x07,
                s0: 0x08,
                s1: 0x09,
                a0: 0x0a,
                a1: 0x0b,
                a2: 0x0c,
                a3: 0x0d,
                a4: 0x0e,
                a5: 0x0f,
                a6: 0x10,
                a7: 0x11,
                s2: 0x12,
                s3: 0x13,
                s4: 0x14,
                s5: 0x15,
                s6: 0x16,
                s7: 0x17,
                s8: 0x18,
                s9: 0x19,
                s10: 0x1a,
                s11: 0x1b,
                t3: 0x1c,
                t4: 0x1d,
                t5: 0x1e,
                t6: 0x1f,
            },
            mode: 0x00,
        });

        vcpu0.set_regs(&core_regs).unwrap();
        assert_eq!(vcpu0.get_regs().unwrap(), core_regs);
    }
}
