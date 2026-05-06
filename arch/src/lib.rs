// Copyright © 2024 Institute of Software, CAS. All rights reserved.
// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements platform specific functionality.
//! Supported platforms: x86_64, aarch64, riscv64.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::{fmt, result};

use serde::{Deserialize, Serialize};
use thiserror::Error;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<vm_memory::bitmap::AtomicBitmap>;
type GuestRegionMmap = vm_memory::GuestRegionMmap<vm_memory::bitmap::AtomicBitmap>;

/// Type for returning error code.
#[derive(Debug, Error)]
pub enum Error {
    #[cfg(target_arch = "x86_64")]
    #[error("Platform specific error (x86_64)")]
    PlatformSpecific(#[from] x86_64::Error),
    #[cfg(target_arch = "aarch64")]
    #[error("Platform specific error (aarch64)")]
    PlatformSpecific(#[from] aarch64::Error),
    #[cfg(target_arch = "riscv64")]
    #[error("Platform specific error (riscv64)")]
    PlatformSpecific(#[from] riscv64::Error),
    #[error("The memory map table extends past the end of guest memory")]
    MemmapTablePastRamEnd,
    #[error("Error writing memory map table to guest memory")]
    MemmapTableSetup,
    #[error("The hvm_start_info structure extends past the end of guest memory")]
    StartInfoPastRamEnd,
    #[error("Error writing hvm_start_info to guest memory")]
    StartInfoSetup,
    #[error("Failed to compute initramfs address")]
    InitramfsAddress,
    #[error("Error writing module entry to guest memory")]
    ModlistSetup(#[source] vm_memory::GuestMemoryError),
    #[error("RSDP extends past the end of guest memory")]
    RsdpPastRamEnd,
    #[error("Failed to setup Zero Page for bzImage")]
    ZeroPageSetup(#[source] vm_memory::GuestMemoryError),
    #[error("Zero Page for bzImage past RAM end")]
    ZeroPagePastRamEnd,
}

/// Type for returning public functions outcome.
pub type Result<T> = result::Result<T, Error>;

/// Vendor / device IDs and chipset register offsets for the emulated
/// Q35 + ICH9 platform.
///
/// These values are properties of the *machine model* CH presents to
/// the guest, not of the PCI bus implementation, so they live in the
/// `arch` crate alongside other layout constants. Keeping them in one
/// place lets ACPI/SMBIOS code in the `vmm` crate and the PCI host
/// bridge in the `pci` crate share a single source of truth and stay
/// byte-compatible with QEMU's q35 machine type.
///
/// Exposed unconditionally (not gated on x86_64) because the emulated
/// PCI host bridge in `pci/src/bus.rs` is also unconditional and these
/// constants must be importable from there on every supported target.
pub mod q35_pci_ids {
    /// Intel vendor ID, used for the host bridge, ICH9 LPC, AHCI, SMBus,
    /// and CH's virt PCIe host stub.
    pub const VENDOR_ID_INTEL: u16 = 0x8086;
    /// CH's synthetic "virtual PCIe host" device ID. Not a real Intel
    /// part — predates the q35 work but uses an Intel vendor range.
    pub const DEVICE_ID_INTEL_VIRT_PCIE_HOST: u16 = 0x0d57;
    /// Intel P35/X38 host bridge (DRAM controller). QEMU's q35 machine
    /// uses this ID for the root complex; matching it lets stock OVMF
    /// and Linux apply the correct chipset quirks.
    pub const DEVICE_ID_INTEL_P35_MCH: u16 = 0x29c0;
    /// ICH9 LPC interface bridge — the PCI/ISA bridge on q35.
    pub const DEVICE_ID_INTEL_ICH9_LPC: u16 = 0x2918;
    /// ICH9 SATA AHCI controller. Reused as a multifunction shell on
    /// q35 even when no AHCI is exposed to the guest.
    pub const DEVICE_ID_INTEL_ICH9_AHCI: u16 = 0x2922;
    /// ICH9 SMBus controller. Required for OVMF's SMBus probe sequence.
    pub const DEVICE_ID_INTEL_ICH9_SMBUS: u16 = 0x2930;

    // Q35 host-bridge PCIEXBAR window and writable bit masks (defined
    // by the P35/X38 datasheet, mirrored by QEMU q35).
    pub const Q35_PCIEXBAR_REG: usize = 0x60 / 4;
    pub const Q35_PCIEXBAR_DEFAULT: u32 = 0xb000_0000;
    pub const Q35_PCIEXBAR_LOW_WRITABLE_BITS: u32 = 0xf000_0007;
    pub const Q35_PCIEXBAR_HIGH_WRITABLE_BITS: u32 = 0x0000_000f;

    // Standard PCI configuration space register indices used by the
    // emulated host bridge / LPC functions.
    pub const PCI_COMMAND_STATUS_REG: usize = 0x04 / 4;
    pub const PCI_HEADER_TYPE_REG: usize = 0x0c / 4;
    pub const PCI_BAR4_REG: usize = 0x20 / 4;
    pub const PCI_CAPABILITY_LIST_REG: usize = 0x34 / 4;
    pub const PCI_INTERRUPT_REG: usize = 0x3c / 4;
    pub const PCI_HEADER_TYPE_MULTIFUNCTION: u32 = 0x0080_0000;
    pub const PCI_STATUS_CAPABILITIES: u32 = 0x0010_0000;

    // ICH9 LPC chipset registers (PMBASE, ACPI control, PIRQ routing,
    // I/O decode, RCBA) used by the ACPI subsystem.
    pub const ICH9_LPC_PMBASE_REG: usize = 0x40 / 4;
    pub const ICH9_LPC_ACPI_CTRL_REG: usize = 0x44 / 4;
    pub const ICH9_LPC_PIRQA_ROUT_REG: usize = 0x60 / 4;
    pub const ICH9_LPC_PIRQE_ROUT_REG: usize = 0x68 / 4;
    pub const ICH9_LPC_IO_DEC_REG: usize = 0x80 / 4;
    pub const ICH9_LPC_RCBA_REG: usize = 0xf0 / 4;

    // ICH9 AHCI capability register indices.
    pub const ICH9_AHCI_MSI_CAP_REG: usize = 0x80 / 4;
    pub const ICH9_AHCI_SATA_CAP_REG: usize = 0xa8 / 4;
}

/// Type for memory region types.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RegionType {
    /// RAM type
    Ram,

    /// SubRegion memory region.
    /// A SubRegion is a memory region sub-region, allowing for a region
    /// to be split into sub regions managed separately.
    /// For example, the x86 32-bit memory hole is a SubRegion.
    SubRegion,

    /// Reserved type.
    /// A Reserved memory region is one that should not be used for memory
    /// allocation. This type can be used to prevent the VMM from allocating
    /// memory ranges in a specific address range.
    Reserved,
}

/// Module for aarch64 related functionality.
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    _NSIG, EntryPoint, arch_memory_regions, configure_system, configure_vcpu,
    fdt::DeviceInfoForFdt, get_host_cpu_phys_bits, initramfs_load_addr, layout,
    layout::CMDLINE_MAX_SIZE, layout::IRQ_BASE, uefi,
};

/// Module for riscv64 related functionality.
#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "riscv64")]
pub use riscv64::{
    _NSIG, EntryPoint, arch_memory_regions, configure_system, configure_vcpu,
    fdt::DeviceInfoForFdt, get_host_cpu_phys_bits, initramfs_load_addr, layout,
    layout::CMDLINE_MAX_SIZE, layout::IRQ_BASE, uefi,
};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    _NSIG, CpuidConfig, CpuidFeatureEntry, EntryPoint, arch_memory_regions, configure_system,
    configure_vcpu, generate_common_cpuid, generate_ram_ranges, get_host_cpu_phys_bits,
    initramfs_load_addr, layout, layout::CMDLINE_MAX_SIZE, layout::CMDLINE_START, regs,
    tdx_q35_arch_memory_regions,
};

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn pagesize() -> usize {
    // SAFETY: Trivially safe
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[derive(Clone, Default)]
pub struct NumaNode {
    pub memory_regions: Vec<Arc<GuestRegionMmap>>,
    pub hotplug_regions: Vec<Arc<GuestRegionMmap>>,
    pub cpus: Vec<u32>,
    pub pci_segments: Vec<u16>,
    pub distances: BTreeMap<u32, u8>,
    pub memory_zones: Vec<String>,
    pub device_id: Option<String>,
}

pub type NumaNodes = BTreeMap<u32, NumaNode>;

/// Type for passing information about the initramfs in the guest memory.
pub struct InitramfsConfig {
    /// Load address of initramfs in guest memory
    pub address: vm_memory::GuestAddress,
    /// Size of initramfs in guest memory
    pub size: usize,
}

/// Types of devices that can get attached to this platform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum DeviceType {
    /// Device Type: Virtio.
    Virtio(u32),
    /// Device Type: Serial.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    Serial,
    /// Device Type: RTC.
    #[cfg(target_arch = "aarch64")]
    Rtc,
    /// Device Type: GPIO.
    #[cfg(target_arch = "aarch64")]
    Gpio,
    /// Device Type: fw_cfg.
    #[cfg(feature = "fw_cfg")]
    FwCfg,
}

/// Default (smallest) memory page size for the supported architectures.
pub const PAGE_SIZE: usize = 4096;

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Structure to describe MMIO device information
#[derive(Clone, Debug)]
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub struct MmioDeviceInfo {
    pub addr: u64,
    pub len: u64,
    pub irq: u32,
}

/// Structure to describe PCI space information
#[derive(Clone, Debug)]
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub struct PciSpaceInfo {
    pub pci_segment_id: u16,
    pub mmio_config_address: u64,
    pub pci_device_space_start: u64,
    pub pci_device_space_size: u64,
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl DeviceInfoForFdt for MmioDeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self.irq
    }
    fn length(&self) -> u64 {
        self.len
    }
}
