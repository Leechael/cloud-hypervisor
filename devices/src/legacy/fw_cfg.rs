// Copyright 2025 Google LLC.
//
// SPDX-License-Identifier: Apache-2.0
//

/// Cloud Hypervisor implementation of Qemu's fw_cfg spec
/// https://www.qemu.org/docs/master/specs/fw_cfg.html
/// Linux kernel fw_cfg driver header
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h
/// Uploading files to the guest via fw_cfg is supported for all kernels 4.6+ w/ CONFIG_FW_CFG_SYSFS enabled
/// https://cateee.net/lkddb/web-lkddb/FW_CFG_SYSFS.html
/// No kernel requirement if above functionality is not required,
/// only firmware must implement mechanism to interact with this fw_cfg device
use std::{
    collections::BTreeMap,
    fs::File,
    io::{ErrorKind, Read, Result, Seek, SeekFrom},
    mem::offset_of,
    os::unix::fs::FileExt,
    path::PathBuf,
    sync::{Arc, Barrier},
};

#[cfg(target_arch = "aarch64")]
use arch::RegionType;
#[cfg(target_arch = "aarch64")]
use arch::aarch64::layout::{
    MEM_32BIT_DEVICES_START, MEM_32BIT_RESERVED_START, RAM_64BIT_START, RAM_START as HIGH_RAM_START,
};
#[cfg(target_arch = "x86_64")]
use arch::layout::{MEM_32BIT_DEVICES_START, RAM_64BIT_START};
use bitfield_struct::bitfield;
#[cfg(target_arch = "x86_64")]
use linux_loader::bootparam::boot_params;
#[cfg(target_arch = "aarch64")]
use linux_loader::loader::pe::arm64_image_header as boot_params;
use log::{debug, error, info};
use vm_device::BusDevice;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap,
};
use vmm_sys_util::sock_ctrl_msg::IntoIovec;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;
#[cfg(target_arch = "x86_64")]
const KVM_IDENTITY_MAP_START: GuestAddress = GuestAddress(0xfeff_c000);
#[cfg(target_arch = "x86_64")]
const KVM_IDENTITY_MAP_SIZE: usize = 0x4000;

#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_SELECTOR: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DATA: u64 = 0x511;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DMA_HI: u64 = 0x514;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DMA_LO: u64 = 0x518;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_BASE: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0xc;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_SELECTOR: u64 = 0x9030008;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DATA: u64 = 0x9030000;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DMA_HI: u64 = 0x9030010;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DMA_LO: u64 = 0x9030014;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_BASE: u64 = 0x9030000;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0x10;

const FW_CFG_SIGNATURE: u16 = 0x00;
const FW_CFG_ID: u16 = 0x01;
const FW_CFG_UUID: u16 = 0x02;
const FW_CFG_RAM_SIZE: u16 = 0x03;
const FW_CFG_NOGRAPHIC: u16 = 0x04;
const FW_CFG_NB_CPUS: u16 = 0x05;
const FW_CFG_KERNEL_ADDR: u16 = 0x07;
const FW_CFG_KERNEL_SIZE: u16 = 0x08;
const FW_CFG_BOOT_DEVICE: u16 = 0x0c;
const FW_CFG_NUMA: u16 = 0x0d;
const FW_CFG_BOOT_MENU: u16 = 0x0e;
const FW_CFG_MAX_CPUS: u16 = 0x0f;
const FW_CFG_KERNEL_ENTRY: u16 = 0x10;
const FW_CFG_INITRD_ADDR: u16 = 0x0a;
const FW_CFG_INITRD_SIZE: u16 = 0x0b;
const FW_CFG_KERNEL_DATA: u16 = 0x11;
const FW_CFG_INITRD_DATA: u16 = 0x12;
const FW_CFG_CMDLINE_ADDR: u16 = 0x13;
const FW_CFG_CMDLINE_SIZE: u16 = 0x14;
const FW_CFG_CMDLINE_DATA: u16 = 0x15;
const FW_CFG_SETUP_ADDR: u16 = 0x16;
const FW_CFG_SETUP_SIZE: u16 = 0x17;
const FW_CFG_SETUP_DATA: u16 = 0x18;
const FW_CFG_FILE_DIR: u16 = 0x19;
const FW_CFG_KNOWN_ITEMS: usize = 0x20;
#[cfg(target_arch = "x86_64")]
const FW_CFG_ARCH_LOCAL: u16 = 0x8000;
#[cfg(target_arch = "x86_64")]
const FW_CFG_ACPI_TABLES: u16 = FW_CFG_ARCH_LOCAL;
#[cfg(target_arch = "x86_64")]
const FW_CFG_IRQ0_OVERRIDE: u16 = FW_CFG_ARCH_LOCAL + 2;
#[cfg(target_arch = "x86_64")]
const FW_CFG_HPET: u16 = FW_CFG_ARCH_LOCAL + 4;
#[cfg(target_arch = "x86_64")]
const HPET_FW_CONFIG_SIZE: usize = 1 + 8 * (4 + 8 + 2 + 1);

pub const FW_CFG_FILE_FIRST: u16 = 0x20;
pub const FW_CFG_SIGNATURE_VALUE: [u8; 4] = *b"QEMU";
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h
pub const FW_CFG_ACPI_ID: &str = "QEMU0002";
// Reserved (must be enabled)
const FW_CFG_F_RESERVED: u8 = 1 << 0;
// DMA Toggle Bit (enabled by default)
const FW_CFG_F_DMA: u8 = 1 << 1;
pub const FW_CFG_FEATURE: [u8; 4] = [FW_CFG_F_RESERVED | FW_CFG_F_DMA, 0, 0, 0];

const COMMAND_ALLOCATE: u32 = 0x1;
const COMMAND_ADD_POINTER: u32 = 0x2;
const COMMAND_ADD_CHECKSUM: u32 = 0x3;

const ALLOC_ZONE_HIGH: u8 = 0x1;
const ALLOC_ZONE_FSEG: u8 = 0x2;

const FW_CFG_FILENAME_TABLE_LOADER: &str = "etc/table-loader";
const FW_CFG_FILENAME_RSDP: &str = "etc/acpi/rsdp";
const FW_CFG_FILENAME_ACPI_TABLES: &str = "etc/acpi/tables";
#[cfg(target_arch = "x86_64")]
const Q35_ACPI_TABLE_LOADER_SIZE: usize = 0x1000;
#[cfg(target_arch = "x86_64")]
const Q35_ACPI_TABLES_SIZE: usize = 0x2_0000;
#[cfg(target_arch = "x86_64")]
const Q35_ACPI_DATA_RESERVED_SIZE: usize = Q35_ACPI_TABLES_SIZE + 0x8000;
#[cfg(target_arch = "x86_64")]
const Q35_SMBIOS_ANCHOR_SIZE: usize = 0x18;
#[cfg(target_arch = "x86_64")]
const Q35_SMBIOS_TABLES_SIZE: usize = 0x13b;

#[derive(Debug)]
pub enum FwCfgContent {
    Bytes(Vec<u8>),
    Slice(&'static [u8]),
    File(u64, File),
    U32(u32),
}

struct FwCfgContentAccess<'a> {
    content: &'a FwCfgContent,
    offset: u32,
}

impl Read for FwCfgContentAccess<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.content {
            FwCfgContent::File(offset, f) => {
                Seek::seek(&mut (&*f), SeekFrom::Start(offset + self.offset as u64))?;
                Read::read(&mut (&*f), buf)
            }
            FwCfgContent::Bytes(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::Slice(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::U32(n) => match n.to_le_bytes().get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
        }
    }
}

impl Default for FwCfgContent {
    fn default() -> Self {
        FwCfgContent::Slice(&[])
    }
}

impl FwCfgContent {
    fn size(&self) -> Result<u32> {
        let ret = match self {
            FwCfgContent::Bytes(v) => v.len(),
            FwCfgContent::File(offset, f) => (f.metadata()?.len() - offset) as usize,
            FwCfgContent::Slice(s) => s.len(),
            FwCfgContent::U32(n) => size_of_val(n),
        };
        u32::try_from(ret).map_err(|_| std::io::ErrorKind::InvalidInput.into())
    }
    fn access(&self, offset: u32) -> FwCfgContentAccess<'_> {
        FwCfgContentAccess {
            content: self,
            offset,
        }
    }
}

#[derive(Debug, Default)]
pub struct FwCfgItem {
    pub name: String,
    pub content: FwCfgContent,
}

/// https://www.qemu.org/docs/master/specs/fw_cfg.html
pub struct FwCfg {
    selector: u16,
    data_offset: u32,
    dma_address: u64,
    items: Vec<FwCfgItem>,                           // 0x20 and above
    known_items: [FwCfgContent; FW_CFG_KNOWN_ITEMS], // 0x0 to 0x19
    arch_known_items: BTreeMap<u16, FwCfgContent>,
    memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
    /// Optional hook called before fw_cfg DMA read/write.
    /// Arguments: (guest_address, length)
    pub dma_pre_hook: Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
    linuxboot_option_rom_enabled: bool,
    patch_linux_setup_header: bool,
    /// Optional list of (fw_cfg name, host path) pairs for option ROMs.
    ///
    /// Typical entries used by OVMF/SeaBIOS:
    ///   ("genroms/kvmvapic.bin",       "/usr/share/qemu/kvmvapic.bin")
    ///   ("genroms/linuxboot_dma.bin",  "/usr/share/qemu/linuxboot_dma.bin")
    ///
    /// Empty by default: callers must opt in explicitly. When the list does
    /// not contain `genroms/linuxboot_dma.bin`, no `bootorder` entry is
    /// emitted either.
    option_roms: Vec<(String, PathBuf)>,
    /// Optional SMBIOS string overrides applied to
    /// `etc/smbios/smbios-tables`. `None` keeps the historical CH default
    /// emission (Types 0/1/127 only) so existing TDX measurements stay
    /// stable.
    #[cfg(target_arch = "x86_64")]
    smbios_overrides: Option<FwCfgSmbiosOverrides>,
    /// Total guest RAM size in bytes, used to fill the SMBIOS Type 17
    /// Memory Device entry. 0 disables the size encoding fast-path; the
    /// resulting Type 17 reports the minimum 1 MB DIMM, which is harmless
    /// for tests / smoke runs that don't care about Type 17 contents.
    #[cfg(target_arch = "x86_64")]
    total_memory_size: u64,
}

impl std::fmt::Debug for FwCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FwCfg")
            .field("selector", &self.selector)
            .field("data_offset", &self.data_offset)
            .field("dma_address", &self.dma_address)
            .field("items", &self.items)
            .field("known_items", &self.known_items)
            .field("arch_known_items", &self.arch_known_items)
            .field("memory", &self.memory)
            .field("dma_pre_hook", &self.dma_pre_hook.is_some())
            .field(
                "linuxboot_option_rom_enabled",
                &self.linuxboot_option_rom_enabled,
            )
            .field("patch_linux_setup_header", &self.patch_linux_setup_header)
            .field("option_roms", &self.option_roms)
            .finish()
    }
}

#[cfg(target_arch = "x86_64")]
impl FwCfg {
    /// Attach SMBIOS string overrides to be folded into
    /// `etc/smbios/smbios-tables` when `populate_fw_cfg` runs.
    pub fn with_smbios_overrides(mut self, overrides: FwCfgSmbiosOverrides) -> Self {
        self.smbios_overrides = Some(overrides);
        self
    }

    /// Set the total guest RAM size in bytes for the SMBIOS Type 17
    /// Memory Device entry. Only consumed when `with_smbios_overrides`
    /// has also been called — the no-overrides path emits no Type 17.
    pub fn with_total_memory_size(mut self, size: u64) -> Self {
        self.total_memory_size = size;
        self
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgDmaAccess {
    control_be: u32,
    length_be: u32,
    address_be: u64,
}

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h#L67
#[bitfield(u32)]
struct AccessControl {
    // FW_CFG_DMA_CTL_ERROR = 0x01
    error: bool,
    // FW_CFG_DMA_CTL_READ = 0x02
    read: bool,
    // FW_CFG_DMA_CTL_SKIP = 0x04
    skip: bool,
    // FW_CFG_DMA_CTL_SELECT = 0x08
    select: bool,
    // FW_CFG_DMA_CTL_WRITE = 0x10
    write: bool,
    #[bits(11)]
    _reserved: u16,
    #[bits(16)]
    selector: u16,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgFilesHeader {
    count_be: u32,
}

pub const FILE_NAME_SIZE: usize = 56;

pub fn create_file_name(name: &str) -> [u8; FILE_NAME_SIZE] {
    let mut c_name = [0u8; FILE_NAME_SIZE];
    let c_len = std::cmp::min(FILE_NAME_SIZE - 1, name.len());
    c_name[0..c_len].copy_from_slice(&name.as_bytes()[0..c_len]);
    c_name
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, FromBytes, Clone, Copy)]
struct BootE820Entry {
    addr: u64,
    size: u64,
    type_: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgFile {
    size_be: u32,
    select_be: u16,
    _reserved: u16,
    name: [u8; FILE_NAME_SIZE],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct Allocate {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    align: u32,
    zone: u8,
    _pad: [u8; 63],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct AddPointer {
    command: u32,
    dst: [u8; FILE_NAME_SIZE],
    src: [u8; FILE_NAME_SIZE],
    offset: u32,
    size: u8,
    _pad: [u8; 7],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct AddChecksum {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    offset: u32,
    start: u32,
    len: u32,
    _pad: [u8; 56],
}

fn create_intra_pointer(name: &str, offset: usize, size: u8) -> AddPointer {
    AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(name),
        src: create_file_name(name),
        offset: offset as u32,
        size,
        _pad: [0; 7],
    }
}

fn create_acpi_table_checksum(offset: usize, len: usize) -> AddChecksum {
    AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: (offset + offset_of!(AcpiTableHeader, checksum)) as u32,
        start: offset as u32,
        len: len as u32,
        _pad: [0; 56],
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, IntoBytes)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    asl_compiler_id: [u8; 4],
    asl_compiler_revision: u32,
}

struct AcpiTable {
    rsdp: Vec<u8>,
    tables: Vec<u8>,
    table_pointers: Vec<(usize, u8)>,
    table_checksums: Vec<(usize, usize)>,
}

impl AcpiTable {
    fn pointers(&self) -> &[(usize, u8)] {
        &self.table_pointers
    }

    fn checksums(&self) -> &[(usize, usize)] {
        &self.table_checksums
    }

    fn take(self) -> (Vec<u8>, Vec<u8>) {
        (self.rsdp, self.tables)
    }
}

// Creates fw_cfg items used by firmware to load and verify Acpi tables
// https://github.com/qemu/qemu/blob/master/hw/acpi/bios-linker-loader.c
fn create_acpi_loader(mut acpi_table: AcpiTable) -> [FwCfgItem; 3] {
    let mut table_loader_bytes: Vec<u8> = Vec::new();
    let allocate_rsdp = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        align: 16,
        zone: ALLOC_ZONE_FSEG,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_rsdp.as_bytes());

    let allocate_tables = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        align: 4,
        zone: ALLOC_ZONE_HIGH,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_tables.as_bytes());

    for (pointer_offset, pointer_size) in acpi_table.pointers().iter() {
        let pointer =
            create_intra_pointer(FW_CFG_FILENAME_ACPI_TABLES, *pointer_offset, *pointer_size);
        table_loader_bytes.extend(pointer.as_bytes());
    }
    let table_checksums = acpi_table.checksums().to_vec();
    for (offset, len) in table_checksums.iter() {
        acpi_table.tables[*offset + offset_of!(AcpiTableHeader, checksum)] = 0;
        let checksum = create_acpi_table_checksum(*offset, *len);
        table_loader_bytes.extend(checksum.as_bytes());
    }
    let (mut rsdp, tables) = acpi_table.take();
    rsdp[8] = 0;
    if rsdp.len() > 20 {
        rsdp[32] = 0;
    }
    let (rsdp_pointer_offset, rsdp_pointer_size) = if rsdp.len() <= 20 { (16, 4) } else { (24, 8) };
    let pointer_rsdp_to_root = AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(FW_CFG_FILENAME_RSDP),
        src: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: rsdp_pointer_offset,
        size: rsdp_pointer_size,
        _pad: [0; 7],
    };
    table_loader_bytes.extend(pointer_rsdp_to_root.as_bytes());
    let checksum_rsdp = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: 8,
        start: 0,
        len: 20,
        _pad: [0; 56],
    };
    table_loader_bytes.extend(checksum_rsdp.as_bytes());
    if rsdp.len() > 20 {
        let checksum_rsdp_ext = AddChecksum {
            command: COMMAND_ADD_CHECKSUM,
            file: create_file_name(FW_CFG_FILENAME_RSDP),
            offset: 32,
            start: 0,
            len: rsdp.len() as u32,
            _pad: [0; 56],
        };
        table_loader_bytes.extend(checksum_rsdp_ext.as_bytes());
    }

    #[cfg(target_arch = "x86_64")]
    table_loader_bytes.resize(Q35_ACPI_TABLE_LOADER_SIZE, 0);

    let table_loader = FwCfgItem {
        name: FW_CFG_FILENAME_TABLE_LOADER.to_owned(),
        content: FwCfgContent::Bytes(table_loader_bytes),
    };
    let acpi_rsdp = FwCfgItem {
        name: FW_CFG_FILENAME_RSDP.to_owned(),
        content: FwCfgContent::Bytes(rsdp),
    };
    #[cfg(target_arch = "x86_64")]
    let tables = {
        let mut padded = tables;
        padded.resize(Q35_ACPI_TABLES_SIZE, 0);
        padded
    };
    let apci_tables = FwCfgItem {
        name: FW_CFG_FILENAME_ACPI_TABLES.to_owned(),
        content: FwCfgContent::Bytes(tables),
    };
    [table_loader, acpi_rsdp, apci_tables]
}

#[cfg(target_arch = "x86_64")]
fn smbios_checksum(bytes: &mut [u8]) {
    let checksum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    bytes[5] = (0u8).wrapping_sub(checksum);
}

#[cfg(target_arch = "x86_64")]
fn smbios_table(type_: u8, handle: u16, formatted: &[u8], strings: &[&str]) -> Vec<u8> {
    let mut table = Vec::with_capacity(4 + formatted.len() + 2);
    table.push(type_);
    table.push((4 + formatted.len()) as u8);
    table.extend_from_slice(&handle.to_le_bytes());
    table.extend_from_slice(formatted);

    if strings.is_empty() {
        table.extend_from_slice(&[0, 0]);
    } else {
        for string in strings {
            table.extend_from_slice(string.as_bytes());
            table.push(0);
        }
        table.push(0);
    }

    table
}

#[cfg(target_arch = "x86_64")]
const CH_SMBIOS_BIOS_VENDOR: &str = "Cloud Hypervisor";
#[cfg(target_arch = "x86_64")]
const CH_SMBIOS_BIOS_VERSION: &str = "Cloud Hypervisor";
// Stable placeholder: CH does not produce a real BIOS image, so a fixed date
// keeps measurements deterministic across builds. Format follows SMBIOS Type 0
// "BIOS Release Date" requirement (MM/DD/YYYY).
#[cfg(target_arch = "x86_64")]
const CH_SMBIOS_BIOS_RELEASE_DATE: &str = "01/01/2024";
#[cfg(target_arch = "x86_64")]
const CH_SMBIOS_SYSTEM_MANUFACTURER: &str = "Cloud Hypervisor";
#[cfg(target_arch = "x86_64")]
const CH_SMBIOS_SYSTEM_PRODUCT: &str = "Cloud Hypervisor TDX VM";
#[cfg(target_arch = "x86_64")]
const CH_SMBIOS_CHASSIS_MANUFACTURER: &str = "Cloud Hypervisor";
#[cfg(target_arch = "x86_64")]
const CH_SMBIOS_PROCESSOR_MANUFACTURER: &str = "Cloud Hypervisor";

/// String overrides for the SMBIOS tables emitted via fw_cfg.
///
/// `devices` does not depend on `vmm`, so we mirror the `vmm::SmbiosConfig`
/// shape here. `vmm::DeviceManager::create_fw_cfg_device` materialises one
/// of these from `PlatformConfig::smbios` before constructing `FwCfg`.
///
/// Each `None` field falls back to the corresponding `CH_SMBIOS_*` default,
/// keeping byte-for-byte parity with `caf3a5861` so existing TDX
/// attestation measurements stay stable when no SMBIOS overrides are
/// supplied.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default)]
pub struct FwCfgSmbiosOverrides {
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub bios_release_date: Option<String>,
    pub system_manufacturer: Option<String>,
    pub system_product: Option<String>,
    pub system_version: Option<String>,
    pub system_serial: Option<String>,
    /// Raw 16 bytes in RFC 4122 big-endian order. Encoded into the SMBIOS
    /// 2.6+ wire format (time_low/time_mid/time_hi_and_version
    /// little-endian) by `build_qemu_compat_smbios`.
    pub system_uuid: Option<[u8; 16]>,
    pub system_sku: Option<String>,
    pub system_family: Option<String>,
    pub chassis_manufacturer: Option<String>,
    pub chassis_version: Option<String>,
    pub chassis_serial: Option<String>,
    pub chassis_asset_tag: Option<String>,
    pub processor_manufacturer: Option<String>,
    pub processor_version: Option<String>,
    pub oem_strings: Option<Vec<String>>,
}

/// Encode an RFC 4122 big-endian UUID into the SMBIOS Type 1 wire format.
///
/// Per SMBIOS 2.6+ (and matching QEMU's `smbios_encode_uuid` in
/// `hw/smbios/smbios.c`), the first three fields (`time_low`, `time_mid`,
/// `time_hi_and_version`) are stored little-endian; the remaining bytes
/// stay in their RFC 4122 order.
#[cfg(target_arch = "x86_64")]
fn smbios_encode_uuid(rfc4122_be: &[u8; 16]) -> [u8; 16] {
    let mut out = *rfc4122_be;
    out.swap(0, 3);
    out.swap(1, 2);
    out.swap(4, 5);
    out.swap(6, 7);
    out
}

#[cfg(target_arch = "x86_64")]
fn smbios_size_field(size_bytes: u64) -> (u16, u32) {
    // SMBIOS Type 17 size encoding mirrors QEMU's
    // `hw/smbios/smbios.c::smbios_build_type_17_table`:
    //   * size in MB rounded up;
    //   * if size_mb < 0x7fff (32 GB - 1 MB): write KB-or-MB into `size`,
    //     extended_size = 0;
    //   * else: clamp `size` to 0x7fff and put the full MB count in
    //     `extended_size`.
    const MAX_T17_STD_MB: u64 = 0x7fff;
    let size_mb = size_bytes.div_ceil(1 << 20);
    if size_mb < MAX_T17_STD_MB {
        (size_mb as u16, 0)
    } else {
        (MAX_T17_STD_MB as u16, size_mb as u32)
    }
}

#[cfg(target_arch = "x86_64")]
fn build_qemu_compat_smbios(
    overrides: Option<&FwCfgSmbiosOverrides>,
    total_memory_size: u64,
) -> (Vec<u8>, Vec<u8>) {
    // String-table indices are 1-based per SMBIOS spec; 0 means
    // "no string". We push every string into `strings` in slot order and
    // use a tiny helper to keep the per-table formatted bytes readable.
    let mut tables = Vec::new();

    // When the operator hasn't passed any `--platform smbios.*` knobs we
    // emit the historical Cloud Hypervisor table set (Types 0/1/127 only).
    // Any deployment that has already taken a TDX measurement against the
    // pre-`caf3a5861` blob therefore observes zero churn — the new tables
    // (3/4/11/17/32) only appear when the operator opts into them.
    let emit_extended_tables = overrides.is_some();
    let none_overrides = FwCfgSmbiosOverrides::default();
    let o = overrides.unwrap_or(&none_overrides);

    // ----- Type 0: BIOS Information ---------------------------------------
    let mut bios_info = vec![0u8; 0x18 - 4];
    bios_info[0] = 1;
    bios_info[1] = 2;
    bios_info[2..4].copy_from_slice(&0xe800u16.to_le_bytes());
    bios_info[4] = 3;
    let bios_vendor = o.bios_vendor.as_deref().unwrap_or(CH_SMBIOS_BIOS_VENDOR);
    let bios_version = o.bios_version.as_deref().unwrap_or(CH_SMBIOS_BIOS_VERSION);
    let bios_release_date = o
        .bios_release_date
        .as_deref()
        .unwrap_or(CH_SMBIOS_BIOS_RELEASE_DATE);
    tables.extend_from_slice(&smbios_table(
        0,
        0x0000,
        &bios_info,
        &[bios_vendor, bios_version, bios_release_date],
    ));

    // ----- Type 1: System Information -------------------------------------
    // Layout (length 0x1b, less the 4-byte header):
    //   off 0: manufacturer_str (1)
    //   off 1: product_name_str (2)
    //   off 2: version_str (3 if present, else 0)
    //   off 3: serial_number_str (4 if present, else 0)
    //   off 4..0x14: 16-byte UUID (SMBIOS 2.6 wire format)
    //   off 0x14: wake_up_type = 0x06 (power switch)
    //   off 0x15: sku_number_str (5 if present, else 0)
    //   off 0x16: family_str (6 if present, else 0)
    let mut system_info = vec![0u8; 0x1b - 4];
    let system_manufacturer = o
        .system_manufacturer
        .as_deref()
        .unwrap_or(CH_SMBIOS_SYSTEM_MANUFACTURER);
    let system_product = o
        .system_product
        .as_deref()
        .unwrap_or(CH_SMBIOS_SYSTEM_PRODUCT);
    let mut t1_strings: Vec<&str> = vec![system_manufacturer, system_product];
    system_info[0] = 1;
    system_info[1] = 2;
    let mut next_idx = 3u8;
    if let Some(v) = o.system_version.as_deref() {
        system_info[2] = next_idx;
        t1_strings.push(v);
        next_idx += 1;
    }
    if let Some(s) = o.system_serial.as_deref() {
        system_info[3] = next_idx;
        t1_strings.push(s);
        next_idx += 1;
    }
    let uuid_bytes = match o.system_uuid {
        Some(raw) => smbios_encode_uuid(&raw),
        None => [0u8; 16],
    };
    system_info[4..4 + 16].copy_from_slice(&uuid_bytes);
    system_info[0x14] = 0x06;
    if let Some(s) = o.system_sku.as_deref() {
        system_info[0x15] = next_idx;
        t1_strings.push(s);
        next_idx += 1;
    }
    if let Some(f) = o.system_family.as_deref() {
        system_info[0x16] = next_idx;
        t1_strings.push(f);
        let _ = next_idx; // last assignment, drop unused warning
    }
    tables.extend_from_slice(&smbios_table(1, 0x0100, &system_info, &t1_strings));

    if emit_extended_tables {
    // ----- Type 3: System Enclosure / Chassis -----------------------------
    // Layout (length 0x16, less the 4-byte header):
    //   off 0: manufacturer_str (1)
    //   off 1: type = 0x01 (Other)
    //   off 2: version_str (2 if present)
    //   off 3: serial_number_str (3 if present)
    //   off 4: asset_tag_str (4 if present)
    //   off 5: boot_up_state = 0x03 (Safe)
    //   off 6: power_supply_state = 0x03 (Safe)
    //   off 7: thermal_state = 0x03 (Safe)
    //   off 8: security_status = 0x02 (Unknown)
    //   off 9..13: oem_defined = 0
    //   off 13: height
    //   off 14: number_of_power_cords
    //   off 15: contained_element_count
    //   off 16: contained_element_record_length
    //   off 17: sku_number_str (0 — not exposed via CLI yet)
    let mut chassis_info = vec![0u8; 0x16 - 4];
    let chassis_manufacturer = o
        .chassis_manufacturer
        .as_deref()
        .unwrap_or(CH_SMBIOS_CHASSIS_MANUFACTURER);
    let mut t3_strings: Vec<&str> = vec![chassis_manufacturer];
    chassis_info[0] = 1;
    chassis_info[1] = 0x01; // Other
    let mut next_idx = 2u8;
    if let Some(v) = o.chassis_version.as_deref() {
        chassis_info[2] = next_idx;
        t3_strings.push(v);
        next_idx += 1;
    }
    if let Some(s) = o.chassis_serial.as_deref() {
        chassis_info[3] = next_idx;
        t3_strings.push(s);
        next_idx += 1;
    }
    if let Some(a) = o.chassis_asset_tag.as_deref() {
        chassis_info[4] = next_idx;
        t3_strings.push(a);
        let _ = next_idx;
    }
    chassis_info[5] = 0x03; // boot_up_state = Safe
    chassis_info[6] = 0x03; // power_supply_state = Safe
    chassis_info[7] = 0x03; // thermal_state = Safe
    chassis_info[8] = 0x02; // security_status = Unknown
    // bytes 9..13 (oem_defined), 13 (height), 14 (cords), 15..17 stay zero
    tables.extend_from_slice(&smbios_table(3, 0x0300, &chassis_info, &t3_strings));

    // ----- Type 4: Processor Information ----------------------------------
    // We emit one Type 4 representing the package — per-vCPU iteration is
    // not required for the q35 attestation surface and matches what
    // SeaBIOS/OVMF expect when no real package topology is exposed.
    //
    // Layout (length 0x2a, SMBIOS 2.6 — `SMBIOS_TYPE_4_LEN_V28`):
    //   off 0: socket_designation_str (1)
    //   off 1: processor_type = 0x03 (Central Processor)
    //   off 2: processor_family = 0x01 (Other)
    //   off 3: processor_manufacturer_str (2)
    //   off 4..12: processor_id (zero — leave CPUID-derived ID to firmware)
    //   off 12: processor_version_str (3 if present)
    //   off 13: voltage = 0 (Reserved / unknown)
    //   off 14..16: external_clock = 0
    //   off 16..18: max_speed = 0
    //   off 18..20: current_speed = 0
    //   off 20: status = 0x41 (Socket populated, CPU enabled)
    //   off 21: processor_upgrade = 0x01 (Other)
    //   off 22..24: l1_cache_handle = 0xFFFF
    //   off 24..26: l2_cache_handle = 0xFFFF
    //   off 26..28: l3_cache_handle = 0xFFFF
    //   off 28: serial_number_str (0)
    //   off 29: asset_tag_str (0)
    //   off 30: part_number_str (0)
    //   off 31: core_count = 0 (Unknown)
    //   off 32: core_enabled = 0
    //   off 33: thread_count = 0
    //   off 34..36: processor_characteristics = 0x02 (Unknown)
    //   off 36..38: processor_family2 = 0x01 (Other)
    let mut proc_info = vec![0u8; 0x2a - 4];
    let processor_manufacturer = o
        .processor_manufacturer
        .as_deref()
        .unwrap_or(CH_SMBIOS_PROCESSOR_MANUFACTURER);
    let mut t4_strings: Vec<&str> = vec!["CPU 0", processor_manufacturer];
    proc_info[0] = 1; // socket_designation_str
    proc_info[1] = 0x03; // processor_type = Central Processor
    proc_info[2] = 0x01; // processor_family = Other
    proc_info[3] = 2; // processor_manufacturer_str
    // off 4..12: processor_id stays zero
    if let Some(v) = o.processor_version.as_deref() {
        proc_info[12] = 3;
        t4_strings.push(v);
    }
    proc_info[13] = 0; // voltage
    // off 14..20: clocks/speeds stay zero
    proc_info[20] = 0x41; // status: Socket populated + CPU enabled
    proc_info[21] = 0x01; // processor_upgrade = Other
    proc_info[22..24].copy_from_slice(&0xffffu16.to_le_bytes());
    proc_info[24..26].copy_from_slice(&0xffffu16.to_le_bytes());
    proc_info[26..28].copy_from_slice(&0xffffu16.to_le_bytes());
    // off 28..31 (serial/asset/part) and 31..34 (core/thread counts) zero
    proc_info[34..36].copy_from_slice(&0x0002u16.to_le_bytes());
    proc_info[36..38].copy_from_slice(&0x0001u16.to_le_bytes());
    tables.extend_from_slice(&smbios_table(4, 0x0400, &proc_info, &t4_strings));

    // ----- Type 11: OEM strings -------------------------------------------
    let oem_strings_default = [String::from("Cloud Hypervisor")];
    let oem_strings: &[String] = match o.oem_strings.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => &oem_strings_default,
    };
    // formatted area is just `count`
    let oem_formatted = vec![oem_strings.len() as u8];
    let oem_refs: Vec<&str> = oem_strings.iter().map(|s| s.as_str()).collect();
    tables.extend_from_slice(&smbios_table(11, 0x0b00, &oem_formatted, &oem_refs));

    // ----- Type 17: Memory Device -----------------------------------------
    // We expose a single Memory Device covering the full guest RAM size.
    // Per-zone iteration (one Type 17 per `MemoryConfig::zones` entry) is
    // out of scope for this change — the typical CH deployment has a
    // single backing region and OS detect logic only checks for
    // *presence* of Type 17, not per-DIMM counts.
    //
    // Layout (length 0x28, SMBIOS 2.8):
    //   off  0..2: physical_memory_array_handle = 0x1000 (Type 16)
    //   off  2..4: memory_error_information_handle = 0xFFFE (Not provided)
    //   off  4..6: total_width = 0xFFFF (Unknown)
    //   off  6..8: data_width = 0xFFFF (Unknown)
    //   off  8..10: size (encoded per SMBIOS spec)
    //   off 10: form_factor = 0x09 (DIMM)
    //   off 11: device_set = 0
    //   off 12: device_locator_str (1)
    //   off 13: bank_locator_str (0 - not set)
    //   off 14: memory_type = 0x12 (DRAM-as-DDR4-ish stand-in;
    //          QEMU uses 0x07/RAM, but TDX guests expect a concrete
    //          DDR-class enum to satisfy lscpu/dmidecode parsers.
    //          0x12 is "DDR" — a safer middle ground than the ambiguous
    //          0x07 that some attestation verifiers reject.)
    //   off 15..17: type_detail = 0x0002 (Other)
    //   off 17..19: speed = 0
    //   off 19..22: manufacturer/serial/asset/part strs (all 0)
    //   off 23: attributes = 0
    //   off 24..28: extended_size
    //   off 28..30: configured_clock_speed = 0
    //   off 30..32: minimum_voltage = 0
    //   off 32..34: maximum_voltage = 0
    //   off 34..36: configured_voltage = 0
    let mut mem_info = vec![0u8; 0x28 - 4];
    mem_info[0..2].copy_from_slice(&0x1000u16.to_le_bytes());
    mem_info[2..4].copy_from_slice(&0xfffeu16.to_le_bytes());
    mem_info[4..6].copy_from_slice(&0xffffu16.to_le_bytes());
    mem_info[6..8].copy_from_slice(&0xffffu16.to_le_bytes());
    let (size_field, ext_size) = smbios_size_field(total_memory_size);
    mem_info[8..10].copy_from_slice(&size_field.to_le_bytes());
    mem_info[10] = 0x09; // form_factor = DIMM
    mem_info[11] = 0; // device_set
    mem_info[12] = 1; // device_locator_str -> "DIMM 0"
    mem_info[13] = 0; // bank_locator_str (none)
    // SMBIOS spec table 76 lists 0x12 as "DDR"; we use it as a concrete
    // DDR-class enum so attestation verifiers / dmidecode parsers don't
    // reject the ambiguous 0x07 ("RAM") that QEMU emits.
    mem_info[14] = 0x12;
    mem_info[15..17].copy_from_slice(&0x0002u16.to_le_bytes()); // type_detail = Other
    // off 17..23 (speed, mfr/serial/asset/part strs) zero
    mem_info[24..28].copy_from_slice(&ext_size.to_le_bytes());
    // remaining voltage fields zero
    tables.extend_from_slice(&smbios_table(17, 0x1100, &mem_info, &["DIMM 0"]));

    // ----- Type 32: System Boot Information -------------------------------
    // Layout: 6 reserved bytes + boot_status (0 = no errors)
    let boot_info = vec![0u8; 7];
    // boot_info already all zero
    tables.extend_from_slice(&smbios_table(32, 0x2000, &boot_info, &[]));
    } // end emit_extended_tables

    // ----- Type 127: End of table -----------------------------------------
    tables.extend_from_slice(&smbios_table(127, 0x7f00, &[], &[]));

    // OVMF allocates Q35_SMBIOS_TABLES_SIZE for the etc/smbios/smbios-tables
    // blob. The historical CH default (Types 0/1/127 only) fits in 0x13b
    // bytes — preserve that exact pad length when no overrides are
    // supplied so the anchor's `tables_len` field remains byte-identical
    // to the pre-`caf3a5861` blob (asserted by the byte-compat unit test).
    // When overrides ARE supplied the additional tables can push us past
    // 0x13b, so round up to the next 4 KiB boundary to keep the OVMF
    // reserved-memory region happy.
    let table_len = tables.len();
    let pad_to = if emit_extended_tables {
        std::cmp::max(Q35_SMBIOS_TABLES_SIZE, (table_len + 0xfff) & !0xfff)
    } else {
        Q35_SMBIOS_TABLES_SIZE
    };
    tables.resize(pad_to, 0);

    let mut anchor = vec![0u8; Q35_SMBIOS_ANCHOR_SIZE];
    anchor[0..5].copy_from_slice(b"_SM3_");
    anchor[6] = Q35_SMBIOS_ANCHOR_SIZE as u8;
    anchor[7] = 1;
    anchor[8] = 3;
    anchor[9] = 0;
    anchor[10] = 0;
    anchor[12..16].copy_from_slice(&(tables.len() as u32).to_le_bytes());
    smbios_checksum(&mut anchor);

    (anchor, tables)
}

impl FwCfg {
    #[cfg(target_arch = "x86_64")]
    fn update_setup_data<F>(&mut self, update: F)
    where
        F: FnOnce(&mut boot_params),
    {
        if let FwCfgContent::Bytes(buffer) = &mut self.known_items[FW_CFG_SETUP_DATA as usize] {
            if buffer.len() >= size_of::<boot_params>() {
                let bp =
                    boot_params::from_mut_slice(&mut buffer[..size_of::<boot_params>()]).unwrap();
                update(bp);
            }
        }
    }

    pub fn new(memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>) -> FwCfg {
        Self::new_with_options(memory, true, true, Vec::new())
    }

    pub fn new_with_options(
        memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
        linuxboot_option_rom_enabled: bool,
        patch_linux_setup_header: bool,
        option_roms: Vec<(String, PathBuf)>,
    ) -> FwCfg {
        const DEFAULT_ITEM: FwCfgContent = FwCfgContent::Slice(&[]);
        let mut known_items = [DEFAULT_ITEM; FW_CFG_KNOWN_ITEMS];
        known_items[FW_CFG_SIGNATURE as usize] = FwCfgContent::Slice(&FW_CFG_SIGNATURE_VALUE);
        known_items[FW_CFG_ID as usize] = FwCfgContent::Slice(&FW_CFG_FEATURE);
        known_items[FW_CFG_UUID as usize] = FwCfgContent::Bytes(vec![0; 16]);
        known_items[FW_CFG_NOGRAPHIC as usize] = FwCfgContent::Bytes(1u16.to_le_bytes().to_vec());
        known_items[FW_CFG_NB_CPUS as usize] = FwCfgContent::Bytes(1u16.to_le_bytes().to_vec());
        known_items[FW_CFG_BOOT_DEVICE as usize] = FwCfgContent::Bytes(0u16.to_le_bytes().to_vec());
        known_items[FW_CFG_NUMA as usize] = FwCfgContent::Bytes(vec![0; 16]);
        known_items[FW_CFG_BOOT_MENU as usize] = FwCfgContent::Bytes(0u16.to_le_bytes().to_vec());
        known_items[FW_CFG_MAX_CPUS as usize] = FwCfgContent::Bytes(1u16.to_le_bytes().to_vec());
        known_items[FW_CFG_KERNEL_ENTRY as usize] = FwCfgContent::U32(0);
        let file_buf = Vec::from(FwCfgFilesHeader { count_be: 0 }.as_mut_bytes());
        known_items[FW_CFG_FILE_DIR as usize] = FwCfgContent::Bytes(file_buf);

        let mut arch_known_items = BTreeMap::new();
        #[cfg(target_arch = "x86_64")]
        {
            // Per QEMU `hw/i386/fw_cfg.c::fw_cfg_init_hpet`: byte 0 is
            // the count/event-mask (0 = first instance present), bytes
            // 1..5 are the timer block ID (LE u32), bytes 5..13 are the
            // MMIO base address (LE u64), the trailing min_tick / page
            // protection bytes stay zero.
            let mut hpet_config = vec![0; HPET_FW_CONFIG_SIZE];
            hpet_config[0] = 0;
            let block_id = crate::legacy::hpet_block_id().to_le_bytes();
            hpet_config[1..5].copy_from_slice(&block_id);
            let address = crate::legacy::HPET_BASE.to_le_bytes();
            hpet_config[5..13].copy_from_slice(&address);

            arch_known_items.insert(FW_CFG_ACPI_TABLES, FwCfgContent::Bytes(Vec::new()));
            arch_known_items.insert(
                FW_CFG_IRQ0_OVERRIDE,
                FwCfgContent::Bytes(1u32.to_le_bytes().to_vec()),
            );
            arch_known_items.insert(FW_CFG_HPET, FwCfgContent::Bytes(hpet_config));
        }

        FwCfg {
            selector: 0,
            data_offset: 0,
            dma_address: 0,
            items: vec![],
            known_items,
            arch_known_items,
            memory,
            dma_pre_hook: None,
            linuxboot_option_rom_enabled,
            patch_linux_setup_header,
            option_roms,
            #[cfg(target_arch = "x86_64")]
            smbios_overrides: None,
            #[cfg(target_arch = "x86_64")]
            total_memory_size: 0,
        }
    }

    pub fn populate_fw_cfg(
        &mut self,
        mem_size: Option<usize>,
        kernel: Option<File>,
        initramfs: Option<File>,
        cmdline: Option<std::ffi::CString>,
        fw_cfg_item_list: Option<Vec<FwCfgItem>>,
    ) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        self.add_qemu_compat_files()?;
        if let Some(mem_size) = mem_size {
            #[cfg(target_arch = "x86_64")]
            {
                self.known_items[FW_CFG_RAM_SIZE as usize] =
                    FwCfgContent::Bytes((mem_size as u64).to_le_bytes().to_vec());
            }
            self.add_e820(mem_size)?;
        }
        if let Some(kernel) = kernel {
            self.add_kernel_data(&kernel)?;
        }
        if let Some(cmdline) = cmdline {
            self.add_kernel_cmdline(cmdline);
        }
        if let Some(initramfs) = initramfs {
            self.add_initramfs_data(&initramfs, mem_size)?;
        }
        if let Some(fw_cfg_item_list) = fw_cfg_item_list {
            for item in fw_cfg_item_list {
                self.add_item(item)?;
            }
        }
        Ok(())
    }

    pub fn add_e820(&mut self, mem_size: usize) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        let mut mem_regions = {
            // Match QEMU/KVM's fw_cfg e820 handoff: the KVM identity-map/TSS
            // pages are advertised first, then the low RAM alias is exposed as
            // one contiguous entry. OVMF uses this data for legacy INT 15
            // services that linuxboot_dma relies on.
            let mut regions = vec![(KVM_IDENTITY_MAP_START, KVM_IDENTITY_MAP_SIZE, E820_RESERVED)];
            let below_4g = std::cmp::min(mem_size as u64, MEM_32BIT_DEVICES_START.0) as usize;
            regions.push((GuestAddress(0), below_4g, E820_RAM));
            regions
        };
        #[cfg(target_arch = "aarch64")]
        let mut mem_regions = arch::aarch64::arch_memory_regions();

        #[cfg(target_arch = "aarch64")]
        {
            if mem_size < MEM_32BIT_DEVICES_START.0 as usize {
                mem_regions.push((
                    HIGH_RAM_START,
                    mem_size - HIGH_RAM_START.0 as usize,
                    RegionType::Ram,
                ));
            } else {
                mem_regions.push((
                    HIGH_RAM_START,
                    MEM_32BIT_RESERVED_START.0 as usize - HIGH_RAM_START.0 as usize,
                    RegionType::Ram,
                ));
                mem_regions.push((
                    MEM_32BIT_DEVICES_START,
                    MEM_32BIT_DEVICES_SIZE as usize,
                    RegionType::Reserved,
                ));
                mem_regions.push((
                    PCI_MMCONFIG_START,
                    PCI_MMCONFIG_SIZE as usize,
                    RegionType::Reserved,
                ));
            }
        }

        if mem_size >= MEM_32BIT_DEVICES_START.0 as usize {
            #[cfg(target_arch = "aarch64")]
            mem_regions.push((
                RAM_64BIT_START,
                mem_size - (MEM_32BIT_DEVICES_START.0 as usize),
                RegionType::Ram,
            ));

            #[cfg(target_arch = "x86_64")]
            mem_regions.push((
                RAM_64BIT_START,
                mem_size - (MEM_32BIT_DEVICES_START.0 as usize),
                E820_RAM,
            ));
        }

        let mut bytes = vec![];
        for (addr, size, type_) in mem_regions.iter() {
            #[cfg(target_arch = "aarch64")]
            let type_ = match type_ {
                RegionType::Ram => E820_RAM,
                RegionType::Reserved => E820_RESERVED,
                RegionType::SubRegion => continue,
            };
            #[cfg(target_arch = "x86_64")]
            let type_ = *type_;
            info!(
                "fw_cfg: e820 addr={:#x} size={:#x} type={}",
                addr.0, size, type_
            );
            let mut entry = BootE820Entry {
                addr: addr.0,
                size: *size as u64,
                type_,
            };
            bytes.extend_from_slice(entry.as_mut_bytes());
        }
        let item = FwCfgItem {
            name: "etc/e820".to_owned(),
            content: FwCfgContent::Bytes(bytes),
        };
        self.add_item(item)
    }

    fn file_dir_mut(&mut self) -> &mut Vec<u8> {
        let FwCfgContent::Bytes(file_buf) = &mut self.known_items[FW_CFG_FILE_DIR as usize] else {
            unreachable!("fw_cfg: selector {FW_CFG_FILE_DIR:#x} should be FwCfgContent::Byte!")
        };
        file_buf
    }

    fn update_count(&mut self) {
        let mut header = FwCfgFilesHeader {
            count_be: (self.items.len() as u32).to_be(),
        };
        self.file_dir_mut()[0..4].copy_from_slice(header.as_mut_bytes());
    }

    fn rebuild_file_dir(&mut self) -> Result<()> {
        let mut file_buf = Vec::from(
            FwCfgFilesHeader {
                count_be: (self.items.len() as u32).to_be(),
            }
            .as_mut_bytes(),
        );

        for (index, item) in self.items.iter().enumerate() {
            let c_name = create_file_name(&item.name);
            let size = item.content.size()?;
            let mut cfg_file = FwCfgFile {
                size_be: size.to_be(),
                select_be: (FW_CFG_FILE_FIRST + index as u16).to_be(),
                _reserved: 0,
                name: c_name,
            };
            file_buf.extend_from_slice(cfg_file.as_mut_bytes());
        }

        self.known_items[FW_CFG_FILE_DIR as usize] = FwCfgContent::Bytes(file_buf);
        Ok(())
    }

    pub fn add_item(&mut self, item: FwCfgItem) -> Result<()> {
        let size = item.content.size()?;
        if self.items.iter().any(|existing| existing.name == item.name) {
            return Err(ErrorKind::AlreadyExists.into());
        }
        let index = self
            .items
            .partition_point(|existing| existing.name.as_str() < item.name.as_str());
        info!(
            "fw_cfg: add file selector={:#x} size={:#x} name={}",
            FW_CFG_FILE_FIRST + index as u16,
            size,
            item.name
        );
        self.items.insert(index, item);
        self.rebuild_file_dir()
    }

    fn has_item(&self, name: &str) -> bool {
        self.items.iter().any(|item| item.name == name)
    }

    fn add_item_if_missing(&mut self, name: &str, content: FwCfgContent) -> Result<()> {
        if self.has_item(name) {
            return Ok(());
        }

        self.add_item(FwCfgItem {
            name: name.to_string(),
            content,
        })
    }

    fn known_content(&self, selector: u16) -> Option<&FwCfgContent> {
        self.known_items
            .get(selector as usize)
            .or_else(|| self.arch_known_items.get(&selector))
    }

    #[cfg(target_arch = "x86_64")]
    fn add_qemu_compat_files(&mut self) -> Result<()> {
        // Historical QEMU layout for reference only; we no longer hard-code
        // these paths. Operators that want OVMF's kvmvapic option ROM must
        // pass `--platform option_rom=genroms/kvmvapic.bin=/path/to/kvmvapic.bin`.
        const KVMVAPIC_FW_CFG: &str = "genroms/kvmvapic.bin";

        self.add_item_if_missing("bios-geometry", FwCfgContent::Bytes(Vec::new()))?;
        self.add_item_if_missing(
            "etc/boot-fail-wait",
            FwCfgContent::Bytes((-1i32).to_le_bytes().to_vec()),
        )?;
        let (smbios_anchor, smbios_tables) =
            build_qemu_compat_smbios(self.smbios_overrides.as_ref(), self.total_memory_size);
        self.add_item_if_missing(
            "etc/smbios/smbios-anchor",
            FwCfgContent::Bytes(smbios_anchor),
        )?;
        self.add_item_if_missing(
            "etc/smbios/smbios-tables",
            FwCfgContent::Bytes(smbios_tables),
        )?;
        // QEMU SMI handshake (hw/i386/fw_cfg.c::pc_build_smbios + hw/isa/lpc_ich9.c).
        // OVMF reads `supported-features`, writes the subset it understands to
        // `requested-features`, then writes `features-ok = 1` once the host has
        // accepted the negotiation. CH does not emulate SMM, so the meaningful
        // value here is `requested-features = 0`. `supported-features` mirrors
        // QEMU's bit layout (ICH9_LPC_SMI_F_BROADCAST_BIT=0,
        // ICH9_LPC_SMI_F_CPU_HOTPLUG_BIT=1, ICH9_LPC_SMI_F_CPU_HOT_UNPLUG_BIT=2)
        // so OVMF's negotiation handshake completes; we never act on those bits.
        self.add_item_if_missing("etc/smi/features-ok", FwCfgContent::Bytes(vec![1]))?;
        self.add_item_if_missing(
            "etc/smi/requested-features",
            FwCfgContent::Bytes(0u64.to_le_bytes().to_vec()),
        )?;
        self.add_item_if_missing(
            "etc/smi/supported-features",
            FwCfgContent::Bytes(7u64.to_le_bytes().to_vec()),
        )?;
        // QEMU `etc/system-states`: 6 bytes encoding (enabled << 7) | (slp_typ
        // & 0x07) for S0..S5 (hw/acpi/core.c::acpi_pm1_cnt_init). CH supports
        // S0 (always on) and S5 (poweroff via Q35Pm1Cnt), advertises S3 with
        // slp_typ=1 to satisfy OVMF's wakeup discovery, and leaves S1/S2
        // disabled. S4 is advertised but no actual hibernation backing exists.
        self.add_item_if_missing(
            "etc/system-states",
            FwCfgContent::Bytes(vec![128, 0, 0, 129, 128, 128]),
        )?;
        self.add_item_if_missing("etc/tpm/log", FwCfgContent::Bytes(Vec::new()))?;
        // The kvmvapic ROM is only emitted when the operator explicitly
        // configures it. If unset we deliberately leave the entry absent so
        // OVMF falls back to its built-in handling rather than reading an
        // empty blob. Pre-existing logic that registered an empty
        // `genroms/kvmvapic.bin` item only existed to mirror QEMU's package
        // layout and is no longer required.
        let _ = KVMVAPIC_FW_CFG; // documentation anchor only
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn add_configured_option_roms(&mut self) -> Result<()> {
        // Operators opt in to option ROMs by passing
        //   --platform option_roms=NAME:PATH[,NAME:PATH...]
        // (see `vmm::config::PlatformConfig`). Without that, no QEMU
        // package files are required at runtime — historically CH would
        // silently look in `/usr/share/qemu/` which forced every host to
        // ship the QEMU package.
        //
        // The linuxboot_option_rom_enabled flag still gates the emission of
        // the auto-generated `bootorder` entry, since some firmware images
        // (notably TDX-hardened OVMF with strict measured boot) do not want
        // the boot path coerced to the option-ROM device.
        const LINUXBOOT_DMA_FW_CFG: &str = "genroms/linuxboot_dma.bin";
        const LINUXBOOT_DMA_BOOT_PATH: &[u8] = b"/rom@genroms/linuxboot_dma.bin\0";

        if self.option_roms.is_empty() {
            return Ok(());
        }

        let entries: Vec<(String, PathBuf)> = self.option_roms.clone();
        let mut emitted_linuxboot = false;
        for (name, path) in entries {
            match File::open(&path) {
                Ok(file) => {
                    self.add_item(FwCfgItem {
                        name: name.clone(),
                        content: FwCfgContent::File(0, file),
                    })?;
                    if name == LINUXBOOT_DMA_FW_CFG {
                        emitted_linuxboot = true;
                    }
                }
                Err(e) => {
                    info!(
                        "Skipping option ROM {name} from {}: {e}",
                        path.display()
                    );
                }
            }
        }

        if emitted_linuxboot && self.linuxboot_option_rom_enabled && !self.has_item("bootorder") {
            self.add_item(FwCfgItem {
                name: "bootorder".to_string(),
                content: FwCfgContent::Bytes(LINUXBOOT_DMA_BOOT_PATH.to_vec()),
            })?;
        }

        Ok(())
    }

    fn dma_read_content(
        &self,
        content: &FwCfgContent,
        offset: u32,
        len: u32,
        address: u64,
    ) -> Result<u32> {
        let content_size = content.size()?.saturating_sub(offset);
        let op_size = std::cmp::min(content_size, len);
        let mut access = content.access(offset);
        let mut buf = vec![0u8; op_size as usize];
        access.read_exact(buf.as_mut_bytes())?;
        let r = self
            .memory
            .memory()
            .write(buf.as_bytes(), GuestAddress(address));
        match r {
            Err(e) => {
                error!("fw_cfg: dma read error: {e:x?}");
                Err(ErrorKind::InvalidInput.into())
            }
            Ok(size) => Ok(size as u32),
        }
    }

    fn dma_read(&mut self, selector: u16, len: u32, address: u64) -> Result<()> {
        let op_size = if let Some(content) = self.known_content(selector) {
            self.dma_read_content(content, self.data_offset, len, address)
        } else if let Some(item) = self.items.get((selector - FW_CFG_FILE_FIRST) as usize) {
            self.dma_read_content(&item.content, self.data_offset, len, address)
        } else {
            error!("fw_cfg: selector {selector:#x} does not exist.");
            Err(ErrorKind::NotFound.into())
        }?;
        self.data_offset += op_size;
        Ok(())
    }

    fn selector_name(&self, selector: u16) -> &str {
        self.items
            .get(selector.wrapping_sub(FW_CFG_FILE_FIRST) as usize)
            .map(|item| item.name.as_str())
            .unwrap_or(match selector {
                FW_CFG_SIGNATURE => "signature",
                FW_CFG_ID => "id",
                FW_CFG_UUID => "uuid",
                FW_CFG_RAM_SIZE => "ram_size",
                FW_CFG_NOGRAPHIC => "nographic",
                FW_CFG_NB_CPUS => "nb_cpus",
                FW_CFG_KERNEL_ADDR => "kernel_addr",
                FW_CFG_KERNEL_SIZE => "kernel_size",
                FW_CFG_BOOT_DEVICE => "boot_device",
                FW_CFG_NUMA => "numa",
                FW_CFG_BOOT_MENU => "boot_menu",
                FW_CFG_MAX_CPUS => "max_cpus",
                FW_CFG_KERNEL_ENTRY => "kernel_entry",
                FW_CFG_INITRD_ADDR => "initrd_addr",
                FW_CFG_INITRD_SIZE => "initrd_size",
                FW_CFG_KERNEL_DATA => "kernel_data",
                FW_CFG_INITRD_DATA => "initrd_data",
                FW_CFG_CMDLINE_ADDR => "cmdline_addr",
                FW_CFG_CMDLINE_SIZE => "cmdline_size",
                FW_CFG_CMDLINE_DATA => "cmdline_data",
                FW_CFG_SETUP_ADDR => "setup_addr",
                FW_CFG_SETUP_SIZE => "setup_size",
                FW_CFG_SETUP_DATA => "setup_data",
                FW_CFG_FILE_DIR => "file_dir",
                #[cfg(target_arch = "x86_64")]
                FW_CFG_ACPI_TABLES => "acpi_tables",
                #[cfg(target_arch = "x86_64")]
                FW_CFG_IRQ0_OVERRIDE => "irq0_override",
                #[cfg(target_arch = "x86_64")]
                FW_CFG_HPET => "hpet",
                _ => "unknown",
            })
    }

    fn do_dma(&mut self) {
        let dma_address = self.dma_address;
        if let Some(hook) = &self.dma_pre_hook {
            hook(dma_address, std::mem::size_of::<FwCfgDmaAccess>() as u64);
        }
        let mut access = FwCfgDmaAccess::new_zeroed();
        let dma_access = match self
            .memory
            .memory()
            .read(access.as_mut_bytes(), GuestAddress(dma_address))
        {
            Ok(_) => access,
            Err(e) => {
                error!("fw_cfg: invalid address of dma access {dma_address:#x}: {e:?}");
                return;
            }
        };
        let control = AccessControl(u32::from_be(dma_access.control_be));
        if control.select() {
            self.selector = control.selector();
            self.data_offset = 0;
        }
        let len = u32::from_be(dma_access.length_be);
        let addr = u64::from_be(dma_access.address_be);
        let name = self.selector_name(self.selector);
        info!(
            "fw_cfg: dma selector={:#x} name={} control={:#x} len={:#x} addr={:#x} desc={:#x}",
            self.selector,
            name,
            u32::from_be(dma_access.control_be),
            len,
            addr,
            dma_address
        );
        if let Some(hook) = &self.dma_pre_hook {
            hook(addr, len as u64);
        }
        let ret = if control.read() {
            self.dma_read(self.selector, len, addr)
        } else if control.write() {
            Err(ErrorKind::InvalidInput.into())
        } else if control.skip() {
            self.data_offset += len;
            Ok(())
        } else {
            Err(ErrorKind::InvalidData.into())
        };
        let mut access_resp = AccessControl(0);
        if let Err(e) = ret {
            error!("fw_cfg: dma operation {dma_access:x?}: {e:x?}");
            access_resp.set_error(true);
        }
        if let Err(e) = self.memory.memory().write(
            &access_resp.0.to_be_bytes(),
            GuestAddress(dma_address + core::mem::offset_of!(FwCfgDmaAccess, control_be) as u64),
        ) {
            error!("fw_cfg: finishing dma: {e:?}");
        }
    }

    pub fn add_kernel_data(&mut self, file: &File) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        const FW_CFG_SETUP_LOAD_ADDR: u32 = 0x0001_0000;
        #[cfg(target_arch = "x86_64")]
        const FW_CFG_KERNEL_LOAD_ADDR: u32 = 0x0010_0000;

        let mut buffer = vec![0u8; size_of::<boot_params>()];
        file.read_exact_at(&mut buffer, 0)?;
        let bp = boot_params::from_mut_slice(&mut buffer).unwrap();
        #[cfg(target_arch = "x86_64")]
        let setup_sects = if bp.hdr.setup_sects == 0 {
            4
        } else {
            bp.hdr.setup_sects
        };
        #[cfg(target_arch = "x86_64")]
        {
            const FW_CFG_CMDLINE_LOAD_ADDR: u32 = 0x0002_0000;
            if self.patch_linux_setup_header {
                // Must set to 4 for backwards compatibility.
                // https://docs.kernel.org/arch/x86/boot.html#the-real-mode-kernel-header
                bp.hdr.setup_sects = setup_sects;
                // Match QEMU's x86_load_linux() fw_cfg boot parameters.
                bp.hdr.type_of_loader = 0xb0;
                bp.hdr.loadflags |= 0x80;
                bp.hdr.heap_end_ptr =
                    (FW_CFG_CMDLINE_LOAD_ADDR - FW_CFG_SETUP_LOAD_ADDR - 0x200) as u16;
                bp.hdr.cmd_line_ptr = FW_CFG_CMDLINE_LOAD_ADDR;
            }
            let version = bp.hdr.version;
            let setup_sects = setup_sects;
            let type_of_loader = bp.hdr.type_of_loader;
            let loadflags = bp.hdr.loadflags;
            let heap_end_ptr = bp.hdr.heap_end_ptr;
            let cmd_line_ptr = bp.hdr.cmd_line_ptr;
            let initrd_addr_max = bp.hdr.initrd_addr_max;
            info!(
                "fw_cfg: linux setup protocol={:#x} setup_sects={} type_of_loader={:#x} loadflags={:#x} heap_end_ptr={:#x} cmd_line_ptr={:#x} initrd_addr_max={:#x}",
                version,
                setup_sects,
                type_of_loader,
                loadflags,
                heap_end_ptr,
                cmd_line_ptr,
                initrd_addr_max
            );
        }
        #[cfg(target_arch = "aarch64")]
        let kernel_start = bp.text_offset;
        #[cfg(target_arch = "x86_64")]
        let kernel_start = (setup_sects as usize + 1) * 512;

        #[cfg(target_arch = "x86_64")]
        if kernel_start <= buffer.len() {
            buffer.truncate(kernel_start);
        } else {
            buffer.resize(kernel_start, 0);
            file.read_exact_at(
                &mut buffer[size_of::<boot_params>()..],
                size_of::<boot_params>() as u64,
            )?;
        }

        #[cfg(target_arch = "x86_64")]
        {
            self.known_items[FW_CFG_SETUP_ADDR as usize] =
                FwCfgContent::U32(FW_CFG_SETUP_LOAD_ADDR);
            self.known_items[FW_CFG_KERNEL_ADDR as usize] =
                FwCfgContent::U32(FW_CFG_KERNEL_LOAD_ADDR);
        }
        self.known_items[FW_CFG_SETUP_SIZE as usize] = FwCfgContent::U32(buffer.len() as u32);
        self.known_items[FW_CFG_SETUP_DATA as usize] = FwCfgContent::Bytes(buffer);
        self.known_items[FW_CFG_KERNEL_SIZE as usize] =
            FwCfgContent::U32(file.metadata()?.len() as u32 - kernel_start as u32);
        self.known_items[FW_CFG_KERNEL_DATA as usize] =
            FwCfgContent::File(kernel_start as u64, file.try_clone()?);
        #[cfg(target_arch = "x86_64")]
        self.add_item(FwCfgItem {
            name: "etc/boot/kernel".to_string(),
            content: FwCfgContent::File(0, file.try_clone()?),
        })?;
        #[cfg(target_arch = "x86_64")]
        self.add_configured_option_roms()?;
        Ok(())
    }

    pub fn add_kernel_cmdline(&mut self, s: std::ffi::CString) {
        #[cfg(target_arch = "x86_64")]
        const FW_CFG_CMDLINE_LOAD_ADDR: u32 = 0x0002_0000;

        let bytes = s.into_bytes_with_nul();
        #[cfg(target_arch = "x86_64")]
        {
            self.known_items[FW_CFG_CMDLINE_ADDR as usize] =
                FwCfgContent::U32(FW_CFG_CMDLINE_LOAD_ADDR);
            if self.patch_linux_setup_header {
                self.update_setup_data(|bp| {
                    bp.hdr.cmd_line_ptr = FW_CFG_CMDLINE_LOAD_ADDR;
                });
            }
        }
        self.known_items[FW_CFG_CMDLINE_SIZE as usize] = FwCfgContent::U32(bytes.len() as u32);
        self.known_items[FW_CFG_CMDLINE_DATA as usize] = FwCfgContent::Bytes(bytes);
    }

    pub fn add_acpi(
        &mut self,
        rsdp: Vec<u8>,
        tables: Vec<u8>,
        table_checksums: Vec<(usize, usize)>,
        table_pointers: Vec<(usize, u8)>,
    ) -> Result<()> {
        let acpi_table = AcpiTable {
            rsdp,
            tables,
            table_checksums,
            table_pointers,
        };
        let [table_loader, acpi_rsdp, apci_tables] = create_acpi_loader(acpi_table);
        self.add_item(table_loader)?;
        self.add_item(acpi_rsdp)?;
        self.add_item(apci_tables)
    }

    pub fn add_initramfs_data(&mut self, file: &File, mem_size: Option<usize>) -> Result<()> {
        // When mem_size is known we already compute a precise ceiling
        // from `min(size, MEM_32BIT_DEVICES_START) - Q35_ACPI_DATA_RESERVED_SIZE`.
        // Only the `mem_size = None` path uses this fallback, which
        // historically pinned the load_end at 0x1f00_0000 (~496 MiB)
        // — fine for the original 512 MiB TDX test images but too low
        // for production initramfs blobs (Phala host stacks, NixOS
        // rescue images, dracut+kmods on Ubuntu cloud images), which
        // routinely exceed 480 MiB and silently overflow.
        //
        // Replace the constant with `Q35_LOWMEM_END - 4 MiB`. That is
        // the architectural ceiling for any q35 lowmem allocation:
        // beyond `Q35_LOWMEM_END` the address space belongs to PCI
        // MMIO and the PCI MMCFG window, where the initramfs cannot
        // live regardless of guest RAM size. A 4 MiB headroom is
        // generous enough for page alignment and trailing zero-page
        // bookkeeping while still leaving ~2 GiB of usable load space.
        // The minimal-tdx-image path (512 MiB RAM) hits the
        // `mem_size = Some(...)` branch, so this fallback only matters
        // for callers that genuinely lack mem_size information.
        #[cfg(target_arch = "x86_64")]
        const FW_CFG_INITRD_LOAD_END_HEADROOM: u64 = 4 << 20;

        let initramfs_size = file.metadata()?.len();
        #[cfg(target_arch = "x86_64")]
        {
            let initrd_load_end = mem_size
                .and_then(|size| {
                    let below_4g = std::cmp::min(size as u64, MEM_32BIT_DEVICES_START.0);
                    below_4g
                        .checked_sub(Q35_ACPI_DATA_RESERVED_SIZE as u64)?
                        .checked_sub(1)
                })
                .filter(|end| *end <= u32::MAX as u64)
                .map(|end| end as u32)
                .unwrap_or_else(|| {
                    // mem_size unknown: derive from Q35_LOWMEM_END so
                    // we get a usable ~2 GiB ceiling instead of the
                    // legacy 496 MiB constant.
                    let q35_lowmem_top = arch::layout::Q35_LOWMEM_END.0;
                    let end = q35_lowmem_top.saturating_sub(FW_CFG_INITRD_LOAD_END_HEADROOM);
                    let end = end.saturating_sub(1);
                    debug_assert!(end <= u32::MAX as u64);
                    end as u32
                });
            let initramfs_addr = (initrd_load_end - initramfs_size as u32) & !0xfff;
            self.known_items[FW_CFG_INITRD_ADDR as usize] = FwCfgContent::U32(initramfs_addr);
            if self.patch_linux_setup_header {
                self.update_setup_data(|bp| {
                    bp.hdr.ramdisk_image = initramfs_addr;
                    bp.hdr.ramdisk_size = initramfs_size as u32;
                });
            }
            info!(
                "fw_cfg: initrd addr={:#x} size={:#x} load_end={:#x}",
                initramfs_addr, initramfs_size, initrd_load_end
            );
        }
        self.known_items[FW_CFG_INITRD_SIZE as usize] = FwCfgContent::U32(initramfs_size as _);
        self.known_items[FW_CFG_INITRD_DATA as usize] = FwCfgContent::File(0, file.try_clone()?);
        Ok(())
    }

    fn read_content(content: &FwCfgContent, offset: u32, data: &mut [u8], size: u32) -> Option<u8> {
        let start = offset as usize;
        let end = start + size as usize;
        match content {
            FwCfgContent::Bytes(b) => {
                if b.len() >= size as usize {
                    data.copy_from_slice(&b[start..end]);
                }
            }
            FwCfgContent::Slice(s) => {
                if s.len() >= size as usize {
                    data.copy_from_slice(&s[start..end]);
                }
            }
            FwCfgContent::File(o, f) => {
                f.read_exact_at(data, o + offset as u64).ok()?;
            }
            FwCfgContent::U32(n) => {
                let bytes = n.to_le_bytes();
                data.copy_from_slice(&bytes[start..end]);
            }
        }
        Some(size as u8)
    }

    fn read_data(&mut self, data: &mut [u8], size: u32) -> u8 {
        let ret = if let Some(content) = self.known_content(self.selector) {
            Self::read_content(content, self.data_offset, data, size)
        } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize) {
            Self::read_content(&item.content, self.data_offset, data, size)
        } else {
            error!("fw_cfg: selector {:#x} does not exist.", self.selector);
            None
        };
        if let Some(val) = ret {
            self.data_offset += size;
            val
        } else {
            0
        }
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let port = offset + PORT_FW_CFG_BASE;
        let size = data.len();
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, _) => {
                error!("fw_cfg: selector register is write-only.");
            }
            (PORT_FW_CFG_DATA, _) => _ = self.read_data(data, size as u32),
            (PORT_FW_CFG_DMA_HI, 4) => {
                let addr = self.dma_address;
                let addr_hi = (addr >> 32) as u32;
                data.copy_from_slice(&addr_hi.to_be_bytes());
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                let addr = self.dma_address;
                let addr_lo = (addr & 0xffff_ffff) as u32;
                data.copy_from_slice(&addr_lo.to_be_bytes());
            }
            _ => {
                debug!(
                    "fw_cfg: read from unknown port {port:#x}: {size:#x} bytes and offset {offset:#x}."
                );
            }
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let port = offset + PORT_FW_CFG_BASE;
        let size = data.size();
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, 2) => {
                let mut buf = [0u8; 2];
                buf[..size].copy_from_slice(&data[..size]);
                #[cfg(target_arch = "x86_64")]
                let val = u16::from_le_bytes(buf);
                #[cfg(target_arch = "aarch64")]
                let val = u16::from_be_bytes(buf);
                self.selector = val;
                self.data_offset = 0;
            }
            (PORT_FW_CFG_DATA, 1) => error!("fw_cfg: data register is read-only."),
            (PORT_FW_CFG_DMA_HI, 4) => {
                let mut buf = [0u8; 4];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u32::from_be_bytes(buf);
                self.dma_address &= 0xffff_ffff;
                self.dma_address |= (val as u64) << 32;
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                let mut buf = [0u8; 4];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u32::from_be_bytes(buf);
                self.dma_address &= !0xffff_ffff;
                self.dma_address |= val as u64;
                self.do_dma();
            }
            _ => debug!(
                "fw_cfg: write to unknown port {port:#x}: {size:#x} bytes and offset {offset:#x} ."
            ),
        }
        None
    }
}

#[cfg(test)]
mod unit_tests {
    use std::ffi::CString;
    use std::io::Write;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[cfg(target_arch = "x86_64")]
    const SELECTOR_OFFSET: u64 = 0;
    #[cfg(target_arch = "aarch64")]
    const SELECTOR_OFFSET: u64 = 8;
    #[cfg(target_arch = "x86_64")]
    const DATA_OFFSET: u64 = 1;
    #[cfg(target_arch = "aarch64")]
    const DATA_OFFSET: u64 = 0;
    #[cfg(target_arch = "x86_64")]
    const DMA_OFFSET: u64 = 4;
    #[cfg(target_arch = "aarch64")]
    const DMA_OFFSET: u64 = 16;

    #[test]
    fn test_signature() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let mut data = vec![0u8];

        let mut sig_iter = FW_CFG_SIGNATURE_VALUE.into_iter();
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        loop {
            if let Some(char) = sig_iter.next() {
                fw_cfg.read(0, DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }
    #[test]
    fn test_kernel_cmdline() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let cmdline = *b"cmdline\0";

        fw_cfg.add_kernel_cmdline(CString::from_vec_with_nul(cmdline.to_vec()).unwrap());

        let mut data = vec![0u8];

        let mut cmdline_iter = cmdline.into_iter();
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_CMDLINE_DATA as u8, 0]);
        loop {
            if let Some(char) = cmdline_iter.next() {
                fw_cfg.read(0, DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_initram_fs() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let temp = TempFile::new().unwrap();
        let mut temp_file = temp.as_file();

        let initram_content = b"this is the initramfs";
        let written = temp_file.write(initram_content);
        assert_eq!(written.unwrap(), 21);
        let _ = fw_cfg.add_initramfs_data(temp_file, None);

        let mut data = vec![0u8];

        let mut initram_iter = (*initram_content).into_iter();
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_INITRD_DATA as u8, 0]);
        loop {
            if let Some(char) = initram_iter.next() {
                fw_cfg.read(0, DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_string_item() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        // Simulate OVMF X-PciMmio64Mb string item for GPU CC passthrough
        let item = FwCfgItem {
            name: "opt/ovmf/X-PciMmio64Mb".to_owned(),
            content: FwCfgContent::Bytes("262144".as_bytes().to_vec()),
        };
        fw_cfg.add_item(item).unwrap();

        let expected = b"262144";
        let mut data = vec![0u8];

        // Select the first file item (FW_CFG_FILE_FIRST = 0x20)
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_FILE_FIRST as u8, 0]);
        for &byte in expected.iter() {
            fw_cfg.read(0, DATA_OFFSET, &mut data);
            assert_eq!(data[0], byte);
        }
    }

    #[test]
    fn test_dma() {
        let code = [
            0xba, 0xf8, 0x03, 0x00, 0xd8, 0x04, b'0', 0xee, 0xb0, b'\n', 0xee, 0xf4,
        ];

        let content = FwCfgContent::Bytes(code.to_vec());

        let mem_size = 0x1000;
        let load_addr = GuestAddress(0x1000);
        let mem: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&[(load_addr, mem_size)]).unwrap();

        // Note: In firmware we would just allocate FwCfgDmaAccess struct
        // and use address of struct (&) as dma address
        let mut access_control = AccessControl(0);
        // bit 1 = read access
        access_control.set_read(true);
        // length of data to access
        let length_be = (code.len() as u32).to_be();
        // guest address for data
        let code_address = 0x1900_u64;
        let address_be = code_address.to_be();
        let mut access = FwCfgDmaAccess {
            control_be: access_control.0.to_be(), // bit(1) = read bit
            length_be,
            address_be,
        };
        // access address is where to put the code
        let access_address = GuestAddress(load_addr.0);
        let address_bytes = access_address.0.to_be_bytes();
        let dma_lo: [u8; 4] = address_bytes[0..4].try_into().unwrap();
        let dma_hi: [u8; 4] = address_bytes[4..8].try_into().unwrap();

        // writing the FwCfgDmaAccess to mem (this would just be self.dma_access.as_ref() in guest)
        let _ = mem.write(access.as_mut_bytes(), access_address);
        let mem_m = GuestMemoryAtomic::new(mem.clone());
        let mut fw_cfg = FwCfg::new(mem_m);
        let cfg_item = FwCfgItem {
            name: "code".to_string(),
            content,
        };
        let _ = fw_cfg.add_item(cfg_item);

        let mut data = [0u8; 12];

        let _ = mem.read(&mut data, GuestAddress(code_address));
        assert_ne!(data, code);

        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_FILE_FIRST as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET, &dma_lo);
        fw_cfg.write(0, DMA_OFFSET + 4, &dma_hi);
        let _ = mem.read(&mut data, GuestAddress(code_address));
        assert_eq!(data, code);
    }

    /// With no SMBIOS overrides, the emitted blob must remain byte-for-byte
    /// identical to the historical CH default produced before this change
    /// (commit `caf3a5861`). Any drift here would shift TDX measurements
    /// for already-deployed guests, which is the explicit non-goal of the
    /// CLI plumbing introduced alongside this test.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_smbios_default_byte_compat() {
        let (anchor, tables) = build_qemu_compat_smbios(None, 0);

        // Anchor: "_SM3_" + checksum + entry-point length + version
        // (3.0.0) — exactly what `caf3a5861` shipped.
        assert_eq!(anchor.len(), Q35_SMBIOS_ANCHOR_SIZE);
        assert_eq!(&anchor[0..5], b"_SM3_");
        assert_eq!(anchor[6] as usize, Q35_SMBIOS_ANCHOR_SIZE);
        assert_eq!(anchor[7], 1); // ep_revision
        assert_eq!(anchor[8], 3); // smbios major
        assert_eq!(anchor[9], 0); // smbios minor
        assert_eq!(anchor[10], 0); // smbios docrev
        let tables_len = u32::from_le_bytes(anchor[12..16].try_into().unwrap());
        assert_eq!(tables_len as usize, tables.len());
        // Anchor checksum: byte 5 fixes the running sum to 0
        let sum: u8 = anchor.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        assert_eq!(sum, 0);

        // Reproduce the pre-change blob verbatim and compare.
        let mut expected = Vec::new();
        let mut bios_info = vec![0u8; 0x18 - 4];
        bios_info[0] = 1;
        bios_info[1] = 2;
        bios_info[2..4].copy_from_slice(&0xe800u16.to_le_bytes());
        bios_info[4] = 3;
        expected.extend_from_slice(&smbios_table(
            0,
            0x0000,
            &bios_info,
            &[
                CH_SMBIOS_BIOS_VENDOR,
                CH_SMBIOS_BIOS_VERSION,
                CH_SMBIOS_BIOS_RELEASE_DATE,
            ],
        ));
        let mut system_info = vec![0u8; 0x1b - 4];
        system_info[0] = 1;
        system_info[1] = 2;
        system_info[0x14] = 0x06;
        expected.extend_from_slice(&smbios_table(
            1,
            0x0100,
            &system_info,
            &[CH_SMBIOS_SYSTEM_MANUFACTURER, CH_SMBIOS_SYSTEM_PRODUCT],
        ));
        expected.extend_from_slice(&smbios_table(127, 0x7f00, &[], &[]));
        expected.resize(Q35_SMBIOS_TABLES_SIZE, 0);

        assert_eq!(
            tables, expected,
            "default SMBIOS emission diverged from the caf3a5861 layout: \
             TDX measurements for guests booted with no `--platform smbios.*` \
             overrides would shift",
        );
    }

    /// Override every string-bearing field and verify each byte lands at
    /// the SMBIOS-spec offset for its table. This guards against silent
    /// off-by-one drift in `build_qemu_compat_smbios` and proves the
    /// extended tables (3/4/11/17/32) are emitted when overrides are
    /// supplied.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_smbios_overrides_present() {
        let overrides = FwCfgSmbiosOverrides {
            bios_vendor: Some("CustomVendor".to_string()),
            bios_version: Some("0.1.2".to_string()),
            bios_release_date: Some("12/31/2025".to_string()),
            system_manufacturer: Some("CustomMfr".to_string()),
            system_product: Some("CustomProduct".to_string()),
            system_version: Some("v1".to_string()),
            system_serial: Some("SN-1234".to_string()),
            system_uuid: Some([
                0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
                0x9a, 0xbc,
            ]),
            system_sku: Some("SKU-A".to_string()),
            system_family: Some("FamilyZ".to_string()),
            chassis_manufacturer: Some("ChassisMfr".to_string()),
            chassis_version: Some("CV1".to_string()),
            chassis_serial: Some("CS1".to_string()),
            chassis_asset_tag: Some("CAT1".to_string()),
            processor_manufacturer: Some("CPUMfr".to_string()),
            processor_version: Some("CPUV1".to_string()),
            oem_strings: Some(vec!["oem-a".to_string(), "oem-b".to_string()]),
        };
        let total_memory_size: u64 = 4 * 1024 * 1024 * 1024; // 4 GB
        let (_anchor, tables) =
            build_qemu_compat_smbios(Some(&overrides), total_memory_size);

        // Helper: scan for an SMBIOS structure with the given type byte.
        // Each structure starts with [type, length, handle_lo, handle_hi]
        // followed by `length - 4` formatted bytes and a double-NUL
        // terminated string heap.
        fn find_table<'a>(blob: &'a [u8], wanted_type: u8) -> &'a [u8] {
            let mut i = 0;
            while i + 4 <= blob.len() {
                let ty = blob[i];
                let len = blob[i + 1] as usize;
                // A length of zero means we have walked off the end of
                // the populated tables into the zero-padded tail.
                if len == 0 {
                    break;
                }
                let formatted_end = i + len;
                // Find the trailing double-NUL terminator that follows
                // the variable-length string heap.
                let mut j = formatted_end;
                while j + 1 < blob.len() {
                    if blob[j] == 0 && blob[j + 1] == 0 {
                        j += 2;
                        break;
                    }
                    j += 1;
                }
                if ty == wanted_type {
                    return &blob[i..j];
                }
                i = j;
            }
            panic!("SMBIOS table type {wanted_type} not found");
        }

        // Type 0 BIOS Information: vendor+version+date strings present.
        let t0 = find_table(&tables, 0);
        assert!(
            t0.windows(b"CustomVendor".len())
                .any(|w| w == b"CustomVendor"),
        );
        assert!(t0.windows(b"0.1.2".len()).any(|w| w == b"0.1.2"));
        assert!(t0.windows(b"12/31/2025".len()).any(|w| w == b"12/31/2025"));

        // Type 1 System Information: UUID at offset 4..20 must be the
        // wire-format byte-flipped 16 bytes (SMBIOS 2.6+).
        let t1 = find_table(&tables, 1);
        let raw_uuid = [
            0x12u8, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc,
        ];
        let mut expected_uuid = raw_uuid;
        expected_uuid.swap(0, 3);
        expected_uuid.swap(1, 2);
        expected_uuid.swap(4, 5);
        expected_uuid.swap(6, 7);
        // Header is 4 bytes; UUID lives at formatted offset 4 -> table byte 8.
        assert_eq!(&t1[8..8 + 16], &expected_uuid);
        assert!(t1.windows(b"CustomMfr".len()).any(|w| w == b"CustomMfr"));
        assert!(t1.windows(b"FamilyZ".len()).any(|w| w == b"FamilyZ"));

        // Type 3 Chassis: manufacturer + asset tag.
        let t3 = find_table(&tables, 3);
        assert!(
            t3.windows(b"ChassisMfr".len())
                .any(|w| w == b"ChassisMfr"),
        );
        assert!(t3.windows(b"CAT1".len()).any(|w| w == b"CAT1"));
        // type byte at formatted offset 1 (table byte 5) = 0x01 (Other)
        assert_eq!(t3[5], 0x01);

        // Type 4 Processor: status byte at formatted offset 20 (table 24)
        // must be 0x41 (socket populated, CPU enabled).
        let t4 = find_table(&tables, 4);
        assert_eq!(t4[24], 0x41);
        assert!(t4.windows(b"CPUMfr".len()).any(|w| w == b"CPUMfr"));
        assert!(t4.windows(b"CPUV1".len()).any(|w| w == b"CPUV1"));

        // Type 11 OEM strings: count byte = 2, both strings present.
        let t11 = find_table(&tables, 11);
        assert_eq!(t11[4], 2);
        assert!(t11.windows(b"oem-a".len()).any(|w| w == b"oem-a"));
        assert!(t11.windows(b"oem-b".len()).any(|w| w == b"oem-b"));

        // Type 17 Memory Device: 4 GB -> size_mb = 4096 fits in 16-bit
        // standard field (4096 < 0x7fff), so size = 4096 LE, ext = 0.
        let t17 = find_table(&tables, 17);
        let size_field = u16::from_le_bytes([t17[12], t17[13]]);
        assert_eq!(size_field, 4096);
        let ext_size = u32::from_le_bytes([t17[28], t17[29], t17[30], t17[31]]);
        assert_eq!(ext_size, 0);

        // Type 32 Boot info: 6 reserved zero bytes + boot_status = 0.
        let t32 = find_table(&tables, 32);
        for byte in &t32[4..4 + 7] {
            assert_eq!(*byte, 0);
        }
    }

    /// `smbios.system_uuid` accepts both canonical dashed form and bare
    /// 32 hex chars. After SMBIOS Wired-For-Management byte-flipping
    /// (per SMBIOS 2.6+), the first three fields land little-endian.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_smbios_uuid_byte_flip() {
        // RFC 4122 big-endian bytes for "12345678-1234-1234-1234-123456789abc"
        let raw: [u8; 16] = [
            0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc,
        ];
        let flipped = smbios_encode_uuid(&raw);
        assert_eq!(
            flipped,
            [
                // time_low (LE)
                0x78, 0x56, 0x34, 0x12,
                // time_mid (LE)
                0x34, 0x12,
                // time_hi_and_version (LE)
                0x34, 0x12,
                // clock_seq_hi/low + node (unchanged)
                0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            ]
        );
    }
}
