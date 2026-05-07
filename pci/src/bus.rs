// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::any::Any;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::{Arc, Barrier, Mutex};

use arch::q35_pci_ids::{
    DEVICE_ID_INTEL_I440FX_HOST_BRIDGE, DEVICE_ID_INTEL_ICH9_AHCI, DEVICE_ID_INTEL_ICH9_LPC,
    DEVICE_ID_INTEL_ICH9_SMBUS, DEVICE_ID_INTEL_P35_MCH, DEVICE_ID_INTEL_VIRT_PCIE_HOST,
    ICH9_AHCI_MSI_CAP_REG, ICH9_AHCI_SATA_CAP_REG, ICH9_LPC_ACPI_CTRL_REG, ICH9_LPC_IO_DEC_REG,
    ICH9_LPC_PIRQA_ROUT_REG, ICH9_LPC_PIRQE_ROUT_REG, ICH9_LPC_PMBASE_REG, ICH9_LPC_RCBA_REG,
    PCI_BAR4_REG, PCI_CAPABILITY_LIST_REG, PCI_COMMAND_STATUS_REG, PCI_HEADER_TYPE_MULTIFUNCTION,
    PCI_HEADER_TYPE_REG, PCI_INTERRUPT_REG, PCI_STATUS_CAPABILITIES, Q35_PCIEXBAR_DEFAULT,
    Q35_PCIEXBAR_HIGH_WRITABLE_BITS, Q35_PCIEXBAR_LOW_WRITABLE_BITS, Q35_PCIEXBAR_REG,
    VENDOR_ID_INTEL,
};
use byteorder::{ByteOrder, LittleEndian};
use log::warn;
use thiserror::Error;
use vm_device::{Bus, BusDevice, BusDeviceSync};

use crate::PciBarConfiguration;
use crate::configuration::{
    PciBarRegionType, PciBridgeSubclass, PciClassCode, PciConfiguration, PciHeaderType,
    PciMassStorageSubclass, PciProgrammingInterface, PciSerialBusSubClass,
};
use crate::device::{BarReprogrammingParams, DeviceRelocation, Error as PciDeviceError, PciDevice};

/// Denotes the PCI device ID of a bus' root bridge device.
pub const PCI_ROOT_DEVICE_ID: u8 = 0;
/// Denotes the maximum number of PCI devices allowed on a bus. 32 per PCI spec.
pub const NUM_DEVICE_IDS: u8 = 32;

struct AhciProgrammingInterface;

impl PciProgrammingInterface for AhciProgrammingInterface {
    fn get_register_value(&self) -> u8 {
        0x01
    }
}

/// Errors for device manager.
#[derive(Error, Debug)]
pub enum PciRootError {
    /// Could not allocate device address space for the device.
    #[error("Could not allocate device address space for the device")]
    AllocateDeviceAddrs(#[source] PciDeviceError),
    /// Could not allocate an IRQ number.
    #[error("Could not allocate an IRQ number")]
    AllocateIrq,
    /// Could not add a device to the port io bus.
    #[error("Could not add a device to the port io bus")]
    PioInsert(#[source] vm_device::BusError),
    /// Could not add a device to the mmio bus.
    #[error("Could not add a device to the mmio bus")]
    MmioInsert(#[source] vm_device::BusError),
    /// Could not find an available device slot on the PCI bus.
    #[error("Could not find an available device slot on the PCI bus")]
    NoPciDeviceSlotAvailable,
    /// Invalid PCI device identifier provided.
    #[error("Invalid PCI device identifier provided: {0}")]
    InvalidPciDeviceSlot(usize),
    /// Valid PCI device identifier but already used.
    #[error("Valid PCI device identifier but already used: {0}")]
    AlreadyInUsePciDeviceSlot(usize),
}
pub type Result<T> = std::result::Result<T, PciRootError>;

/// Emulates the PCI Root bridge device.
pub struct PciRoot {
    /// Configuration space.
    config: PciConfiguration,
}

impl PciRoot {
    /// Create an empty PCI root bridge.
    pub fn new(config: Option<PciConfiguration>) -> Self {
        if let Some(config) = config {
            PciRoot { config }
        } else {
            PciRoot {
                config: PciConfiguration::new(
                    VENDOR_ID_INTEL,
                    DEVICE_ID_INTEL_VIRT_PCIE_HOST,
                    0,
                    PciClassCode::BridgeDevice,
                    &PciBridgeSubclass::HostBridge,
                    None,
                    PciHeaderType::Device,
                    0,
                    0,
                    None,
                    None,
                ),
            }
        }
    }

    /// Create a QEMU q35-compatible MCH host bridge.
    pub fn new_q35() -> Self {
        let mut config = PciConfiguration::new(
            VENDOR_ID_INTEL,
            DEVICE_ID_INTEL_P35_MCH,
            0,
            PciClassCode::BridgeDevice,
            &PciBridgeSubclass::HostBridge,
            None,
            PciHeaderType::Device,
            0,
            0,
            None,
            None,
        );

        config.set_reg(Q35_PCIEXBAR_REG, Q35_PCIEXBAR_DEFAULT);
        config.set_writable_bits(Q35_PCIEXBAR_REG, Q35_PCIEXBAR_LOW_WRITABLE_BITS);
        config.set_writable_bits(Q35_PCIEXBAR_REG + 1, Q35_PCIEXBAR_HIGH_WRITABLE_BITS);

        PciRoot { config }
    }

    /// Create a QEMU i440fx-compatible host bridge.
    pub fn new_i440fx() -> Self {
        PciRoot {
            config: PciConfiguration::new(
                VENDOR_ID_INTEL,
                DEVICE_ID_INTEL_I440FX_HOST_BRIDGE,
                2,
                PciClassCode::BridgeDevice,
                &PciBridgeSubclass::HostBridge,
                None,
                PciHeaderType::Device,
                0,
                0,
                None,
                None,
            ),
        }
    }
}

impl BusDevice for PciRoot {}

impl PciDevice for PciRoot {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        (
            self.config.write_config_register(reg_idx, offset, data),
            None,
        )
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        None
    }
}

/// Minimal QEMU q35-compatible ICH9 LPC/ISA bridge at 00:1f.0.
pub struct PciLpcBridge {
    config: PciConfiguration,
}

impl PciLpcBridge {
    pub fn new_ich9() -> Self {
        let mut config = PciConfiguration::new(
            VENDOR_ID_INTEL,
            DEVICE_ID_INTEL_ICH9_LPC,
            2,
            PciClassCode::BridgeDevice,
            &PciBridgeSubclass::IsaBridge,
            None,
            PciHeaderType::Device,
            0,
            0,
            None,
            None,
        );

        config.set_reg(
            PCI_HEADER_TYPE_REG,
            config.read_reg(PCI_HEADER_TYPE_REG) | PCI_HEADER_TYPE_MULTIFUNCTION,
        );
        config.set_reg(ICH9_LPC_PMBASE_REG, 0x0000_0001);
        config.set_writable_bits(ICH9_LPC_PMBASE_REG, 0xffff_ff80);
        config.set_reg(ICH9_LPC_ACPI_CTRL_REG, 0);
        config.set_writable_bits(ICH9_LPC_ACPI_CTRL_REG, 0x0000_0087);
        config.set_reg(ICH9_LPC_PIRQA_ROUT_REG, 0x8080_8080);
        config.set_reg(ICH9_LPC_PIRQE_ROUT_REG, 0x8080_8080);
        config.set_writable_bits(ICH9_LPC_PIRQA_ROUT_REG, 0xffff_ffff);
        config.set_writable_bits(ICH9_LPC_PIRQE_ROUT_REG, 0xffff_ffff);
        // QEMU marks an ISA serial port as decoded in ICH9 LPC config byte
        // 0x82 only when the corresponding I/O region is present. Cloud
        // Hypervisor exposes the primary serial device at 0x3f8 and does not
        // install an absent COM2 stub at 0x2f8.
        config.set_reg(ICH9_LPC_IO_DEC_REG, 0x0001_0000);
        config.set_reg(ICH9_LPC_RCBA_REG, 0);
        config.set_writable_bits(ICH9_LPC_RCBA_REG, 0xffff_c001);

        PciLpcBridge { config }
    }
}

impl BusDevice for PciLpcBridge {}

impl PciDevice for PciLpcBridge {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        (
            self.config.write_config_register(reg_idx, offset, data),
            None,
        )
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        None
    }
}

/// Minimal q35 ICH9 AHCI function at 00:1f.2.
pub struct PciQ35Ahci {
    config: PciConfiguration,
}

impl PciQ35Ahci {
    pub fn new() -> Self {
        let ahci_pi = AhciProgrammingInterface;
        let mut config = PciConfiguration::new(
            VENDOR_ID_INTEL,
            DEVICE_ID_INTEL_ICH9_AHCI,
            2,
            PciClassCode::MassStorage,
            &PciMassStorageSubclass::SataController,
            Some(&ahci_pi),
            PciHeaderType::Device,
            0x1af4,
            0x1100,
            None,
            None,
        );
        config.set_reg(
            PCI_HEADER_TYPE_REG,
            config.read_reg(PCI_HEADER_TYPE_REG) | PCI_HEADER_TYPE_MULTIFUNCTION,
        );
        config.set_reg(
            PCI_COMMAND_STATUS_REG,
            config.read_reg(PCI_COMMAND_STATUS_REG) | PCI_STATUS_CAPABILITIES,
        );
        config.set_reg(PCI_BAR4_REG, 0x0000_0001);
        config.set_reg(PCI_CAPABILITY_LIST_REG, 0x0000_0080);
        config.set_reg(PCI_INTERRUPT_REG, 0x0000_0100);
        config.set_reg(ICH9_AHCI_MSI_CAP_REG, 0x0000_a805);
        config.set_reg(ICH9_AHCI_SATA_CAP_REG, 0x0000_0012);

        PciQ35Ahci { config }
    }
}

impl BusDevice for PciQ35Ahci {}

impl PciDevice for PciQ35Ahci {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        (
            self.config.write_config_register(reg_idx, offset, data),
            None,
        )
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        None
    }
}

/// Minimal q35 ICH9 SMBus function at 00:1f.3.
pub struct PciQ35Smbus {
    config: PciConfiguration,
}

impl PciQ35Smbus {
    pub fn new() -> Self {
        let mut config = PciConfiguration::new(
            VENDOR_ID_INTEL,
            DEVICE_ID_INTEL_ICH9_SMBUS,
            2,
            PciClassCode::SerialBusController,
            &PciSerialBusSubClass::Smbus,
            None,
            PciHeaderType::Device,
            0x1af4,
            0x1100,
            None,
            None,
        );
        config.set_reg(
            PCI_HEADER_TYPE_REG,
            config.read_reg(PCI_HEADER_TYPE_REG) | PCI_HEADER_TYPE_MULTIFUNCTION,
        );
        config.set_reg(PCI_BAR4_REG, 0x0000_0001);
        config.set_reg(PCI_INTERRUPT_REG, 0x0000_0100);

        PciQ35Smbus { config }
    }
}

impl BusDevice for PciQ35Smbus {}

impl PciDevice for PciQ35Smbus {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        (
            self.config.write_config_register(reg_idx, offset, data),
            None,
        )
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeviceIdState {
    Free,
    Reserved,
    Allocated,
}

pub struct PciBus {
    /// Devices attached to this bus.
    /// Device 0 is host bridge.
    devices: HashMap<(u8, u8), Arc<Mutex<dyn PciDevice>>>,
    device_reloc: Arc<dyn DeviceRelocation>,
    device_ids: [DeviceIdState; NUM_DEVICE_IDS as usize],
}

impl PciBus {
    pub fn new(pci_root: PciRoot, device_reloc: Arc<dyn DeviceRelocation>) -> Self {
        let mut devices: HashMap<(u8, u8), Arc<Mutex<dyn PciDevice>>> = HashMap::new();
        let mut device_ids = [DeviceIdState::Free; NUM_DEVICE_IDS as usize];

        devices.insert((PCI_ROOT_DEVICE_ID, 0), Arc::new(Mutex::new(pci_root)));
        device_ids[PCI_ROOT_DEVICE_ID as usize] = DeviceIdState::Allocated;

        PciBus {
            devices,
            device_reloc,
            device_ids,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn register_mapping(
        &self,
        dev: Arc<dyn BusDeviceSync>,
        io_bus: &Bus,
        mmio_bus: &Bus,
        bars: Vec<PciBarConfiguration>,
    ) -> Result<()> {
        for bar in bars {
            match bar.region_type() {
                PciBarRegionType::IoRegion => {
                    io_bus
                        .insert(dev.clone(), bar.addr(), bar.size())
                        .map_err(PciRootError::PioInsert)?;
                }
                PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => {
                    mmio_bus
                        .insert(dev.clone(), bar.addr(), bar.size())
                        .map_err(PciRootError::MmioInsert)?;
                }
            }
        }
        Ok(())
    }

    pub fn add_device(&mut self, device_id: u8, device: Arc<Mutex<dyn PciDevice>>) -> Result<()> {
        self.add_device_function(device_id, 0, device)
    }

    pub fn add_device_function(
        &mut self,
        device_id: u8,
        function: u8,
        device: Arc<Mutex<dyn PciDevice>>,
    ) -> Result<()> {
        if device_id >= NUM_DEVICE_IDS || function > 7 {
            return Err(PciRootError::InvalidPciDeviceSlot(device_id as usize));
        }

        self.devices.insert((device_id, function), device);
        Ok(())
    }

    pub fn remove_by_device(&mut self, device: &Arc<Mutex<dyn PciDevice>>) -> Result<()> {
        self.devices.retain(|_, dev| !Arc::ptr_eq(dev, device));
        Ok(())
    }

    /// Reserves a PCI device ID on the bus, marking it as in-use so
    /// that automatic allocation will not use it.
    ///
    /// - `id`: Preferred ID to reserve on the bus.
    ///
    /// ## Errors
    ///
    /// * Returns [`PciRootError::AlreadyInUsePciDeviceSlot`] if the
    ///   slot is already reserved or allocated.
    /// * Returns [`PciRootError::InvalidPciDeviceSlot`] if the slot
    ///   exceeds [`NUM_DEVICE_IDS`].
    pub fn reserve_device_id(&mut self, id: u8) -> Result<u8> {
        let idx = id as usize;
        if idx < NUM_DEVICE_IDS as usize {
            if self.device_ids[idx] == DeviceIdState::Free {
                self.device_ids[idx] = DeviceIdState::Reserved;
                Ok(id)
            } else {
                Err(PciRootError::AlreadyInUsePciDeviceSlot(idx))
            }
        } else {
            Err(PciRootError::InvalidPciDeviceSlot(idx))
        }
    }

    /// Allocates a PCI device ID on the bus.
    ///
    /// - `id`: ID to allocate on the bus. If [`None`], the next free
    ///   device ID on the bus is allocated, else the ID given is
    ///   allocated
    ///
    /// ## Errors
    ///
    /// * Returns [`PciRootError::AlreadyInUsePciDeviceSlot`] in case
    ///   the ID requested is already allocated.
    /// * Returns [`PciRootError::InvalidPciDeviceSlot`] in case the
    ///   requested ID exceeds the maximum number of devices allowed per
    ///   bus (see [`NUM_DEVICE_IDS`]).
    /// * If `id` is [`None`]: Returns
    ///   [`PciRootError::NoPciDeviceSlotAvailable`] if no free device
    ///   slot is available on the bus.
    pub fn allocate_device_id(&mut self, id: Option<u8>) -> Result<u8> {
        if let Some(idx) = id.map(|i| i as usize) {
            if idx < NUM_DEVICE_IDS as usize {
                if self.device_ids[idx] == DeviceIdState::Allocated {
                    Err(PciRootError::AlreadyInUsePciDeviceSlot(idx))
                } else {
                    self.device_ids[idx] = DeviceIdState::Allocated;
                    Ok(idx as u8)
                }
            } else {
                Err(PciRootError::InvalidPciDeviceSlot(idx))
            }
        } else {
            for (idx, device_id) in self.device_ids.iter_mut().enumerate() {
                if *device_id == DeviceIdState::Free {
                    *device_id = DeviceIdState::Allocated;
                    return Ok(idx as u8);
                }
            }
            Err(PciRootError::NoPciDeviceSlotAvailable)
        }
    }

    /// Frees a PCI device ID on the bus.
    ///
    /// - `id`: ID to free on the bus.
    ///
    /// ## Errors
    /// * Returns [`PciRootError::InvalidPciDeviceSlot`] if the slot
    ///   exceeds [`NUM_DEVICE_IDS`].
    pub fn free_device_id(&mut self, id: u8) -> Result<()> {
        if id < NUM_DEVICE_IDS {
            self.device_ids[id as usize] = DeviceIdState::Free;
            Ok(())
        } else {
            Err(PciRootError::InvalidPciDeviceSlot(id as usize))
        }
    }
}

pub struct PciConfigIo {
    /// Config space register.
    config_address: u32,
    pci_bus: Arc<Mutex<PciBus>>,
}

impl PciConfigIo {
    pub fn new(pci_bus: Arc<Mutex<PciBus>>) -> Self {
        PciConfigIo {
            config_address: 0,
            pci_bus,
        }
    }

    pub fn config_space_read(&self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (bus, device, function, register) =
            parse_io_config_address(self.config_address & !0x8000_0000);

        // Only support one bus.
        if bus != 0 {
            return 0xffff_ffff;
        }

        self.pci_bus
            .as_ref()
            .lock()
            .unwrap()
            .devices
            .get(&(device as u8, function as u8))
            .map_or(0xffff_ffff, |d| {
                d.lock().unwrap().read_config_register(register)
            })
    }

    pub fn config_space_write(&mut self, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if offset as usize + data.len() > 4 {
            return None;
        }

        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return None;
        }

        let (bus, device, function, register) =
            parse_io_config_address(self.config_address & !0x8000_0000);

        // Only support one bus.
        if bus != 0 {
            return None;
        }

        let pci_bus = self.pci_bus.as_ref().lock().unwrap();
        if let Some(d) = pci_bus.devices.get(&(device as u8, function as u8)) {
            let mut device = d.lock().unwrap();

            // Update the register value
            let (bar_reprogram, ret) = device.write_config_register(register, offset, data);

            // Move the device's BAR if needed
            for params in &bar_reprogram {
                if let Err(e) = pci_bus.device_reloc.move_bar(
                    params.old_base,
                    params.new_base,
                    params.len,
                    device.deref_mut(),
                    params.region_type,
                ) {
                    warn!(
                        "Failed moving device BAR: {}: 0x{:x}->0x{:x}(0x{:x}), keeping old BAR",
                        e, params.old_base, params.new_base, params.len
                    );
                    // Rollback: the config register was already updated to
                    // new_base by detect_bar_reprogramming(). Restore it by
                    // writing back the old address so device state stays
                    // consistent with the MMIO bus mapping.
                    device.restore_bar_addr(params);
                }
            }

            ret
        } else {
            None
        }
    }

    fn set_config_address(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }
        let (mask, value): (u32, u32) = match data.len() {
            1 => (
                0x0000_00ff << (offset * 8),
                u32::from(data[0]) << (offset * 8),
            ),
            2 => (
                0x0000_ffff << (offset * 16),
                ((u32::from(data[1]) << 8) | u32::from(data[0])) << (offset * 16),
            ),
            4 => (0xffff_ffff, LittleEndian::read_u32(data)),
            _ => return,
        };
        self.config_address = (self.config_address & !mask) | value;
    }
}

impl BusDevice for PciConfigIo {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        // `offset` is relative to 0xcf8
        let value = match offset {
            0..=3 => self.config_address,
            4..=7 => self.config_space_read(),
            _ => 0xffff_ffff,
        };

        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end <= 4 {
            for i in start..end {
                data[i - start] = (value >> (i * 8)) as u8;
            }
        } else {
            for d in data {
                *d = 0xff;
            }
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        // `offset` is relative to 0xcf8
        match offset {
            o @ 0..=3 => {
                self.set_config_address(o, data);
                None
            }
            o @ 4..=7 => self.config_space_write(o - 4, data),
            _ => None,
        }
    }
}

/// Emulates PCI memory-mapped configuration access mechanism.
pub struct PciConfigMmio {
    pci_bus: Arc<Mutex<PciBus>>,
}

impl PciConfigMmio {
    pub fn new(pci_bus: Arc<Mutex<PciBus>>) -> Self {
        PciConfigMmio { pci_bus }
    }

    fn config_space_read(&self, config_address: u32) -> u32 {
        let (bus, device, function, register) = parse_mmio_config_address(config_address);

        // Only support one bus.
        if bus != 0 {
            return 0xffff_ffff;
        }

        self.pci_bus
            .lock()
            .unwrap()
            .devices
            .get(&(device as u8, function as u8))
            .map_or(0xffff_ffff, |d| {
                d.lock().unwrap().read_config_register(register)
            })
    }

    fn config_space_write(&mut self, config_address: u32, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }

        let (bus, device, function, register) = parse_mmio_config_address(config_address);

        // Only support one bus.
        if bus != 0 {
            return;
        }

        let pci_bus = self.pci_bus.lock().unwrap();
        if let Some(d) = pci_bus.devices.get(&(device as u8, function as u8)) {
            let mut device = d.lock().unwrap();

            // Update the register value
            let (bar_reprogram, _) = device.write_config_register(register, offset, data);

            // Move the device's BAR if needed
            for params in &bar_reprogram {
                if let Err(e) = pci_bus.device_reloc.move_bar(
                    params.old_base,
                    params.new_base,
                    params.len,
                    device.deref_mut(),
                    params.region_type,
                ) {
                    warn!(
                        "Failed moving device BAR: {}: 0x{:x}->0x{:x}(0x{:x}), keeping old BAR",
                        e, params.old_base, params.new_base, params.len
                    );
                    device.restore_bar_addr(params);
                }
            }
        }
    }
}

impl BusDevice for PciConfigMmio {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end > 4 || offset > u64::from(u32::MAX) {
            for d in data {
                *d = 0xff;
            }
            return;
        }

        let value = self.config_space_read(offset as u32);
        for i in start..end {
            data[i - start] = (value >> (i * 8)) as u8;
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if offset > u64::from(u32::MAX) {
            return None;
        }
        self.config_space_write(offset as u32, offset % 4, data);

        None
    }
}

fn shift_and_mask(value: u32, offset: usize, mask: u32) -> usize {
    ((value >> offset) & mask) as usize
}

// Parse the MMIO address offset to a (bus, device, function, register) tuple.
// See section 7.2.2 PCI Express Enhanced Configuration Access Mechanism (ECAM)
// from the Pci Express Base Specification Revision 5.0 Version 1.0.
fn parse_mmio_config_address(config_address: u32) -> (usize, usize, usize, usize) {
    const BUS_NUMBER_OFFSET: usize = 20;
    const BUS_NUMBER_MASK: u32 = 0x00ff;
    const DEVICE_NUMBER_OFFSET: usize = 15;
    const DEVICE_NUMBER_MASK: u32 = 0x1f;
    const FUNCTION_NUMBER_OFFSET: usize = 12;
    const FUNCTION_NUMBER_MASK: u32 = 0x07;
    const REGISTER_NUMBER_OFFSET: usize = 2;
    const REGISTER_NUMBER_MASK: u32 = 0x3ff;

    (
        shift_and_mask(config_address, BUS_NUMBER_OFFSET, BUS_NUMBER_MASK),
        shift_and_mask(config_address, DEVICE_NUMBER_OFFSET, DEVICE_NUMBER_MASK),
        shift_and_mask(config_address, FUNCTION_NUMBER_OFFSET, FUNCTION_NUMBER_MASK),
        shift_and_mask(config_address, REGISTER_NUMBER_OFFSET, REGISTER_NUMBER_MASK),
    )
}

// Parse the CONFIG_ADDRESS register to a (bus, device, function, register) tuple.
fn parse_io_config_address(config_address: u32) -> (usize, usize, usize, usize) {
    const BUS_NUMBER_OFFSET: usize = 16;
    const BUS_NUMBER_MASK: u32 = 0x00ff;
    const DEVICE_NUMBER_OFFSET: usize = 11;
    const DEVICE_NUMBER_MASK: u32 = 0x1f;
    const FUNCTION_NUMBER_OFFSET: usize = 8;
    const FUNCTION_NUMBER_MASK: u32 = 0x07;
    const REGISTER_NUMBER_OFFSET: usize = 2;
    const REGISTER_NUMBER_MASK: u32 = 0x3f;

    (
        shift_and_mask(config_address, BUS_NUMBER_OFFSET, BUS_NUMBER_MASK),
        shift_and_mask(config_address, DEVICE_NUMBER_OFFSET, DEVICE_NUMBER_MASK),
        shift_and_mask(config_address, FUNCTION_NUMBER_OFFSET, FUNCTION_NUMBER_MASK),
        shift_and_mask(config_address, REGISTER_NUMBER_OFFSET, REGISTER_NUMBER_MASK),
    )
}

#[cfg(test)]
mod unit_tests {
    use std::error::Error;
    use std::result::Result;

    use super::*;

    #[derive(Debug)]
    /// Helper struct that mocks the implementation of DeviceRelocation
    struct MockDeviceRelocation;

    impl DeviceRelocation for MockDeviceRelocation {
        fn move_bar(
            &self,
            _old_base: u64,
            _new_base: u64,
            _len: u64,
            _pci_dev: &mut dyn PciDevice,
            _region_type: PciBarRegionType,
        ) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    fn setup_bus() -> PciBus {
        let pci_root = PciRoot::new(None);
        let mock_device_reloc = Arc::new(MockDeviceRelocation {});
        PciBus::new(pci_root, mock_device_reloc)
    }

    #[test]
    // Test to acquire all IDs that can be acquired
    fn allocate_device_id_next_free() {
        // The first address is occupied by the root
        let mut bus = setup_bus();
        for expected_id in 1..NUM_DEVICE_IDS {
            assert_eq!(expected_id, bus.allocate_device_id(None).unwrap());
        }
    }

    #[test]
    // Test that requesting specific ID work
    fn allocate_device_id_request_id() -> Result<(), Box<dyn Error>> {
        // The first address is occupied by the root
        let mut bus = setup_bus();
        let max_id = NUM_DEVICE_IDS - 1;
        assert_eq!(0x01_u8, bus.allocate_device_id(Some(0x01))?);
        assert_eq!(0x10_u8, bus.allocate_device_id(Some(0x10))?);
        assert_eq!(max_id, bus.allocate_device_id(Some(max_id))?);
        Ok(())
    }

    #[test]
    // Test that reserved IDs are skipped by automatic allocation
    fn allocate_device_id_fills_gaps() -> Result<(), Box<dyn Error>> {
        // The first address is occupied by the root
        let mut bus = setup_bus();
        bus.reserve_device_id(0x01)?;
        bus.reserve_device_id(0x03)?;
        bus.reserve_device_id(0x06)?;
        assert_eq!(0x02_u8, bus.allocate_device_id(None)?);
        assert_eq!(0x04_u8, bus.allocate_device_id(None)?);
        assert_eq!(0x05_u8, bus.allocate_device_id(None)?);
        assert_eq!(0x07_u8, bus.allocate_device_id(None)?);
        Ok(())
    }

    #[test]
    // Test that reserving the same ID twice fails
    fn reserve_device_id_twice_fails() -> Result<(), Box<dyn Error>> {
        let mut bus = setup_bus();
        let max_id = NUM_DEVICE_IDS - 1;
        bus.reserve_device_id(max_id)?;
        let result = bus.reserve_device_id(max_id);
        assert!(matches!(
            result,
            Err(PciRootError::AlreadyInUsePciDeviceSlot(x)) if x == usize::from(max_id),
        ));
        Ok(())
    }

    #[test]
    // Test that allocating a previously reserved ID succeeds (idempotent)
    fn allocate_device_id_after_reserve() -> Result<(), Box<dyn Error>> {
        let mut bus = setup_bus();
        bus.reserve_device_id(0x10)?;
        assert_eq!(0x10_u8, bus.allocate_device_id(Some(0x10))?);
        Ok(())
    }

    #[test]
    // Test to request an invalid ID
    fn allocate_device_id_request_invalid_id_fails() -> Result<(), Box<dyn Error>> {
        let mut bus = setup_bus();
        let max_id = NUM_DEVICE_IDS + 1;
        let result = bus.allocate_device_id(Some(max_id));
        assert!(matches!(
            result,
            Err(PciRootError::InvalidPciDeviceSlot(x)) if x == usize::from(max_id),
        ));
        Ok(())
    }

    #[test]
    // Test to acquire an ID when all IDs were already acquired
    fn allocate_device_id_none_left() {
        // The first address is occupied by the root
        let mut bus = setup_bus();
        for expected_id in 1..NUM_DEVICE_IDS {
            assert_eq!(expected_id, bus.allocate_device_id(None).unwrap());
        }
        let result = bus.allocate_device_id(None);
        assert!(matches!(
            result,
            Err(PciRootError::NoPciDeviceSlotAvailable),
        ));
    }
}
