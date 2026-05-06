// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 - 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use std::sync::{Arc, Mutex};

use acpi_tables::{Aml, aml};
use arch::layout;
use log::info;
use pci::{
    DeviceRelocation, PciBdf, PciBus, PciConfigMmio, PciLpcBridge, PciQ35Ahci, PciQ35Smbus,
    PciRoot,
};
#[cfg(target_arch = "x86_64")]
use pci::{PCI_CONFIG_IO_PORT, PCI_CONFIG_IO_PORT_SIZE, PciConfigIo};
use uuid::Uuid;
use vm_allocator::AddressAllocator;
use vm_device::BusDeviceSync;

use crate::device_manager::{AddressManager, DeviceManagerError, DeviceManagerResult};

pub(crate) struct PciSegment {
    pub(crate) id: u16,
    pub(crate) pci_bus: Arc<Mutex<PciBus>>,
    pub(crate) pci_config_mmio: Arc<Mutex<PciConfigMmio>>,
    pub(crate) mmio_config_address: u64,
    pub(crate) proximity_domain: u32,

    #[cfg(target_arch = "x86_64")]
    pub(crate) pci_config_io: Option<Arc<Mutex<PciConfigIo>>>,

    // Bitmap of PCI devices to hotplug.
    pub(crate) pci_devices_up: u32,
    // Bitmap of PCI devices to hotunplug.
    pub(crate) pci_devices_down: u32,
    // List of allocated IRQs for each PCI slot.
    pub(crate) pci_irq_slots: [u8; 32],

    // Device memory covered by this segment
    pub(crate) start_of_mem32_area: u64,
    pub(crate) end_of_mem32_area: u64,

    pub(crate) start_of_mem64_area: u64,
    pub(crate) end_of_mem64_area: u64,

    pub(crate) mem32_allocator: Arc<Mutex<AddressAllocator>>,
    pub(crate) mem64_allocator: Arc<Mutex<AddressAllocator>>,
}

impl PciSegment {
    pub(crate) fn new(
        id: u16,
        numa_node: u32,
        address_manager: &Arc<AddressManager>,
        mem32_allocator: Arc<Mutex<AddressAllocator>>,
        mem64_allocator: Arc<Mutex<AddressAllocator>>,
        mmio_config_base: u64,
        q35_host_bridge: bool,
        pci_irq_slots: &[u8; 32],
    ) -> DeviceManagerResult<PciSegment> {
        let pci_root = if q35_host_bridge {
            PciRoot::new_q35()
        } else {
            PciRoot::new(None)
        };
        let pci_bus = Arc::new(Mutex::new(PciBus::new(
            pci_root,
            Arc::clone(address_manager) as Arc<dyn DeviceRelocation>,
        )));
        if q35_host_bridge && id == 0 {
            let mut pci_bus_locked = pci_bus.lock().unwrap();
            pci_bus_locked
                .allocate_device_id(Some(31))
                .map_err(DeviceManagerError::AllocatePciDeviceId)?;
            pci_bus_locked
                .add_device(31, Arc::new(Mutex::new(PciLpcBridge::new_ich9())))
                .map_err(DeviceManagerError::AddPciDevice)?;
            pci_bus_locked
                .add_device_function(31, 2, Arc::new(Mutex::new(PciQ35Ahci::new())))
                .map_err(DeviceManagerError::AddPciDevice)?;
            pci_bus_locked
                .add_device_function(31, 3, Arc::new(Mutex::new(PciQ35Smbus::new())))
                .map_err(DeviceManagerError::AddPciDevice)?;
        }

        let pci_config_mmio = Arc::new(Mutex::new(PciConfigMmio::new(Arc::clone(&pci_bus))));
        let mmio_config_address =
            mmio_config_base + layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT * id as u64;

        address_manager
            .mmio_bus
            .insert(
                Arc::clone(&pci_config_mmio) as Arc<dyn BusDeviceSync>,
                mmio_config_address,
                layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT,
            )
            .map_err(DeviceManagerError::BusError)?;

        #[cfg(target_arch = "x86_64")]
        if q35_host_bridge && id == 0 && mmio_config_address != 0xe000_0000 {
            let compat_mmio_config_address = 0xe000_0000;
            address_manager
                .mmio_bus
                .insert(
                    Arc::clone(&pci_config_mmio) as Arc<dyn BusDeviceSync>,
                    compat_mmio_config_address,
                    layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT,
                )
                .map_err(DeviceManagerError::BusError)?;
            info!(
                "Adding q35 PCI MMIO config compatibility alias: id={}, address=0x{:x}",
                id, compat_mmio_config_address
            );
        }

        let start_of_mem32_area = mem32_allocator.lock().unwrap().base().0;
        let end_of_mem32_area = mem32_allocator.lock().unwrap().end().0;

        let start_of_mem64_area = mem64_allocator.lock().unwrap().base().0;
        let end_of_mem64_area = mem64_allocator.lock().unwrap().end().0;

        let segment = PciSegment {
            id,
            pci_bus,
            pci_config_mmio,
            mmio_config_address,
            proximity_domain: numa_node,
            pci_devices_up: 0,
            pci_devices_down: 0,
            #[cfg(target_arch = "x86_64")]
            pci_config_io: None,
            mem32_allocator,
            mem64_allocator,
            start_of_mem32_area,
            end_of_mem32_area,
            start_of_mem64_area,
            end_of_mem64_area,
            pci_irq_slots: *pci_irq_slots,
        };

        info!(
            "Adding PCI segment: id={}, PCI MMIO config address: 0x{:x}, mem32 area [0x{:x}-0x{:x}], mem64 area [0x{:x}-0x{:x}]",
            segment.id,
            segment.mmio_config_address,
            segment.start_of_mem32_area,
            segment.end_of_mem32_area,
            segment.start_of_mem64_area,
            segment.end_of_mem64_area
        );
        Ok(segment)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn new_default_segment(
        address_manager: &Arc<AddressManager>,
        mem32_allocator: Arc<Mutex<AddressAllocator>>,
        mem64_allocator: Arc<Mutex<AddressAllocator>>,
        mmio_config_base: u64,
        q35_host_bridge: bool,
        pci_irq_slots: &[u8; 32],
    ) -> DeviceManagerResult<PciSegment> {
        let mut segment = Self::new(
            0,
            0,
            address_manager,
            mem32_allocator,
            mem64_allocator,
            mmio_config_base,
            q35_host_bridge,
            pci_irq_slots,
        )?;
        let pci_config_io = Arc::new(Mutex::new(PciConfigIo::new(Arc::clone(&segment.pci_bus))));

        address_manager
            .io_bus
            .insert(
                pci_config_io.clone(),
                PCI_CONFIG_IO_PORT,
                PCI_CONFIG_IO_PORT_SIZE,
            )
            .map_err(DeviceManagerError::BusError)?;

        segment.pci_config_io = Some(pci_config_io);

        Ok(segment)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub(crate) fn new_default_segment(
        address_manager: &Arc<AddressManager>,
        mem32_allocator: Arc<Mutex<AddressAllocator>>,
        mem64_allocator: Arc<Mutex<AddressAllocator>>,
        mmio_config_base: u64,
        q35_host_bridge: bool,
        pci_irq_slots: &[u8; 32],
    ) -> DeviceManagerResult<PciSegment> {
        Self::new(
            0,
            0,
            address_manager,
            mem32_allocator,
            mem64_allocator,
            mmio_config_base,
            q35_host_bridge,
            pci_irq_slots,
        )
    }

    /// Reserves a device ID on this PCI segment, marking it as in-use
    /// so that automatic allocation will not use it.
    pub(crate) fn reserve_device_id(&self, device_id: u8) -> DeviceManagerResult<()> {
        self.pci_bus
            .lock()
            .unwrap()
            .reserve_device_id(device_id)
            .map_err(DeviceManagerError::ReservePciDeviceId)?;
        Ok(())
    }

    /// Allocates a device's ID on this PCI segment.
    ///
    /// - `device_id`: Device ID to request for allocation
    ///
    /// ## Errors
    /// * [`DeviceManagerError::AllocatePciDeviceId`] if device ID
    ///   allocation on the bus fails.
    pub(crate) fn allocate_device_id(&self, device_id: Option<u8>) -> DeviceManagerResult<PciBdf> {
        Ok(PciBdf::new(
            self.id,
            0,
            self.pci_bus
                .lock()
                .unwrap()
                .allocate_device_id(device_id)
                .map_err(DeviceManagerError::AllocatePciDeviceId)?,
            0,
        ))
    }

    pub fn reserve_legacy_interrupts_for_pci_devices(
        address_manager: &Arc<AddressManager>,
        pci_irq_slots: &mut [u8; 32],
    ) -> DeviceManagerResult<()> {
        // Reserve 8 IRQs which will be shared across all PCI devices.
        let num_irqs = 8;
        let mut irqs: Vec<u8> = Vec::new();
        for _ in 0..num_irqs {
            irqs.push(
                address_manager
                    .allocator
                    .lock()
                    .unwrap()
                    .allocate_irq()
                    .ok_or(DeviceManagerError::AllocateIrq)? as u8,
            );
        }

        // There are 32 devices on the PCI bus, let's assign them an IRQ.
        for i in 0..32 {
            pci_irq_slots[i] = irqs[i % num_irqs];
        }

        Ok(())
    }

    #[cfg(test)]
    /// Creates a PciSegment without the need for an [`AddressManager`]
    /// for testing purpose.
    ///
    /// An [`AddressManager`] would otherwise be required to create
    /// [`PciBus`] instances. Instead, we use any struct that implements
    /// [`DeviceRelocation`] to instantiate a [`PciBus`].
    pub(crate) fn new_without_address_manager(
        id: u16,
        numa_node: u32,
        mem32_allocator: Arc<Mutex<AddressAllocator>>,
        mem64_allocator: Arc<Mutex<AddressAllocator>>,
        mmio_config_base: u64,
        pci_irq_slots: &[u8; 32],
        device_reloc: &Arc<dyn DeviceRelocation>,
    ) -> DeviceManagerResult<Self> {
        let pci_root = PciRoot::new(None);
        let pci_bus = Arc::new(Mutex::new(PciBus::new(pci_root, device_reloc.clone())));

        let pci_config_mmio = Arc::new(Mutex::new(PciConfigMmio::new(Arc::clone(&pci_bus))));
        let mmio_config_address =
            mmio_config_base + layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT * id as u64;

        let start_of_mem32_area = mem32_allocator.lock().unwrap().base().0;
        let end_of_mem32_area = mem32_allocator.lock().unwrap().end().0;

        let start_of_mem64_area = mem64_allocator.lock().unwrap().base().0;
        let end_of_mem64_area = mem64_allocator.lock().unwrap().end().0;

        let segment = PciSegment {
            id,
            pci_bus,
            pci_config_mmio,
            mmio_config_address,
            proximity_domain: numa_node,
            pci_devices_up: 0,
            pci_devices_down: 0,
            #[cfg(target_arch = "x86_64")]
            pci_config_io: None,
            mem32_allocator,
            mem64_allocator,
            start_of_mem32_area,
            end_of_mem32_area,
            start_of_mem64_area,
            end_of_mem64_area,
            pci_irq_slots: *pci_irq_slots,
        };

        info!(
            "Adding PCI segment: id={}, PCI MMIO config address: 0x{:x}, mem32 area [0x{:x}-0x{:x}], mem64 area [0x{:x}-0x{:x}]",
            segment.id,
            segment.mmio_config_address,
            segment.start_of_mem32_area,
            segment.end_of_mem32_area,
            segment.start_of_mem64_area,
            segment.end_of_mem64_area
        );
        Ok(segment)
    }
}

struct PciDevSlot {
    device_id: u8,
}

impl Aml for PciDevSlot {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let sun = self.device_id;
        let adr: u32 = (self.device_id as u32) << 16;
        aml::Device::new(
            format!("S{:03}", self.device_id).as_str().into(),
            vec![
                &aml::Name::new("_SUN".into(), &sun),
                &aml::Name::new("_ADR".into(), &adr),
                &aml::Method::new(
                    "_EJ0".into(),
                    1,
                    true,
                    vec![&aml::MethodCall::new(
                        "\\_SB_.PHPR.PCEJ".into(),
                        vec![&aml::Path::new("_SUN"), &aml::Path::new("_SEG")],
                    )],
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

struct PciDevSlotNotify {
    device_id: u8,
}

impl Aml for PciDevSlotNotify {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let device_id_mask: u32 = 1 << self.device_id;
        let object = aml::Path::new(&format!("S{:03}", self.device_id));
        aml::And::new(&aml::Local(0), &aml::Arg(0), &device_id_mask).to_aml_bytes(sink);
        aml::If::new(
            &aml::Equal::new(&aml::Local(0), &device_id_mask),
            vec![&aml::Notify::new(&object, &aml::Arg(1))],
        )
        .to_aml_bytes(sink);
    }
}

struct PciDevSlotMethods {}

impl Aml for PciDevSlotMethods {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let mut device_notifies = Vec::new();
        for device_id in 0..32 {
            device_notifies.push(PciDevSlotNotify { device_id });
        }

        let mut device_notifies_refs: Vec<&dyn Aml> = Vec::new();
        for device_notify in device_notifies.iter() {
            device_notifies_refs.push(device_notify);
        }

        aml::Method::new("DVNT".into(), 2, true, device_notifies_refs).to_aml_bytes(sink);
        aml::Method::new(
            "PCNT".into(),
            0,
            true,
            vec![
                &aml::Acquire::new("\\_SB_.PHPR.BLCK".into(), 0xffff),
                &aml::Store::new(&aml::Path::new("\\_SB_.PHPR.PSEG"), &aml::Path::new("_SEG")),
                &aml::MethodCall::new(
                    "DVNT".into(),
                    vec![&aml::Path::new("\\_SB_.PHPR.PCIU"), &aml::ONE],
                ),
                &aml::MethodCall::new(
                    "DVNT".into(),
                    vec![&aml::Path::new("\\_SB_.PHPR.PCID"), &3usize],
                ),
                &aml::Release::new("\\_SB_.PHPR.BLCK".into()),
            ],
        )
        .to_aml_bytes(sink);
    }
}

/// PCIe Native HotPlug control bit advertised through `_OSC`.
const PCIE_OSC_CTRL_HOTPLUG: u32 = 1 << 0;
/// PCIe Native PME control bit.
const PCIE_OSC_CTRL_PME: u32 = 1 << 2;
/// PCIe AER control bit.
const PCIE_OSC_CTRL_AER: u32 = 1 << 3;
/// PCIe Capability Structure control bit.
const PCIE_OSC_CTRL_CAP_STRUCT: u32 = 1 << 4;
/// Mask of OS-controllable PCIe features we are willing to grant to the OS.
/// Mirrors what QEMU's q35 advertises in `build_q35_osc`, so OVMF and Linux
/// pick up native PCIe hot-plug, PME, AER, and capability access.
const PCIE_OSC_CTRL_MASK: u32 =
    PCIE_OSC_CTRL_HOTPLUG | PCIE_OSC_CTRL_PME | PCIE_OSC_CTRL_AER | PCIE_OSC_CTRL_CAP_STRUCT;

/// `_OSC` (Operating System Capabilities) method for the PCIe root complex.
///
/// The method follows the standard ACPI v6.3 §6.2.11.3 / PCI Firmware Spec
/// §4.5.1 control negotiation pattern. It declares to firmware (OVMF) and the
/// OS (Linux) which PCIe features the platform supports and grants control
/// over native hot-plug, PME, AER, and capability access. Without this,
/// Linux's `acpi_pci_root_create` cannot transition the host bridge into
/// native PCIe mode and the existing CH pio hotplug path would not be usable
/// for OS-driven slot rescans.
///
/// Equivalent ASL (per QEMU `build_q35_osc`):
/// ```asl
/// Method (_OSC, 4, NotSerialized) {
///     CreateDWordField (Arg3, 0x00, CDW1)
///     If (Arg0 == ToUUID ("33db4d5b-1ff7-401c-9657-7441c03dd766")) {
///         CreateDWordField (Arg3, 0x04, CDW2)
///         CreateDWordField (Arg3, 0x08, CDW3)
///         Store (CDW2, SUPP)
///         Store (CDW3, CTRL)
///         And  (CTRL, 0x1d, CTRL)        /* keep HotPlug | PME | AER | CapStruct */
///         If (LNotEqual (Arg1, One)) {
///             Or (CDW1, 0x08, CDW1)      /* unknown revision */
///         }
///         If (LNotEqual (CDW3, CTRL)) {
///             Or (CDW1, 0x10, CDW1)      /* capability mismatch */
///         }
///         Store (CTRL, CDW3)
///         Return (Arg3)
///     }
///     Or (CDW1, 0x04, CDW1)              /* unrecognized UUID */
///     Return (Arg3)
/// }
/// ```
struct PciOscMethod {}

impl Aml for PciOscMethod {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        // PCI Express Base Specification _OSC UUID, ACPI v6.3 §6.2.11.3.
        // Mixed-endian per ACPI: d1/d2/d3 little endian, d4 big endian.
        let uuid = Uuid::parse_str("33DB4D5B-1FF7-401C-9657-7441C03DD766").unwrap();
        let (d1, d2, d3, d4) = uuid.as_fields();
        let mut uuid_buf = Vec::with_capacity(16);
        uuid_buf.extend(d1.to_le_bytes());
        uuid_buf.extend(d2.to_le_bytes());
        uuid_buf.extend(d3.to_le_bytes());
        uuid_buf.extend(d4);

        let cdw1_path = aml::Path::new("CDW1");
        let cdw2_path = aml::Path::new("CDW2");
        let cdw3_path = aml::Path::new("CDW3");
        let supp_path = aml::Path::new("SUPP");
        let ctrl_path = aml::Path::new("CTRL");
        let arg3 = aml::Arg(3);
        let arg1 = aml::Arg(1);
        let arg0 = aml::Arg(0);
        let one = aml::ONE;
        // Bit 2: unrecognized UUID. Bit 3: unknown revision. Bit 4: capability mismatch.
        let osc_unrecognised_uuid = 0x04u32;
        let osc_unknown_revision = 0x08u32;
        let osc_capabilities_mismatch = 0x10u32;
        let ctrl_mask = PCIE_OSC_CTRL_MASK;

        // CreateDWordField(Arg3, 0, CDW1)
        let create_cdw1 = aml::CreateDWordField::new(&cdw1_path, &arg3, &0u8);
        // Inside-If: CreateDWordField(Arg3, 4, CDW2)
        let create_cdw2 = aml::CreateDWordField::new(&cdw2_path, &arg3, &4u8);
        let create_cdw3 = aml::CreateDWordField::new(&cdw3_path, &arg3, &8u8);

        let store_supp = aml::Store::new(&supp_path, &cdw2_path);
        let store_ctrl = aml::Store::new(&ctrl_path, &cdw3_path);
        let mask_ctrl = aml::And::new(&ctrl_path, &ctrl_path, &ctrl_mask);

        let revision_pred = aml::NotEqual::new(&arg1, &one);
        let revision_or = aml::Or::new(&cdw1_path, &cdw1_path, &osc_unknown_revision);
        let revision_check = aml::If::new(&revision_pred, vec![&revision_or]);

        let mismatch_pred = aml::NotEqual::new(&cdw3_path, &ctrl_path);
        let mismatch_or = aml::Or::new(&cdw1_path, &cdw1_path, &osc_capabilities_mismatch);
        let mismatch_check = aml::If::new(&mismatch_pred, vec![&mismatch_or]);

        let write_back_ctrl = aml::Store::new(&cdw3_path, &ctrl_path);
        let return_arg3 = aml::Return::new(&arg3);
        let return_arg3_outer = aml::Return::new(&arg3);

        let uuid_buffer = aml::BufferData::new(uuid_buf);
        let uuid_pred = aml::Equal::new(&arg0, &uuid_buffer);
        let if_uuid = aml::If::new(
            &uuid_pred,
            vec![
                &create_cdw2,
                &create_cdw3,
                &store_supp,
                &store_ctrl,
                &mask_ctrl,
                &revision_check,
                &mismatch_check,
                &write_back_ctrl,
                &return_arg3,
            ],
        );
        let unrecognised = aml::Or::new(&cdw1_path, &cdw1_path, &osc_unrecognised_uuid);

        aml::Method::new(
            "_OSC".into(),
            4,
            false,
            vec![&create_cdw1, &if_uuid, &unrecognised, &return_arg3_outer],
        )
        .to_aml_bytes(sink);
    }
}

/// PCI INTx link device (`LNKA`/`LNKB`/`LNKC`/`LNKD`) backed by a single
/// IOAPIC GSI. PCI INTx is level-triggered, active-low, and shareable; the
/// IRQ value comes from the same pool that `device_manager` already wires up
/// for legacy PCI interrupts via `LegacyIrqGroupConfig`, so the routing
/// presented through `_PRT` is consistent with what the VMM actually injects.
struct PciLinkDevice {
    name: &'static str,
    irq: u32,
}

impl Aml for PciLinkDevice {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        aml::Device::new(
            self.name.into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C0F")),
                &aml::Name::new("_UID".into(), &(self.irq)),
                &aml::Name::new("_STA".into(), &0x0Bu8),
                &aml::Name::new(
                    "_PRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::Interrupt::new(
                        true, false, true, true, self.irq,
                    )]),
                ),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::Interrupt::new(
                        true, false, true, true, self.irq,
                    )]),
                ),
                // _SRS is required by some OSes for link devices but the
                // routing is fixed in this VMM, so accept and ignore.
                &aml::Method::new("_SRS".into(), 1, false, vec![]),
                &aml::Method::new(
                    "_DIS".into(),
                    0,
                    false,
                    vec![&aml::Store::new(&aml::Path::new("_STA"), &0x09u8)],
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

struct PciDsmMethod {}

impl Aml for PciDsmMethod {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        // Refer to ACPI spec v6.3 Ch 9.1.1 and PCI Firmware spec v3.3 Ch 4.6.1
        // _DSM (Device Specific Method), the following is the implementation in ASL.
        /*
        Method (_DSM, 4, NotSerialized)  // _DSM: Device-Specific Method
        {
              If ((Arg0 == ToUUID ("e5c937d0-3553-4d7a-9117-ea4d19c3434d") /* Device Labeling Interface */))
              {
                  If ((Arg2 == Zero))
                  {
                      Return (Buffer (One) { 0x21 })
                  }
                  If ((Arg2 == 0x05))
                  {
                      Return (Zero)
                  }
              }

              Return (Buffer (One) { 0x00 })
        }
         */
        /*
         * As per ACPI v6.3 Ch 19.6.142, the UUID is required to be in mixed endian:
         * Among the fields of a UUID:
         *   {d1 (8 digits)} - {d2 (4 digits)} - {d3 (4 digits)} - {d4 (16 digits)}
         * d1 ~ d3 need to be little endian, d4 be big endian.
         * See https://en.wikipedia.org/wiki/Universally_unique_identifier#Encoding .
         */
        let uuid = Uuid::parse_str("E5C937D0-3553-4D7A-9117-EA4D19C3434D").unwrap();
        let (uuid_d1, uuid_d2, uuid_d3, uuid_d4) = uuid.as_fields();
        let mut uuid_buf = vec![];
        uuid_buf.extend(uuid_d1.to_le_bytes());
        uuid_buf.extend(uuid_d2.to_le_bytes());
        uuid_buf.extend(uuid_d3.to_le_bytes());
        uuid_buf.extend(uuid_d4);
        aml::Method::new(
            "_DSM".into(),
            4,
            false,
            vec![
                &aml::If::new(
                    &aml::Equal::new(&aml::Arg(0), &aml::BufferData::new(uuid_buf)),
                    vec![
                        &aml::If::new(
                            &aml::Equal::new(&aml::Arg(2), &aml::ZERO),
                            vec![&aml::Return::new(&aml::BufferData::new(vec![0x21]))],
                        ),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Arg(2), &0x05u8),
                            vec![&aml::Return::new(&aml::ZERO)],
                        ),
                    ],
                ),
                &aml::Return::new(&aml::BufferData::new(vec![0])),
            ],
        )
        .to_aml_bytes(sink);
    }
}

impl Aml for PciSegment {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let mut pci_dsdt_inner_data: Vec<&dyn Aml> = Vec::new();
        let hid = aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A08"));
        pci_dsdt_inner_data.push(&hid);
        let cid = aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A03"));
        pci_dsdt_inner_data.push(&cid);
        let adr = aml::Name::new("_ADR".into(), &aml::ZERO);
        pci_dsdt_inner_data.push(&adr);
        let seg = aml::Name::new("_SEG".into(), &self.id);
        pci_dsdt_inner_data.push(&seg);
        let uid = aml::Name::new("_UID".into(), &self.id);
        pci_dsdt_inner_data.push(&uid);
        let cca = aml::Name::new("_CCA".into(), &aml::ONE);
        pci_dsdt_inner_data.push(&cca);
        // Scratch slots used by `_OSC` to mirror the OS' supported / control
        // capability words back to the caller. Initialised to zero; written
        // by `_OSC` on each invocation.
        let supp = aml::Name::new("SUPP".into(), &aml::ZERO);
        pci_dsdt_inner_data.push(&supp);
        let ctrl = aml::Name::new("CTRL".into(), &aml::ZERO);
        pci_dsdt_inner_data.push(&ctrl);

        let proximity_domain = self.proximity_domain;
        let pxm_return = aml::Return::new(&proximity_domain);
        let pxm = aml::Method::new("_PXM".into(), 0, false, vec![&pxm_return]);
        pci_dsdt_inner_data.push(&pxm);

        let pci_osc = PciOscMethod {};
        pci_dsdt_inner_data.push(&pci_osc);

        let pci_dsm = PciDsmMethod {};
        pci_dsdt_inner_data.push(&pci_dsm);

        #[allow(clippy::if_same_then_else)]
        let crs = if self.id == 0 {
            aml::Name::new(
                "_CRS".into(),
                &aml::ResourceTemplate::new(vec![
                    &aml::AddressSpace::new_bus_number(0x0u16, 0x0u16),
                    #[cfg(target_arch = "x86_64")]
                    &aml::IO::new(0xcf8, 0xcf8, 1, 0x8),
                    &aml::Memory32Fixed::new(
                        true,
                        self.mmio_config_address as u32,
                        layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT as u32,
                    ),
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.start_of_mem32_area,
                        self.end_of_mem32_area,
                        None,
                    ),
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.start_of_mem64_area,
                        self.end_of_mem64_area,
                        None,
                    ),
                    #[cfg(target_arch = "x86_64")]
                    &aml::AddressSpace::new_io(0u16, 0x0cf7u16, None),
                    #[cfg(target_arch = "x86_64")]
                    &aml::AddressSpace::new_io(0x0d00u16, 0xffffu16, None),
                ]),
            )
        } else {
            aml::Name::new(
                "_CRS".into(),
                &aml::ResourceTemplate::new(vec![
                    &aml::AddressSpace::new_bus_number(0x0u16, 0x0u16),
                    &aml::Memory32Fixed::new(
                        true,
                        self.mmio_config_address as u32,
                        layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT as u32,
                    ),
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.start_of_mem32_area,
                        self.end_of_mem32_area,
                        None,
                    ),
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.start_of_mem64_area,
                        self.end_of_mem64_area,
                        None,
                    ),
                ]),
            )
        };
        pci_dsdt_inner_data.push(&crs);

        let mut pci_devices = Vec::new();
        for device_id in 0..32 {
            let pci_device = PciDevSlot { device_id };
            pci_devices.push(pci_device);
        }
        for pci_device in pci_devices.iter() {
            pci_dsdt_inner_data.push(pci_device);
        }

        let pci_device_methods = PciDevSlotMethods {};
        pci_dsdt_inner_data.push(&pci_device_methods);

        // PCI INTx link devices LNKA..LNKD. Each pins one of the four IRQs
        // reserved by `reserve_legacy_interrupts_for_pci_devices`, so the
        // _PRT routing matches the IOAPIC entries the VMM actually injects.
        let link_irqs: [u32; 4] = [
            self.pci_irq_slots[0] as u32,
            self.pci_irq_slots[1] as u32,
            self.pci_irq_slots[2] as u32,
            self.pci_irq_slots[3] as u32,
        ];
        let lnk_devices: [PciLinkDevice; 4] = [
            PciLinkDevice {
                name: "LNKA",
                irq: link_irqs[0],
            },
            PciLinkDevice {
                name: "LNKB",
                irq: link_irqs[1],
            },
            PciLinkDevice {
                name: "LNKC",
                irq: link_irqs[2],
            },
            PciLinkDevice {
                name: "LNKD",
                irq: link_irqs[3],
            },
        ];
        for lnk in &lnk_devices {
            pci_dsdt_inner_data.push(lnk);
        }

        // Build the full PCI Routing Table: 32 device slots × 4 INTx pins
        // (INTA..INTD). Pin P on device N rotates onto LNK[(N+P) % 4],
        // matching QEMU's q35 convention so guests with shared expectations
        // (OVMF, Linux) route INTx consistently with what we declare.
        let lnk_paths: [aml::Path; 4] = [
            aml::Path::new("LNKA"),
            aml::Path::new("LNKB"),
            aml::Path::new("LNKC"),
            aml::Path::new("LNKD"),
        ];
        // Pre-compute the (bdf, pin) literals so their storage outlives the
        // packages that reference them.
        let prt_indices: Vec<(u32, u32, usize)> = (0..32u32)
            .flat_map(|device_id| {
                (0..4u32).map(move |pin| {
                    let bdf = (device_id << 16) | 0xffffu32;
                    let lnk_idx = ((device_id + pin) & 0x3) as usize;
                    (bdf, pin, lnk_idx)
                })
            })
            .collect();
        let prt_zero: u32 = 0;
        let prt_entries: Vec<aml::Package> = prt_indices
            .iter()
            .map(|(bdf, pin, lnk_idx)| {
                aml::Package::new(vec![
                    bdf as &dyn Aml,
                    pin as &dyn Aml,
                    &lnk_paths[*lnk_idx] as &dyn Aml,
                    &prt_zero as &dyn Aml,
                ])
            })
            .collect();
        let prt_entry_refs: Vec<&dyn Aml> =
            prt_entries.iter().map(|item| item as &dyn Aml).collect();
        let prt = aml::Name::new("_PRT".into(), &aml::Package::new(prt_entry_refs));
        pci_dsdt_inner_data.push(&prt);

        let pci_name = if self.id == 0 {
            "_SB_.PCI0".into()
        } else {
            format!("_SB_.PC{:02X}", self.id).as_str().into()
        };
        aml::Device::new(pci_name, pci_dsdt_inner_data).to_aml_bytes(sink);
    }
}

#[cfg(test)]
mod unit_tests {
    use std::result::Result;

    use vm_memory::GuestAddress;

    use super::*;

    #[derive(Debug)]
    struct MockDeviceRelocation;
    impl DeviceRelocation for MockDeviceRelocation {
        fn move_bar(
            &self,
            _old_base: u64,
            _new_base: u64,
            _len: u64,
            _pci_dev: &mut dyn pci::PciDevice,
            _region_type: pci::PciBarRegionType,
        ) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    fn setup() -> PciSegment {
        let guest_addr = 0_u64;
        let guest_size = 0x1000_usize;
        let allocator_1 = Arc::new(Mutex::new(
            AddressAllocator::new(GuestAddress(guest_addr), guest_size as u64).unwrap(),
        ));
        let allocator_2 = Arc::new(Mutex::new(
            AddressAllocator::new(GuestAddress(guest_addr), guest_size as u64).unwrap(),
        ));
        let mock_device_reloc: Arc<dyn DeviceRelocation> = Arc::new(MockDeviceRelocation {});
        let arr = [0_u8; 32];

        PciSegment::new_without_address_manager(
            0,
            0,
            allocator_1,
            allocator_2,
            layout::PCI_MMCONFIG_START.0,
            false,
            &arr,
            &mock_device_reloc,
        )
        .unwrap()
    }

    #[test]
    // Test the default device ID for a segment with an empty bus (except for the root device).
    fn allocate_device_id_default() {
        // The first address is occupied by the root
        let segment = setup();
        let bdf = segment.allocate_device_id(None).unwrap();
        assert_eq!(bdf.segment(), segment.id);
        assert_eq!(bdf.bus(), 0);
        assert_eq!(bdf.device(), 1);
        assert_eq!(bdf.function(), 0);
    }

    #[test]
    // Test to acquire a specific device ID
    fn allocate_device_id_fixed_device_id() {
        // The first address is occupied by the root
        let expect_device_id = 0x10_u8;
        let segment = setup();
        let bdf = segment.allocate_device_id(Some(expect_device_id)).unwrap();
        assert_eq!(bdf.segment(), segment.id);
        assert_eq!(bdf.bus(), 0);
        assert_eq!(bdf.device(), expect_device_id);
        assert_eq!(bdf.function(), 0);
    }

    #[test]
    // Test that reserving an already taken device ID fails and that
    // allocating an out-of-range device ID fails.
    fn allocate_device_id_invalid_device_id() {
        // The first address is occupied by the root
        let already_taken_device_id = 0x0_u8;
        let overflow_device_id = 0xff_u8;
        let segment = setup();
        let bdf_res = segment.reserve_device_id(already_taken_device_id);
        assert!(matches!(
            bdf_res,
            Err(DeviceManagerError::ReservePciDeviceId(e)) if matches!(
                e,
                pci::PciRootError::AlreadyInUsePciDeviceSlot(0x0)
            )
        ));
        let bdf_res = segment.allocate_device_id(Some(overflow_device_id));
        assert!(matches!(
            bdf_res,
            Err(DeviceManagerError::AllocatePciDeviceId(e)) if matches!(
                e,
                pci::PciRootError::InvalidPciDeviceSlot(0xff)
            )
        ));
    }
}
