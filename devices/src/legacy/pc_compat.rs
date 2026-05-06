// Copyright 2026 Cloud Hypervisor Authors.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vm_device::BusDevice;
use vm_device::interrupt::InterruptSourceGroup;
use vmm_sys_util::eventfd::EventFd;

/// Minimal i8259-compatible PIC ports.
///
/// TDVF and Linux touch the legacy PIC even when interrupts are ultimately
/// routed through the local APIC/IOAPIC. Keeping the masks readable avoids
/// firmware fallback/reset paths on q35 TDX guests.
pub struct PicStub {
    master_mask: u8,
    slave_mask: u8,
}

impl PicStub {
    pub fn new() -> Self {
        Self {
            master_mask: 0xff,
            slave_mask: 0xff,
        }
    }
}

impl BusDevice for PicStub {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        let port = base + offset;
        data[0] = match port {
            0x21 => self.master_mask,
            0xa1 => self.slave_mask,
            0x20 | 0xa0 => 0,
            _ => 0xff,
        };
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() != 1 {
            return None;
        }

        match base + offset {
            0x21 => self.master_mask = data[0],
            0xa1 => self.slave_mask = data[0],
            _ => {}
        }

        None
    }
}

/// Minimal i8254 PIT ports.
pub struct PitStub {
    channels: [u16; 3],
    read_high: [bool; 3],
    write_high: [bool; 3],
    access_mode: [u8; 3],
    selected: usize,
    last_programmed: [Instant; 3],
    timer_state: Arc<Mutex<PitTimerState>>,
}

struct PitTimerState {
    period: Option<Duration>,
    next_tick: Instant,
}

impl PitStub {
    pub fn new(interrupt: Arc<dyn InterruptSourceGroup>) -> Self {
        let now = Instant::now();
        let timer_state = Arc::new(Mutex::new(PitTimerState {
            period: None,
            next_tick: now,
        }));

        Self::start_timer_thread(Arc::clone(&timer_state), interrupt);

        Self {
            channels: [0; 3],
            read_high: [false; 3],
            write_high: [false; 3],
            access_mode: [3; 3],
            selected: 0,
            last_programmed: [now; 3],
            timer_state,
        }
    }

    fn current_value(&self, channel: usize) -> u16 {
        const PIT_HZ: u128 = 1_193_182;

        let reload = self.channels[channel];
        if reload == 0 {
            return 0;
        }

        let elapsed = self.last_programmed[channel].elapsed();
        let ticks = elapsed.as_nanos().saturating_mul(PIT_HZ) / 1_000_000_000;
        let position = (ticks % reload as u128) as u16;
        reload.wrapping_sub(position)
    }

    fn start_timer_thread(
        timer_state: Arc<Mutex<PitTimerState>>,
        interrupt: Arc<dyn InterruptSourceGroup>,
    ) {
        let _ = thread::Builder::new()
            .name("pit-irq0".to_string())
            .spawn(move || {
                loop {
                    let sleep_for = {
                        let mut state = timer_state.lock().unwrap();
                        match state.period {
                            Some(period) => {
                                let now = Instant::now();
                                if now >= state.next_tick {
                                    state.next_tick = now + period;
                                    drop(state);
                                    if let Err(e) = interrupt.trigger(0) {
                                        log::trace!("PIT IRQ0 injection failed: {e}");
                                    }
                                    Duration::from_millis(1)
                                } else {
                                    state.next_tick.saturating_duration_since(now)
                                }
                            }
                            None => Duration::from_millis(1),
                        }
                    };

                    thread::sleep(sleep_for.min(Duration::from_millis(10)));
                }
            });
    }

    fn update_channel0_timer(&mut self) {
        const PIT_HZ: u128 = 1_193_182;

        let reload = if self.channels[0] == 0 {
            0x1_0000
        } else {
            self.channels[0] as u128
        };
        let nanos = (reload * 1_000_000_000).div_ceil(PIT_HZ) as u64;
        let period = Duration::from_nanos(nanos.max(1));

        let mut state = self.timer_state.lock().unwrap();
        state.period = Some(period);
        state.next_tick = Instant::now() + period;
    }
}

impl BusDevice for PitStub {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        let channel = offset as usize;
        if channel < self.channels.len() {
            let value = self.current_value(channel);
            data[0] = if self.read_high[channel] {
                (value >> 8) as u8
            } else {
                value as u8
            };
            self.read_high[channel] = !self.read_high[channel];
        } else {
            data[0] = 0;
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() != 1 {
            return None;
        }

        match offset {
            0..=2 => {
                let channel = offset as usize;
                match self.access_mode[channel] {
                    1 => {
                        self.channels[channel] = (self.channels[channel] & 0xff00) | data[0] as u16;
                        self.last_programmed[channel] = Instant::now();
                        if channel == 0 {
                            self.update_channel0_timer();
                        }
                    }
                    2 => {
                        self.channels[channel] =
                            (self.channels[channel] & 0x00ff) | ((data[0] as u16) << 8);
                        self.last_programmed[channel] = Instant::now();
                        if channel == 0 {
                            self.update_channel0_timer();
                        }
                    }
                    _ => {
                        if self.write_high[channel] {
                            self.channels[channel] =
                                (self.channels[channel] & 0x00ff) | ((data[0] as u16) << 8);
                            self.last_programmed[channel] = Instant::now();
                            if channel == 0 {
                                self.update_channel0_timer();
                            }
                        } else {
                            self.channels[channel] =
                                (self.channels[channel] & 0xff00) | data[0] as u16;
                        }
                        self.write_high[channel] = !self.write_high[channel];
                    }
                }
            }
            3 => {
                let channel = (data[0] >> 6) & 0x3;
                if channel == 3 {
                    return None;
                }
                self.selected = channel as usize;
                self.access_mode[self.selected] = (data[0] >> 4) & 0x3;
                self.read_high[self.selected] = false;
                self.write_high[self.selected] = false;
            }
            _ => {}
        }

        None
    }
}

/// Port 0x61 system-control latch used by PIT channel 2 and pc speaker probes.
pub struct Port61 {
    value: u8,
}

impl Port61 {
    pub fn new() -> Self {
        Self { value: 0x20 }
    }
}

impl BusDevice for Port61 {
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        if data.len() == 1 {
            // Bit 5 set matches the traditional kvmtool behavior used to avoid
            // Linux PIT calibration hangs when no real speaker/PIT gate exists.
            data[0] = self.value | 0x20;
        }
    }

    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() == 1 {
            self.value = data[0] | 0x20;
        }
        None
    }
}

/// Port 0x92 system-control stub with A20 enabled.
pub struct Port92 {
    value: u8,
}

impl Port92 {
    pub fn new() -> Self {
        Self { value: 0x02 }
    }
}

impl BusDevice for Port92 {
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        if data.len() == 1 {
            data[0] = self.value;
        }
    }

    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() == 1 {
            // Ignore the reset bit; the dedicated i8042 reset path handles
            // guest-requested resets in Cloud Hypervisor.
            self.value = data[0] & !0x01;
        }
        None
    }
}

/// Minimal q35 ACPI PM1 event block at PMBASE + 0x00.
pub struct Q35Pm1Evt {
    status: u16,
    enable: u16,
}

impl Q35Pm1Evt {
    pub fn new() -> Self {
        Self {
            status: 0,
            enable: 0,
        }
    }
}

impl BusDevice for Q35Pm1Evt {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&self.status.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.enable.to_le_bytes());
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = bytes.get(offset as usize + index).copied().unwrap_or(0);
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&self.status.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.enable.to_le_bytes());
        for (index, byte) in data.iter().enumerate() {
            if let Some(dst) = bytes.get_mut(offset as usize + index) {
                *dst = *byte;
            }
        }

        let written_status = u16::from_le_bytes([bytes[0], bytes[1]]);
        self.status &= !written_status;
        self.enable = u16::from_le_bytes([bytes[2], bytes[3]]);
        None
    }
}

/// Minimal q35 ACPI PM1 control register at PMBASE + 0x04.
pub struct Q35Pm1Cnt {
    value: u16,
    guest_exit_evt: EventFd,
    vcpus_kill_signalled: Arc<AtomicBool>,
}

impl Q35Pm1Cnt {
    pub fn new(guest_exit_evt: EventFd, vcpus_kill_signalled: Arc<AtomicBool>) -> Self {
        Self {
            value: 0,
            guest_exit_evt,
            vcpus_kill_signalled,
        }
    }
}

impl BusDevice for Q35Pm1Cnt {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let bytes = self.value.to_le_bytes();
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = bytes.get(offset as usize + index).copied().unwrap_or(0);
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let mut bytes = self.value.to_le_bytes();
        for (index, byte) in data.iter().enumerate() {
            if let Some(dst) = bytes.get_mut(offset as usize + index) {
                *dst = *byte;
            }
        }

        let value = u16::from_le_bytes(bytes);

        const S5_SLEEP_VALUE: u16 = 5;
        const SLEEP_VALUE_SHIFT: u16 = 10;
        const SLEEP_VALUE_MASK: u16 = 0x7;
        const SLEEP_ENABLE_BIT: u16 = 13;
        let sleep_value = (value >> SLEEP_VALUE_SHIFT) & SLEEP_VALUE_MASK;
        if (sleep_value == 0 || sleep_value == S5_SLEEP_VALUE)
            && (value & (1 << SLEEP_ENABLE_BIT)) != 0
        {
            log::info!("q35 ACPI shutdown signalled");
            if let Err(e) = self.guest_exit_evt.write(1) {
                log::error!("Error triggering q35 ACPI shutdown event: {e}");
            }
            while !self.vcpus_kill_signalled.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
        }

        // Match QEMU's PM1_CNT behavior for firmware probing: SLP_EN is
        // write-only and does not remain set after the write.
        self.value = value & !(1 << SLEEP_ENABLE_BIT);
        None
    }
}

/// Minimal APM command/status ports used as q35 SMI_CMD.
pub struct ApmStub {
    command: u8,
    status: u8,
}

impl ApmStub {
    pub fn new() -> Self {
        Self {
            command: 0,
            status: 0,
        }
    }
}

impl BusDevice for ApmStub {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = match offset + index as u64 {
                0 => self.command,
                1 => self.status,
                _ => 0,
            };
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        for (index, byte) in data.iter().enumerate() {
            match offset + index as u64 {
                0 => self.command = *byte,
                1 => self.status = *byte,
                _ => {}
            }
        }

        None
    }
}
