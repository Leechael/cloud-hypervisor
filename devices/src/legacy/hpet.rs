// Copyright 2026 Cloud Hypervisor Authors.
//
// SPDX-License-Identifier: Apache-2.0

//! High Precision Event Timer (HPET) MMIO emulation.
//!
//! Implements the IA-PC HPET specification revision 1.0a in software.
//! The device exposes the standard 0x400-byte register block at
//! `0xfed0_0000`, three timers, and the legacy replacement routing the
//! Intel ICH9 datasheet describes. A single background thread owns the
//! comparator deadlines and fires the appropriate IO-APIC IRQ when a
//! timer expires.

use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vm_device::BusDevice;
use vm_device::interrupt::InterruptSourceGroup;

/// MMIO base address required by the IA-PC HPET specification.
pub const HPET_BASE: u64 = 0xfed0_0000;
/// Size of the HPET MMIO window.
pub const HPET_LEN: u64 = 0x400;
/// Number of comparators implemented by this HPET. The IA-PC spec
/// requires at least three.
pub const HPET_NUM_TIMERS: usize = 3;

/// HPET clock period in femtoseconds.
///
/// 10 ns / 100 MHz, matching QEMU's `HPET_CLK_PERIOD * FS_PER_NS`
/// (10 * 1_000_000 = 10_000_000 fs).
const HPET_CLK_PERIOD_FS: u64 = 10_000_000;
/// HPET clock period in nanoseconds. Used to convert between the main
/// counter ticks and host wall-clock time.
const HPET_CLK_PERIOD_NS: u64 = 10;

// Global register offsets (relative to HPET_BASE).
const HPET_REG_ID: u64 = 0x000;
const HPET_REG_CFG: u64 = 0x010;
const HPET_REG_STATUS: u64 = 0x020;
const HPET_REG_COUNTER: u64 = 0x0f0;

// Per-timer offsets.
const TIMER_BLOCK_BASE: u64 = 0x100;
const TIMER_BLOCK_STRIDE: u64 = 0x20;
const TIMER_OFFSET_CFG: u64 = 0x00;
const TIMER_OFFSET_CMP: u64 = 0x08;
const TIMER_OFFSET_ROUTE: u64 = 0x10;

// Configuration register bits.
const HPET_CFG_ENABLE: u64 = 1 << 0;
const HPET_CFG_LEGACY: u64 = 1 << 1;
const HPET_CFG_WRITE_MASK: u64 = HPET_CFG_ENABLE | HPET_CFG_LEGACY;

// Per-timer configuration bits / capabilities.
const HPET_TN_TYPE_LEVEL: u64 = 1 << 1;
const HPET_TN_ENABLE: u64 = 1 << 2;
const HPET_TN_PERIODIC: u64 = 1 << 3;
const HPET_TN_PERIODIC_CAP: u64 = 1 << 4;
const HPET_TN_SIZE_CAP: u64 = 1 << 5;
const HPET_TN_SETVAL: u64 = 1 << 6;
const HPET_TN_32BIT: u64 = 1 << 8;
const HPET_TN_INT_ROUTE_MASK: u64 = 0x3e00;
const HPET_TN_CFG_WRITE_MASK: u64 = 0x7f4e;
const HPET_TN_INT_ROUTE_CAP_SHIFT: u64 = 32;

// IRQ routing capability advertised in each timer config register.
// Allow IRQs 2, 8 and 11 to match what we wire on the IO-APIC side.
const HPET_INT_ROUTE_CAP: u32 = (1 << 2) | (1 << 8) | (1 << 11);

// Indexes into the interrupt-group vector handed to `Hpet::new()`:
// timer0/timer1/timer2 occupy slots 0..3 and the legacy aliases for
// PIT (timer0 in legacy mode) and RTC (timer1 in legacy mode) occupy
// slots 3 and 4.
const IRQ_GROUP_LEGACY_PIT: usize = 3;
const IRQ_GROUP_LEGACY_RTC: usize = 4;
const HPET_IRQ_GROUP_COUNT: usize = 5;

/// 32-bit Event Timer Block ID exposed via fw_cfg and the ACPI HPET
/// table.
///
/// vendor=0x8086, leg_replacement_capable=1, count_size=1 (64-bit),
/// num_timers-1=2 (3 timers), rev_id=0x01 -> low 16 bits = 0xa201.
pub fn hpet_block_id() -> u32 {
    let vendor = 0x8086u32;
    let leg_rt_cap = 1u32 << 15;
    let count_size_cap = 1u32 << 13;
    let num_tim_cap = ((HPET_NUM_TIMERS as u32) - 1) << 8;
    let rev_id = 0x01u32;
    (vendor << 16) | leg_rt_cap | count_size_cap | num_tim_cap | rev_id
}

/// Build the 64-bit General Capabilities/ID register value.
fn hpet_capability() -> u64 {
    (hpet_block_id() as u64) | ((HPET_CLK_PERIOD_FS as u64) << 32)
}

#[derive(Clone, Copy)]
struct HpetTimer {
    config: u64,
    cmp: u64,
    fsb: u64,
    period: u64,
    /// Absolute host deadline at which this timer should next fire, or
    /// `None` if the timer is currently disarmed.
    next_deadline: Option<Instant>,
}

impl HpetTimer {
    fn new() -> Self {
        // Reset value per spec: comparator = !0, type=64-bit periodic-capable.
        let config = HPET_TN_PERIODIC_CAP
            | HPET_TN_SIZE_CAP
            | ((HPET_INT_ROUTE_CAP as u64) << HPET_TN_INT_ROUTE_CAP_SHIFT);
        Self {
            config,
            cmp: u64::MAX,
            fsb: 0,
            period: 0,
            next_deadline: None,
        }
    }

    fn enabled(&self) -> bool {
        self.config & HPET_TN_ENABLE != 0
    }

    fn periodic(&self) -> bool {
        self.config & HPET_TN_PERIODIC != 0
    }

    fn is_32bit(&self) -> bool {
        self.config & HPET_TN_32BIT != 0
    }
}

struct HpetState {
    /// Global Capabilities/ID register, read-only.
    capability: u64,
    /// General Configuration register.
    config: u64,
    /// General Interrupt Status register (write-1-to-clear).
    isr: u64,
    /// Cached counter value used while the main counter is halted.
    counter_when_halted: u64,
    /// Host instant at which the main counter logically reads zero. Set
    /// when the counter is started/resumed.
    counter_base: Instant,
    /// Per-timer state.
    timers: [HpetTimer; HPET_NUM_TIMERS],
    /// Set by the device on shutdown to ask the worker to exit.
    shutdown: bool,
}

impl HpetState {
    fn new() -> Self {
        Self {
            capability: hpet_capability(),
            config: 0,
            isr: 0,
            counter_when_halted: 0,
            counter_base: Instant::now(),
            timers: [HpetTimer::new(); HPET_NUM_TIMERS],
            shutdown: false,
        }
    }

    fn enabled(&self) -> bool {
        self.config & HPET_CFG_ENABLE != 0
    }

    fn legacy(&self) -> bool {
        self.config & HPET_CFG_LEGACY != 0
    }

    /// Current value of the 64-bit main counter.
    fn current_ticks(&self) -> u64 {
        if self.enabled() {
            let elapsed = self.counter_base.elapsed();
            let ns = elapsed.as_nanos() as u64;
            self.counter_when_halted
                .wrapping_add(ns / HPET_CLK_PERIOD_NS)
        } else {
            self.counter_when_halted
        }
    }

    /// Set `counter_base` so that `current_ticks()` returns `value` right
    /// now. Only meaningful when the counter is enabled.
    fn rebase_counter(&mut self, value: u64) {
        self.counter_when_halted = value;
        self.counter_base = Instant::now();
    }

    fn rearm_timer(&mut self, idx: usize) {
        if !self.enabled() || !self.timers[idx].enabled() {
            self.timers[idx].next_deadline = None;
            return;
        }
        let timer_cmp = self.timers[idx].cmp;
        let cmp = if self.timers[idx].is_32bit() {
            timer_cmp & 0xffff_ffff
        } else {
            timer_cmp
        };
        let now_ticks = self.current_ticks();
        let delta = cmp.wrapping_sub(now_ticks);
        let nanos = delta
            .saturating_mul(HPET_CLK_PERIOD_NS)
            .min(3_600 * 1_000_000_000);
        self.timers[idx].next_deadline = Some(Instant::now() + Duration::from_nanos(nanos));
    }
}

/// HPET MMIO device.
pub struct Hpet {
    state: Arc<(Mutex<HpetState>, Condvar)>,
}

impl Hpet {
    /// Create a new HPET device.
    ///
    /// `irq_groups` must contain exactly five entries, in order:
    /// timer0 (IRQ2), timer1 (IRQ8), timer2 (IRQ11), legacy PIT alias
    /// (IRQ2) and legacy RTC alias (IRQ8). The last two are used when
    /// the guest enables LegacyReplacement so timers 0 and 1 fire on
    /// the PIT/RTC IRQ lines.
    pub fn new(irq_groups: Vec<Arc<dyn InterruptSourceGroup>>) -> Self {
        assert_eq!(
            irq_groups.len(),
            HPET_IRQ_GROUP_COUNT,
            "HPET expects {HPET_IRQ_GROUP_COUNT} interrupt groups"
        );
        let state = Arc::new((Mutex::new(HpetState::new()), Condvar::new()));
        let irq_groups = Arc::new(irq_groups);

        Self::start_worker(Arc::clone(&state), irq_groups);

        Self { state }
    }

    fn start_worker(
        state: Arc<(Mutex<HpetState>, Condvar)>,
        irq_groups: Arc<Vec<Arc<dyn InterruptSourceGroup>>>,
    ) {
        let _ = thread::Builder::new()
            .name("hpet".to_string())
            .spawn(move || Self::worker_loop(state, irq_groups));
    }

    fn worker_loop(
        state: Arc<(Mutex<HpetState>, Condvar)>,
        irq_groups: Arc<Vec<Arc<dyn InterruptSourceGroup>>>,
    ) {
        let (lock, cvar) = &*state;
        let mut guard = lock.lock().unwrap();
        loop {
            if guard.shutdown {
                return;
            }

            // Find the soonest deadline among armed timers while the
            // HPET is enabled.
            let now = Instant::now();
            let mut next_wake: Option<Instant> = None;
            let mut to_fire: Vec<usize> = Vec::new();

            if guard.enabled() {
                for idx in 0..HPET_NUM_TIMERS {
                    if let Some(deadline) = guard.timers[idx].next_deadline {
                        if deadline <= now {
                            to_fire.push(idx);
                        } else {
                            next_wake = Some(match next_wake {
                                None => deadline,
                                Some(prev) => prev.min(deadline),
                            });
                        }
                    }
                }
            }

            if !to_fire.is_empty() {
                let legacy = guard.legacy();
                for idx in &to_fire {
                    // Refresh per-timer state with `&mut` while holding
                    // the lock so we can both mark ISR and re-arm.
                    let timer_periodic = guard.timers[*idx].periodic();
                    let timer_period = guard.timers[*idx].period;
                    let timer_32bit = guard.timers[*idx].is_32bit();
                    let level = guard.timers[*idx].config & HPET_TN_TYPE_LEVEL != 0;

                    // Update ISR for level-triggered interrupts.
                    if level {
                        guard.isr |= 1u64 << *idx;
                    }

                    // Pick interrupt-group target.
                    let group_idx = if legacy && *idx == 0 {
                        IRQ_GROUP_LEGACY_PIT
                    } else if legacy && *idx == 1 {
                        IRQ_GROUP_LEGACY_RTC
                    } else {
                        *idx
                    };
                    let group = Arc::clone(&irq_groups[group_idx]);

                    // Re-arm or disarm.
                    if timer_periodic && timer_period != 0 {
                        let new_cmp = guard.timers[*idx].cmp.wrapping_add(timer_period);
                        let new_cmp = if timer_32bit {
                            new_cmp & 0xffff_ffff
                        } else {
                            new_cmp
                        };
                        guard.timers[*idx].cmp = new_cmp;
                        guard.rearm_timer(*idx);
                    } else {
                        guard.timers[*idx].next_deadline = None;
                    }

                    // Drop the lock while triggering the interrupt to
                    // avoid holding it across the kernel call.
                    drop(guard);
                    if let Err(e) = group.trigger(0) {
                        log::trace!("HPET timer{} IRQ injection failed: {e}", *idx);
                    }
                    guard = lock.lock().unwrap();
                    if guard.shutdown {
                        return;
                    }
                }
                // Loop again to recompute next_wake with refreshed
                // deadlines.
                continue;
            }

            // Sleep until next deadline or until somebody pokes us.
            guard = match next_wake {
                Some(deadline) => {
                    let dur = deadline.saturating_duration_since(Instant::now());
                    cvar.wait_timeout(guard, dur).unwrap().0
                }
                None => cvar.wait(guard).unwrap(),
            };
        }
    }

    fn read_register(state: &HpetState, addr: u64) -> u64 {
        if addr <= 0xff {
            match addr & !0x7 {
                HPET_REG_ID => state.capability,
                HPET_REG_CFG => state.config,
                HPET_REG_STATUS => state.isr,
                HPET_REG_COUNTER => state.current_ticks(),
                _ => 0,
            }
        } else {
            let timer_id = ((addr - TIMER_BLOCK_BASE) / TIMER_BLOCK_STRIDE) as usize;
            if timer_id >= HPET_NUM_TIMERS {
                return 0;
            }
            let t = &state.timers[timer_id];
            match (addr - TIMER_BLOCK_BASE) % TIMER_BLOCK_STRIDE & !0x7 {
                TIMER_OFFSET_CFG => t.config,
                TIMER_OFFSET_CMP => t.cmp,
                TIMER_OFFSET_ROUTE => t.fsb,
                _ => 0,
            }
        }
    }

    /// Apply a write of `len` bytes (1, 2, 4 or 8) to `addr`. Returns
    /// `true` if the worker thread should be notified.
    fn write_register(state: &mut HpetState, addr: u64, value: u64, len: usize) -> bool {
        let aligned = addr & !0x7;
        let shift = ((addr & 0x7) as u32) * 8;
        let mask: u64 = if len == 8 {
            u64::MAX
        } else {
            ((1u128 << (len * 8)) - 1) as u64
        };
        let value = (value & mask) << shift;
        let write_mask = mask << shift;
        let mut wake = false;

        if aligned <= 0xff {
            match aligned {
                HPET_REG_ID => {
                    // Read-only.
                }
                HPET_REG_CFG => {
                    let old = state.config;
                    let mut new = (old & !write_mask) | value;
                    new &= HPET_CFG_WRITE_MASK;
                    let activating_enable =
                        (old & HPET_CFG_ENABLE == 0) && (new & HPET_CFG_ENABLE != 0);
                    let deactivating_enable =
                        (old & HPET_CFG_ENABLE != 0) && (new & HPET_CFG_ENABLE == 0);
                    state.config = new;
                    if activating_enable {
                        // Resume main counter from its halted value.
                        state.counter_base = Instant::now();
                        for idx in 0..HPET_NUM_TIMERS {
                            state.rearm_timer(idx);
                        }
                    } else if deactivating_enable {
                        // Capture counter, halt timers.
                        let now = state.current_ticks();
                        state.counter_when_halted = now;
                        for idx in 0..HPET_NUM_TIMERS {
                            state.timers[idx].next_deadline = None;
                        }
                    }
                    wake = true;
                }
                HPET_REG_STATUS => {
                    // Write-1-to-clear per-timer interrupt status bits.
                    let cleared = state.isr & value;
                    state.isr &= !cleared;
                    wake = true;
                }
                HPET_REG_COUNTER => {
                    // Writes are only supposed to be honored when the
                    // counter is halted. We accept them regardless and
                    // simply rebase the host instant.
                    let mut current = state.counter_when_halted;
                    current = (current & !write_mask) | value;
                    if state.enabled() {
                        state.rebase_counter(current);
                    } else {
                        state.counter_when_halted = current;
                    }
                    wake = true;
                }
                _ => {}
            }
        } else {
            let timer_id = ((aligned - TIMER_BLOCK_BASE) / TIMER_BLOCK_STRIDE) as usize;
            if timer_id >= HPET_NUM_TIMERS {
                return false;
            }
            let offset = (aligned - TIMER_BLOCK_BASE) % TIMER_BLOCK_STRIDE;
            match offset {
                TIMER_OFFSET_CFG => {
                    let old = state.timers[timer_id].config;
                    let mut new = (old & !write_mask) | value;
                    let writable = HPET_TN_CFG_WRITE_MASK
                        | (HPET_TN_INT_ROUTE_MASK)
                        | (0xffff_ffffu64 << HPET_TN_INT_ROUTE_CAP_SHIFT);
                    new = (old & !writable) | (new & writable);
                    state.timers[timer_id].config = new;
                    if state.enabled() {
                        state.rearm_timer(timer_id);
                    }
                    wake = true;
                }
                TIMER_OFFSET_CMP => {
                    let timer = &mut state.timers[timer_id];
                    let mut cmp = timer.cmp;
                    cmp = (cmp & !write_mask) | value;
                    if timer.is_32bit() {
                        cmp &= 0xffff_ffff;
                    }
                    if !timer.periodic() || (timer.config & HPET_TN_SETVAL != 0) {
                        timer.cmp = cmp;
                    }
                    if timer.periodic() {
                        let mut period = timer.period;
                        period = (period & !write_mask) | value;
                        if timer.is_32bit() {
                            period &= 0xffff_ffff;
                        }
                        timer.period = period;
                    }
                    timer.config &= !HPET_TN_SETVAL;
                    if state.enabled() {
                        state.rearm_timer(timer_id);
                    }
                    wake = true;
                }
                TIMER_OFFSET_ROUTE => {
                    let timer = &mut state.timers[timer_id];
                    timer.fsb = (timer.fsb & !write_mask) | value;
                }
                _ => {}
            }
        }

        wake
    }
}

impl Drop for Hpet {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.shutdown = true;
        cvar.notify_all();
    }
}

impl BusDevice for Hpet {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let len = data.len();
        if !(len == 1 || len == 2 || len == 4 || len == 8) {
            for byte in data.iter_mut() {
                *byte = 0;
            }
            return;
        }
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > HPET_LEN)
        {
            for byte in data.iter_mut() {
                *byte = 0;
            }
            return;
        }
        let state = self.state.0.lock().unwrap();
        let raw = Hpet::read_register(&state, offset & !0x7);
        let shift = ((offset & 0x7) as u32) * 8;
        let value = raw >> shift;
        let bytes = value.to_le_bytes();
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = bytes[i];
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let len = data.len();
        if !(len == 1 || len == 2 || len == 4 || len == 8) {
            return None;
        }
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > HPET_LEN)
        {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[..len].copy_from_slice(data);
        let value = u64::from_le_bytes(buf);
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        let wake = Hpet::write_register(&mut state, offset, value, len);
        drop(state);
        if wake {
            cvar.notify_all();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_id_matches_qemu() {
        // QEMU advertises 0x8086a201 for a 3-timer 64-bit HPET with
        // legacy replacement support (rev_id=0x01).
        assert_eq!(hpet_block_id(), 0x8086_a201);
    }

    #[test]
    fn capability_layout() {
        let cap = hpet_capability();
        assert_eq!(cap as u32, hpet_block_id());
        assert_eq!((cap >> 32) as u32, HPET_CLK_PERIOD_FS as u32);
    }
}
