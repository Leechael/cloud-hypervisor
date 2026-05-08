// Copyright 2026 Cloud Hypervisor Authors.
//
// SPDX-License-Identifier: Apache-2.0

//! Intel ICH9 LPC PM aggregator device.
//!
//! q35 firmwares (OVMF / SeaBIOS) and Linux probe a fixed set of
//! PMBASE-relative registers that the legacy [`Q35Pm1Cnt`] / [`Q35Pm1Evt`]
//! stubs do not cover. This module implements the remaining PMBASE block
//! (offsets 0x10..0x80) so that:
//!
//!   * Linux can declare GPE0 (no events ever fire because no source is
//!     wired, but the register window must read back as zeroes).
//!   * OVMF can probe SMI_EN and observe SMM is disabled (we always
//!     return zero on read).
//!   * Linux's `iTCO_wdt` / lpc_ich driver can probe the TCO window
//!     without faulting; writes are absorbed and reads return zero.
//!
//! The block is intentionally **not** registered at offsets 0x00..0x0f:
//! PM1_EVT (0x00), PM1_CNT (0x04) and PM_TMR (0x08) are owned by the
//! existing [`Q35Pm1Evt`], [`Q35Pm1Cnt`] and `AcpiPmTimerDevice` and
//! continue to handle those offsets unchanged.
//!
//! No SMM emulation is provided. Writes to SMI_EN/SMI_STS are stored
//! purely so that read-modify-write probes do not see surprising
//! values, but no SMI is ever raised. TCO timer writes are dropped.
//!
//! Reference: QEMU `hw/acpi/ich9.c::ich9_pm_init`,
//! `include/hw/southbridge/ich9.h` (`ICH9_PMIO_*`).

use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Barrier};

use vm_device::BusDevice;

/// ICH9 PMBASE-relative register offsets.
///
/// The block we own starts at PMBASE+0x10 and extends to PMBASE+0x80.
/// Offsets in this module are expressed relative to the device base
/// (i.e. PMBASE+0x10 == 0).
pub const ICH9_PM_BLOCK_OFFSET: u16 = 0x10;
/// Length of the PM block we register on the IO bus.
pub const ICH9_PM_BLOCK_LEN: u16 = 0x70;

/// Absolute PMBASE-relative offset of GPE0_STS (status). Length 4 bytes.
pub const ICH9_PMIO_GPE0_STS: u16 = 0x20;
/// Absolute PMBASE-relative offset of GPE0_EN (enable). Length 4 bytes.
pub const ICH9_PMIO_GPE0_EN: u16 = 0x28;
/// GPE0 block length advertised in FADT.GPE0_BLK_LEN.
///
/// ACPI 6.x defines `GPE0_BLK_LEN` as the *combined* size of status +
/// enable halves; `gpe0_blk_len/2` is the size of each half. We expose
/// 4 bytes of status and 4 bytes of enable, so the FADT value is 8.
pub const ICH9_PMIO_GPE0_BLK_LEN: u8 = 8;

/// Absolute PMBASE-relative offset of SMI_EN. Length 4 bytes.
pub const ICH9_PMIO_SMI_EN: u16 = 0x30;
/// Absolute PMBASE-relative offset of SMI_STS. Length 4 bytes.
pub const ICH9_PMIO_SMI_STS: u16 = 0x34;

/// Absolute PMBASE-relative offset of the TCO sub-block.
pub const ICH9_PMIO_TCO_BASE: u16 = 0x60;
/// TCO sub-block length per the ICH9 datasheet.
pub const ICH9_PMIO_TCO_LEN: u16 = 0x20;

// ---- TCO register offsets (relative to ICH9_PMIO_TCO_BASE) ------------------
const TCO_RLD: u16 = 0x00; // 16-bit reload (write ignored)
const TCO_DAT_IN: u16 = 0x02; // 8-bit
const TCO_DAT_OUT: u16 = 0x03; // 8-bit
const TCO1_STS: u16 = 0x04; // 16-bit (W1C)
const TCO2_STS: u16 = 0x06; // 16-bit (W1C)
const TCO1_CNT: u16 = 0x08; // 16-bit
const TCO2_CNT: u16 = 0x0a; // 16-bit
const TCO_MESSAGE1: u16 = 0x0c; // 8-bit
const TCO_MESSAGE2: u16 = 0x0d; // 8-bit
const TCO_WDSTATUS: u16 = 0x0e; // 8-bit (W1C)
const TCO_SW_IRQ_GEN: u16 = 0x10; // 8-bit
#[cfg(test)]
const TCO_TMR: u16 = 0x12; // 16-bit (timer; writes ignored, reads 0)

/// TCO register file.
///
/// Mirrors the ICH9 datasheet layout. Write semantics are intentionally
/// minimal: status registers implement write-1-to-clear, control
/// registers store the written value, and the timer register is fully
/// inert. No countdown is ever performed; this device exists so that
/// guest probes complete without fault.
#[derive(Default)]
struct TcoRegs {
    rld: AtomicU16,
    dat_in: u8,
    dat_out: u8,
    sts1: AtomicU16,
    sts2: AtomicU16,
    cnt1: AtomicU16,
    cnt2: AtomicU16,
    message1: u8,
    message2: u8,
    wdstatus: AtomicU16, // 8-bit field stored in low byte
    sw_irq_gen: u8,
}

/// ICH9 LPC PM aggregator covering GPE0, SMI_*, and TCO.
///
/// This device intentionally registers at PMBASE+0x10 (length 0x70). It
/// is *not* responsible for PM1_EVT / PM1_CNT / PM_TMR which live at
/// PMBASE+0x00..0x0f and are handled by their dedicated devices.
pub struct Ich9Pm {
    gpe0_sts: AtomicU32,
    gpe0_en: AtomicU32,
    smi_en: AtomicU32,
    smi_sts: AtomicU32,
    tco: TcoRegs,
}

impl Ich9Pm {
    pub fn new() -> Self {
        Self {
            gpe0_sts: AtomicU32::new(0),
            gpe0_en: AtomicU32::new(0),
            smi_en: AtomicU32::new(0),
            smi_sts: AtomicU32::new(0),
            tco: TcoRegs::default(),
        }
    }

    /// Build a u32 by overlaying `data[data_off..]` onto the existing
    /// `current` value at `byte_in_reg` within the register.
    fn merge_u32(current: u32, byte_in_reg: usize, data: &[u8], data_off: usize) -> u32 {
        let mut bytes = current.to_le_bytes();
        for (i, src) in data.iter().enumerate().skip(data_off) {
            let dst_idx = byte_in_reg + (i - data_off);
            if let Some(dst) = bytes.get_mut(dst_idx) {
                *dst = *src;
            }
        }
        u32::from_le_bytes(bytes)
    }

    fn merge_u16(current: u16, byte_in_reg: usize, data: &[u8], data_off: usize) -> u16 {
        let mut bytes = current.to_le_bytes();
        for (i, src) in data.iter().enumerate().skip(data_off) {
            let dst_idx = byte_in_reg + (i - data_off);
            if let Some(dst) = bytes.get_mut(dst_idx) {
                *dst = *src;
            }
        }
        u16::from_le_bytes(bytes)
    }

    /// Apply a write-1-to-clear update to a u32 status register.
    fn w1c_u32(reg: &AtomicU32, byte_in_reg: usize, data: &[u8], data_off: usize) {
        let cur = reg.load(Ordering::SeqCst);
        let written = Self::merge_u32(0, byte_in_reg, data, data_off);
        // Only the bits whose byte was actually written can be cleared.
        let mut mask: u32 = 0;
        for (i, _) in data.iter().enumerate().skip(data_off) {
            let dst_idx = byte_in_reg + (i - data_off);
            if dst_idx < 4 {
                mask |= 0xffu32 << (dst_idx * 8);
            }
        }
        let new_val = cur & !(written & mask);
        reg.store(new_val, Ordering::SeqCst);
    }

    fn w1c_u16(reg: &AtomicU16, byte_in_reg: usize, data: &[u8], data_off: usize) {
        let cur = reg.load(Ordering::SeqCst);
        let written = Self::merge_u16(0, byte_in_reg, data, data_off);
        let mut mask: u16 = 0;
        for (i, _) in data.iter().enumerate().skip(data_off) {
            let dst_idx = byte_in_reg + (i - data_off);
            if dst_idx < 2 {
                mask |= 0xffu16 << (dst_idx * 8);
            }
        }
        let new_val = cur & !(written & mask);
        reg.store(new_val, Ordering::SeqCst);
    }

    fn handle_read(&self, abs_off: u16, data: &mut [u8]) {
        // Default fill is zero. Each byte is then resolved against the
        // ICH9 register map; offsets that fall outside any defined
        // register stay zero, which matches QEMU's behavior for the
        // unimplemented holes in the PMBASE block.
        for (i, byte) in data.iter_mut().enumerate() {
            let abs = abs_off as usize + i;
            *byte = match abs {
                0x20..=0x23 => {
                    let v = self.gpe0_sts.load(Ordering::SeqCst).to_le_bytes();
                    v[abs - 0x20]
                }
                0x28..=0x2b => {
                    let v = self.gpe0_en.load(Ordering::SeqCst).to_le_bytes();
                    v[abs - 0x28]
                }
                0x30..=0x33 => {
                    // SMI_EN: report zero so OVMF concludes SMM is off.
                    let v = self.smi_en.load(Ordering::SeqCst).to_le_bytes();
                    v[abs - 0x30]
                }
                0x34..=0x37 => {
                    let v = self.smi_sts.load(Ordering::SeqCst).to_le_bytes();
                    v[abs - 0x34]
                }
                0x60..=0x7f => self.tco_read_byte((abs - 0x60) as u16),
                _ => 0,
            };
        }
    }

    fn tco_read_byte(&self, off: u16) -> u8 {
        // Decode by sub-register; reads outside a defined register read as 0.
        match off {
            // TCO_RLD (16-bit)
            x if x == TCO_RLD || x == TCO_RLD + 1 => {
                self.tco.rld.load(Ordering::SeqCst).to_le_bytes()[(x - TCO_RLD) as usize]
            }
            x if x == TCO_DAT_IN => self.tco.dat_in,
            x if x == TCO_DAT_OUT => self.tco.dat_out,
            // TCO1_STS (16-bit, W1C)
            x if x == TCO1_STS || x == TCO1_STS + 1 => {
                self.tco.sts1.load(Ordering::SeqCst).to_le_bytes()[(x - TCO1_STS) as usize]
            }
            x if x == TCO2_STS || x == TCO2_STS + 1 => {
                self.tco.sts2.load(Ordering::SeqCst).to_le_bytes()[(x - TCO2_STS) as usize]
            }
            x if x == TCO1_CNT || x == TCO1_CNT + 1 => {
                self.tco.cnt1.load(Ordering::SeqCst).to_le_bytes()[(x - TCO1_CNT) as usize]
            }
            x if x == TCO2_CNT || x == TCO2_CNT + 1 => {
                self.tco.cnt2.load(Ordering::SeqCst).to_le_bytes()[(x - TCO2_CNT) as usize]
            }
            x if x == TCO_MESSAGE1 => self.tco.message1,
            x if x == TCO_MESSAGE2 => self.tco.message2,
            x if x == TCO_WDSTATUS => self.tco.wdstatus.load(Ordering::SeqCst) as u8,
            x if x == TCO_SW_IRQ_GEN => self.tco.sw_irq_gen,
            // TCO_TMR (16-bit) reads as 0.
            _ => 0,
        }
    }

    fn handle_write(&mut self, abs_off: u16, data: &[u8]) {
        // Walk each byte; per spec each register is 8/16/32 bit but
        // guests may issue any access size, so we resolve byte-by-byte
        // and aggregate writes that fall inside a multi-byte register.
        // To do that efficiently we group by region.
        //
        // Strategy: scan once and detect region for each byte. For W1C
        // status registers we need the full written value for a clean
        // mask, so we slice by region.

        let start = abs_off as usize;
        let end = start + data.len();

        // GPE0_STS (W1C)
        if let Some((rel, slice_off, slice_len)) =
            slice_within(start, end, 0x20, 4)
        {
            Self::w1c_u32(&self.gpe0_sts, rel, &data[slice_off..slice_off + slice_len], 0);
        }

        // GPE0_EN (plain store)
        if let Some((rel, slice_off, slice_len)) =
            slice_within(start, end, 0x28, 4)
        {
            let cur = self.gpe0_en.load(Ordering::SeqCst);
            let new = Self::merge_u32(cur, rel, &data[slice_off..slice_off + slice_len], 0);
            self.gpe0_en.store(new, Ordering::SeqCst);
        }

        // SMI_EN (plain store; never raises an SMI)
        if let Some((rel, slice_off, slice_len)) =
            slice_within(start, end, 0x30, 4)
        {
            let cur = self.smi_en.load(Ordering::SeqCst);
            let new = Self::merge_u32(cur, rel, &data[slice_off..slice_off + slice_len], 0);
            self.smi_en.store(new, Ordering::SeqCst);
        }

        // SMI_STS (W1C)
        if let Some((rel, slice_off, slice_len)) =
            slice_within(start, end, 0x34, 4)
        {
            Self::w1c_u32(&self.smi_sts, rel, &data[slice_off..slice_off + slice_len], 0);
        }

        // TCO sub-block (0x60..0x80)
        if let Some((rel, slice_off, slice_len)) =
            slice_within(start, end, 0x60, ICH9_PMIO_TCO_LEN as usize)
        {
            self.tco_write(rel as u16, &data[slice_off..slice_off + slice_len]);
        }
    }

    fn tco_write(&mut self, off: u16, data: &[u8]) {
        // Walk byte by byte across [off, off+data.len()) and dispatch by
        // sub-register. This keeps the dispatch logic uniform regardless
        // of access size.
        for (i, byte) in data.iter().enumerate() {
            let cur_off = off + i as u16;
            match cur_off {
                // TCO_RLD: write resets reload (we ignore the actual value).
                x if x == TCO_RLD || x == TCO_RLD + 1 => {
                    let mut bytes = self.tco.rld.load(Ordering::SeqCst).to_le_bytes();
                    bytes[(x - TCO_RLD) as usize] = *byte;
                    self.tco.rld.store(u16::from_le_bytes(bytes), Ordering::SeqCst);
                }
                x if x == TCO_DAT_IN => self.tco.dat_in = *byte,
                x if x == TCO_DAT_OUT => self.tco.dat_out = *byte,
                // TCO1_STS / TCO2_STS / TCO_WDSTATUS are W1C.
                x if x == TCO1_STS || x == TCO1_STS + 1 => {
                    Self::w1c_u16(&self.tco.sts1, (x - TCO1_STS) as usize, &[*byte], 0);
                }
                x if x == TCO2_STS || x == TCO2_STS + 1 => {
                    Self::w1c_u16(&self.tco.sts2, (x - TCO2_STS) as usize, &[*byte], 0);
                }
                x if x == TCO1_CNT || x == TCO1_CNT + 1 => {
                    let mut bytes = self.tco.cnt1.load(Ordering::SeqCst).to_le_bytes();
                    bytes[(x - TCO1_CNT) as usize] = *byte;
                    self.tco.cnt1.store(u16::from_le_bytes(bytes), Ordering::SeqCst);
                }
                x if x == TCO2_CNT || x == TCO2_CNT + 1 => {
                    let mut bytes = self.tco.cnt2.load(Ordering::SeqCst).to_le_bytes();
                    bytes[(x - TCO2_CNT) as usize] = *byte;
                    self.tco.cnt2.store(u16::from_le_bytes(bytes), Ordering::SeqCst);
                }
                x if x == TCO_MESSAGE1 => self.tco.message1 = *byte,
                x if x == TCO_MESSAGE2 => self.tco.message2 = *byte,
                x if x == TCO_WDSTATUS => {
                    let cur = self.tco.wdstatus.load(Ordering::SeqCst);
                    let cleared = (cur as u8) & !*byte;
                    self.tco.wdstatus.store(cleared as u16, Ordering::SeqCst);
                }
                x if x == TCO_SW_IRQ_GEN => self.tco.sw_irq_gen = *byte,
                // TCO_TMR (and any other offset within the window) is ignored.
                _ => {}
            }
        }
    }
}

impl Default for Ich9Pm {
    fn default() -> Self {
        Self::new()
    }
}

impl BusDevice for Ich9Pm {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        // The bus passes us offsets relative to our registration base
        // (ICH9_PM_BLOCK_OFFSET), so add it back to get the absolute
        // PMBASE-relative offset used by the ICH9 datasheet.
        let abs = ICH9_PM_BLOCK_OFFSET + offset as u16;
        self.handle_read(abs, data);
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.is_empty() {
            return None;
        }
        let abs = ICH9_PM_BLOCK_OFFSET + offset as u16;
        self.handle_write(abs, data);
        None
    }
}

/// Compute the intersection of the requested `[start, end)` byte range
/// with the register at `[reg_off, reg_off + reg_len)`. Returns
/// `(byte_in_reg, slice_off, slice_len)` where:
///   * `byte_in_reg` is the offset of the first overlapping byte
///     within the register.
///   * `slice_off` is the offset within the caller's `data` slice at
///     which the overlap begins.
///   * `slice_len` is the number of overlapping bytes.
fn slice_within(
    start: usize,
    end: usize,
    reg_off: usize,
    reg_len: usize,
) -> Option<(usize, usize, usize)> {
    let reg_end = reg_off + reg_len;
    let lo = start.max(reg_off);
    let hi = end.min(reg_end);
    if hi <= lo {
        return None;
    }
    Some((lo - reg_off, lo - start, hi - lo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpe0_sts_w1c() {
        let mut dev = Ich9Pm::new();
        // Pretend a status bit is latched.
        dev.gpe0_sts.store(0x0000_0003, Ordering::SeqCst);
        // Write 0x01 to the low byte: bit 0 should clear, bit 1 stays.
        dev.handle_write(0x20, &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(dev.gpe0_sts.load(Ordering::SeqCst), 0x0000_0002);
    }

    #[test]
    fn gpe0_en_plain_store() {
        let mut dev = Ich9Pm::new();
        dev.handle_write(0x28, &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(dev.gpe0_en.load(Ordering::SeqCst), 0xddccbbaa);
        let mut buf = [0u8; 4];
        dev.handle_read(0x28, &mut buf);
        assert_eq!(buf, [0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn smi_en_returns_what_was_written_but_does_nothing() {
        let mut dev = Ich9Pm::new();
        dev.handle_write(0x30, &[0x12, 0x34, 0x56, 0x78]);
        // Reads echo back (no SMI delivery exists).
        let mut buf = [0u8; 4];
        dev.handle_read(0x30, &mut buf);
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn tco_timer_writes_ignored() {
        let mut dev = Ich9Pm::new();
        dev.handle_write(0x60 + TCO_TMR, &[0x55, 0xaa]);
        let mut buf = [0u8; 2];
        dev.handle_read(0x60 + TCO_TMR, &mut buf);
        assert_eq!(buf, [0, 0]);
    }

    #[test]
    fn tco1_sts_w1c() {
        let mut dev = Ich9Pm::new();
        dev.tco.sts1.store(0x000f, Ordering::SeqCst);
        dev.handle_write(0x60 + TCO1_STS, &[0x05, 0x00]);
        assert_eq!(dev.tco.sts1.load(Ordering::SeqCst), 0x000a);
    }

    #[test]
    fn unmapped_offset_reads_zero() {
        let dev = Ich9Pm::new();
        let mut buf = [0xffu8; 4];
        dev.handle_read(0x10, &mut buf);
        assert_eq!(buf, [0, 0, 0, 0]);
    }
}
