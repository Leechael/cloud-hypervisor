// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

mod cmos;
#[cfg(target_arch = "x86_64")]
mod debug_port;
#[cfg(feature = "fw_cfg")]
pub mod fw_cfg;
#[cfg(target_arch = "x86_64")]
mod fwdebug;
#[cfg(target_arch = "aarch64")]
mod gpio_pl061;
#[cfg(target_arch = "x86_64")]
mod hpet;
mod i8042;
#[cfg(target_arch = "x86_64")]
mod pc_compat;
#[cfg(target_arch = "aarch64")]
mod rtc_pl031;
mod serial;
#[cfg(target_arch = "aarch64")]
mod uart_pl011;

pub use self::cmos::Cmos;
#[cfg(target_arch = "x86_64")]
pub use self::debug_port::DebugPort;
#[cfg(feature = "fw_cfg")]
pub use self::fw_cfg::FwCfg;
#[cfg(target_arch = "x86_64")]
pub use self::fwdebug::FwDebugDevice;
#[cfg(target_arch = "aarch64")]
pub use self::gpio_pl061::Error as GpioDeviceError;
#[cfg(target_arch = "aarch64")]
pub use self::gpio_pl061::Gpio;
#[cfg(target_arch = "x86_64")]
pub use self::hpet::{HPET_BASE, HPET_LEN, HPET_NUM_TIMERS, Hpet, hpet_block_id};
pub use self::i8042::I8042Device;
#[cfg(target_arch = "x86_64")]
pub use self::pc_compat::{
    ApmStub, ComPortStub, PicStub, PitStub, Port61, Port92, Q35Pm1Cnt, Q35Pm1Evt,
};
#[cfg(target_arch = "aarch64")]
pub use self::rtc_pl031::Rtc;
pub use self::serial::Serial;
#[cfg(target_arch = "aarch64")]
pub use self::uart_pl011::Pl011;
