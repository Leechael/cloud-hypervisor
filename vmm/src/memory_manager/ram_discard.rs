// Copyright (c) Phala Network. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// RamDiscardListener trait and registry. Mirrors QEMU's RamDiscardManager
// listener mechanism. For TDX, listeners (such as VFIO) need to be told
// when guest pages flip between private and shared so they can drop or
// re-add IOMMU mappings to match the host-accessible state.

use std::io;
use std::sync::{Arc, Mutex};

/// Listener invoked when guest pages flip between shared and private.
///
/// `notify_populate` runs *after* the pages at `gpa..gpa+size` become
/// shared (host-accessible). `host_va` is the host virtual address the
/// listener should use to set up DMA mappings.
///
/// `notify_discard` runs *before* the pages become private
/// (host-inaccessible). Listeners must drop any IOMMU / DMA mapping
/// covering that range before the call returns; the host backing may
/// be punched out immediately after.
pub trait RamDiscardListener: Send + Sync {
    /// Called after pages at `gpa..gpa+size` become shared.
    fn notify_populate(&self, gpa: u64, host_va: u64, size: u64) -> io::Result<()>;
    /// Called before pages at `gpa..gpa+size` become private.
    fn notify_discard(&self, gpa: u64, size: u64);
}

/// Registry of `RamDiscardListener` instances.
///
/// Owned by `MemoryManager` so `convert_guest_memory_region` (driven by
/// the TDX vcpu run-loop via `VmOps::notify_memory_state_change`) can
/// fan out share/private transitions to all interested subsystems
/// (currently VFIO; future: vhost-user, virtio-iommu).
pub struct RamDiscardListenerRegistry {
    listeners: Mutex<Vec<Arc<dyn RamDiscardListener>>>,
}

impl RamDiscardListenerRegistry {
    pub fn new() -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
        }
    }

    pub fn register(&self, listener: Arc<dyn RamDiscardListener>) {
        self.listeners.lock().unwrap().push(listener);
    }

    /// Best-effort removal: removes the first listener whose `Arc` points
    /// at the same allocation as `listener`. Returns true if a listener
    /// was removed.
    ///
    /// TODO: A more robust API would track listeners by id/token so a
    /// caller can deregister without holding the original Arc.
    pub fn unregister(&self, listener: &Arc<dyn RamDiscardListener>) -> bool {
        let mut listeners = self.listeners.lock().unwrap();
        if let Some(pos) = listeners
            .iter()
            .position(|existing| Arc::ptr_eq(existing, listener))
        {
            listeners.remove(pos);
            true
        } else {
            false
        }
    }

    /// Snapshot the current listener list. Returned `Arc`s are cheap to
    /// clone and outlive the registry lock so callers can fire
    /// notifications without holding it.
    pub fn snapshot(&self) -> Vec<Arc<dyn RamDiscardListener>> {
        self.listeners.lock().unwrap().clone()
    }

    /// Fire `notify_populate` on every registered listener for a range
    /// that just became shared. The first error short-circuits and is
    /// returned to the caller.
    pub fn notify_populate(&self, gpa: u64, host_va: u64, size: u64) -> io::Result<()> {
        for listener in self.snapshot() {
            listener.notify_populate(gpa, host_va, size)?;
        }
        Ok(())
    }

    /// Fire `notify_discard` on every registered listener for a range
    /// about to become private. Errors from listeners are swallowed (the
    /// trait method is infallible) — the conversion must proceed even if
    /// a listener's unmap fails, otherwise the guest hangs.
    pub fn notify_discard(&self, gpa: u64, size: u64) {
        for listener in self.snapshot() {
            listener.notify_discard(gpa, size);
        }
    }
}

impl Default for RamDiscardListenerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
