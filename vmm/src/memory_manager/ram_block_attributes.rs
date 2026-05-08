// Copyright (c) Phala Network. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Per-RAM-region shared/private bitmap. Mirrors QEMU's
// `RamBlockAttributes`: one bit per host page tracking whether the page
// is currently in the shared (host-accessible) state.
//
// The bitmap is the source of truth for "what is shared right now". It
// is updated synchronously with `set_memory_attributes` calls in
// `convert_guest_memory_region`, and listeners can query it via
// `shared_ranges` to know what to populate when first registering.

/// Per-region shared/private page bitmap.
///
/// `shared_bits[i / 64]` bit `i % 64` is `1` if the i-th page (counting
/// from `region_start`) is currently shared, `0` if private. New
/// regions start fully private (all zero).
pub struct RamBlockAttributes {
    page_size: usize,
    region_start: u64,
    region_size: u64,
    shared_bits: Vec<u64>,
}

impl RamBlockAttributes {
    /// Create a new attributes bitmap covering `[region_start,
    /// region_start + region_size)`. `page_size` must be > 0; both the
    /// region start and size must be page-aligned.
    pub fn new(region_start: u64, region_size: u64, page_size: usize) -> Self {
        assert!(page_size > 0, "page_size must be non-zero");
        assert!(
            region_start.is_multiple_of(page_size as u64),
            "region_start {region_start:#x} must be page-aligned to {page_size:#x}"
        );
        assert!(
            region_size.is_multiple_of(page_size as u64),
            "region_size {region_size:#x} must be page-aligned to {page_size:#x}"
        );
        let pages = (region_size / page_size as u64) as usize;
        let words = pages.div_ceil(64);
        Self {
            page_size,
            region_start,
            region_size,
            shared_bits: vec![0u64; words],
        }
    }

    pub fn region_start(&self) -> u64 {
        self.region_start
    }

    pub fn region_size(&self) -> u64 {
        self.region_size
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// True if `gpa` falls within `[region_start, region_start + region_size)`.
    pub fn contains(&self, gpa: u64) -> bool {
        gpa >= self.region_start && gpa < self.region_start.saturating_add(self.region_size)
    }

    /// True if the page containing `gpa` is currently shared. Returns
    /// false if `gpa` is outside this region.
    pub fn is_shared(&self, gpa: u64) -> bool {
        if !self.contains(gpa) {
            return false;
        }
        let page = ((gpa - self.region_start) / self.page_size as u64) as usize;
        self.bit(page)
    }

    /// Mark `[gpa, gpa + size)` as shared. Ranges outside this region
    /// are silently ignored (caller may pass a wider range that spans
    /// multiple regions).
    pub fn set_shared(&mut self, gpa: u64, size: u64) {
        self.update_range(gpa, size, true);
    }

    /// Mark `[gpa, gpa + size)` as private.
    pub fn set_private(&mut self, gpa: u64, size: u64) {
        self.update_range(gpa, size, false);
    }

    /// Enumerate `(gpa, size)` runs of currently-shared pages within
    /// `[gpa, gpa + size)`. Used by listeners on registration to
    /// replay the current shared state.
    pub fn shared_ranges(&self, gpa: u64, size: u64) -> Vec<(u64, u64)> {
        let (start_page, end_page) = match self.clamp_to_pages(gpa, size) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut out = Vec::new();
        let mut run_start: Option<usize> = None;
        for page in start_page..end_page {
            if self.bit(page) {
                if run_start.is_none() {
                    run_start = Some(page);
                }
            } else if let Some(s) = run_start.take() {
                out.push(self.range_for(s, page));
            }
        }
        if let Some(s) = run_start {
            out.push(self.range_for(s, end_page));
        }
        out
    }

    fn update_range(&mut self, gpa: u64, size: u64, shared: bool) {
        let (start_page, end_page) = match self.clamp_to_pages(gpa, size) {
            Some(p) => p,
            None => return,
        };
        for page in start_page..end_page {
            self.set_bit(page, shared);
        }
    }

    /// Convert a (gpa, size) request into a [start_page, end_page) range
    /// fully clamped to this region. Returns None for empty intersections.
    fn clamp_to_pages(&self, gpa: u64, size: u64) -> Option<(usize, usize)> {
        let region_end = self.region_start.saturating_add(self.region_size);
        let req_end = gpa.checked_add(size)?;
        let start = gpa.max(self.region_start);
        let end = req_end.min(region_end);
        if start >= end {
            return None;
        }
        let ps = self.page_size as u64;
        // Round inward: only fully-covered pages count.
        let aligned_start = start.div_ceil(ps).checked_mul(ps)?;
        let aligned_end = (end / ps).checked_mul(ps)?;
        if aligned_start >= aligned_end {
            return None;
        }
        let start_page = ((aligned_start - self.region_start) / ps) as usize;
        let end_page = ((aligned_end - self.region_start) / ps) as usize;
        Some((start_page, end_page))
    }

    fn range_for(&self, start_page: usize, end_page: usize) -> (u64, u64) {
        let ps = self.page_size as u64;
        let gpa = self.region_start + start_page as u64 * ps;
        let size = (end_page - start_page) as u64 * ps;
        (gpa, size)
    }

    fn bit(&self, page: usize) -> bool {
        self.shared_bits[page / 64] & (1u64 << (page % 64)) != 0
    }

    fn set_bit(&mut self, page: usize, value: bool) {
        let mask = 1u64 << (page % 64);
        if value {
            self.shared_bits[page / 64] |= mask;
        } else {
            self.shared_bits[page / 64] &= !mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;
    const BASE: u64 = 0x1000_0000;
    const SIZE: u64 = 64 * PAGE as u64;

    #[test]
    fn starts_all_private() {
        let attrs = RamBlockAttributes::new(BASE, SIZE, PAGE);
        for page in 0..(SIZE / PAGE as u64) {
            assert!(!attrs.is_shared(BASE + page * PAGE as u64));
        }
        assert!(attrs.shared_ranges(BASE, SIZE).is_empty());
    }

    #[test]
    fn set_and_query_round_trip() {
        let mut attrs = RamBlockAttributes::new(BASE, SIZE, PAGE);
        attrs.set_shared(BASE + 4 * PAGE as u64, 3 * PAGE as u64);
        attrs.set_shared(BASE + 10 * PAGE as u64, PAGE as u64);

        let ranges = attrs.shared_ranges(BASE, SIZE);
        assert_eq!(
            ranges,
            vec![
                (BASE + 4 * PAGE as u64, 3 * PAGE as u64),
                (BASE + 10 * PAGE as u64, PAGE as u64),
            ]
        );

        attrs.set_private(BASE + 5 * PAGE as u64, PAGE as u64);
        let ranges = attrs.shared_ranges(BASE, SIZE);
        assert_eq!(
            ranges,
            vec![
                (BASE + 4 * PAGE as u64, PAGE as u64),
                (BASE + 6 * PAGE as u64, PAGE as u64),
                (BASE + 10 * PAGE as u64, PAGE as u64),
            ]
        );
    }

    #[test]
    fn out_of_range_is_noop() {
        let mut attrs = RamBlockAttributes::new(BASE, SIZE, PAGE);
        attrs.set_shared(BASE - PAGE as u64, PAGE as u64);
        attrs.set_shared(BASE + SIZE, PAGE as u64);
        assert!(attrs.shared_ranges(BASE, SIZE).is_empty());
    }
}
