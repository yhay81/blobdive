use std::time::{Duration, Instant};

use crate::{
    error::BlobError,
    model::{BudgetLimits, BudgetUsage, TruncationReason},
};

#[derive(Debug)]
pub struct Budget {
    pub limits: BudgetLimits,
    started: Instant,
    deadline: Instant,
    source_bytes: u64,
    decompressed_bytes: u64,
    entries_visited: u64,
    nodes_emitted: u64,
}

impl Budget {
    #[must_use]
    pub fn new(limits: BudgetLimits, source_bytes: u64) -> Self {
        Self::new_at(limits, source_bytes, Instant::now())
    }

    #[must_use]
    pub fn new_at(limits: BudgetLimits, source_bytes: u64, started: Instant) -> Self {
        let deadline = started
            .checked_add(Duration::from_millis(limits.timeout_ms))
            .unwrap_or(started);
        Self {
            limits,
            started,
            deadline,
            source_bytes,
            decompressed_bytes: 0,
            entries_visited: 0,
            nodes_emitted: 0,
        }
    }

    /// Confirms that the cooperative wall-clock deadline has not elapsed.
    ///
    /// # Errors
    ///
    /// Returns [`BlobError::Timeout`] after the configured deadline.
    pub fn ensure_time(&self) -> Result<(), BlobError> {
        if Instant::now() >= self.deadline {
            Err(BlobError::Timeout)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn time_exhausted(&self) -> bool {
        Instant::now() >= self.deadline
    }

    #[must_use]
    pub fn visit_entry(&mut self) -> bool {
        if self.entries_visited >= self.limits.max_entries {
            false
        } else {
            self.entries_visited += 1;
            true
        }
    }

    pub fn emit_node(&mut self) {
        self.nodes_emitted = self.nodes_emitted.saturating_add(1);
    }

    #[must_use]
    pub fn remaining_decompressed(&self) -> u64 {
        self.limits
            .max_decompressed_bytes
            .saturating_sub(self.decompressed_bytes)
    }

    #[must_use]
    pub fn decompression_allowance(&self, compressed_size: u64) -> u64 {
        let ratio_limit = compressed_size
            .max(1)
            .saturating_mul(self.limits.max_compression_ratio);
        self.remaining_decompressed().min(ratio_limit)
    }

    pub fn claim_decompressed(&mut self, amount: u64) {
        self.decompressed_bytes = self.decompressed_bytes.saturating_add(amount);
    }

    #[must_use]
    pub fn decompression_block_reason(
        &self,
        compressed_size: u64,
        uncompressed_size: u64,
    ) -> Option<TruncationReason> {
        if uncompressed_size > self.remaining_decompressed() {
            Some(TruncationReason::MaxDecompressedBytes)
        } else if uncompressed_size
            > compressed_size
                .max(1)
                .saturating_mul(self.limits.max_compression_ratio)
        {
            Some(TruncationReason::MaxCompressionRatio)
        } else {
            None
        }
    }

    #[must_use]
    pub fn usage(&self) -> BudgetUsage {
        BudgetUsage {
            source_bytes: self.source_bytes,
            decompressed_bytes: self.decompressed_bytes,
            entries_visited: self.entries_visited,
            nodes_emitted: self.nodes_emitted,
            elapsed_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }
}
