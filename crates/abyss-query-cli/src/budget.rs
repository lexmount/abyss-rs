//! Aggregate output budget independent of per-response HTTP limits.

use crate::error::QueryError;
use serde::Serialize;

pub struct OutputBudget {
    used: usize,
}
impl OutputBudget {
    pub const fn new() -> Self {
        Self { used: 0 }
    }
    pub fn include<T: Serialize>(&mut self, value: &T) -> Result<(), QueryError> {
        self.used = self.used.saturating_add(serde_json::to_vec(value)?.len());
        if self.used > 64 * 1024 * 1024 {
            return Err(QueryError::Protocol(
                "combined output exceeds 64 MiB; reduce --max-items or query a narrower time range",
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::OutputBudget;
    #[test]
    fn aggregate_budget_is_checked_without_integer_wraparound() {
        let mut budget = OutputBudget { used: usize::MAX };
        assert!(
            budget.include(&"small").is_err(),
            "overflow must never reset the budget"
        );
        assert!(
            OutputBudget::new().include(&"small").is_ok(),
            "ordinary output fits"
        );
    }
}
