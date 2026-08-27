//! Harness identity and source evidence produced independently of LLM parsing.

use super::HarnessId;

/// One explainable source marker used to identify a calling Harness.
#[derive(Clone, Debug)]
pub enum HarnessEvidence {
    /// Source process name or executable path matched a known product.
    Process(String),
    /// Platform application identity matched a known product.
    ApplicationId(String),
    /// A product-specific request header matched.
    Header(&'static str),
    /// A private product route matched.
    Path(String),
}

/// Harness identity composed with a separately parsed LLM interaction.
#[derive(Clone, Debug)]
pub struct HarnessDetection {
    pub harness_id: HarnessId,
    pub evidence: Vec<HarnessEvidence>,
    pub version: Option<String>,
    pub working_directory: Option<String>,
}

impl HarnessDetection {
    pub fn evidence_names(&self) -> Vec<String> {
        self.evidence
            .iter()
            .map(|evidence| match evidence {
                HarnessEvidence::Process(value) => format!("process:{value}"),
                HarnessEvidence::ApplicationId(value) => format!("application_id:{value}"),
                HarnessEvidence::Header(value) => format!("header:{value}"),
                HarnessEvidence::Path(value) => format!("path:{value}"),
            })
            .collect()
    }
}
