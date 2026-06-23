pub mod process_tree;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationSource {
    ProcessLineage,
    Launcher,
    Hook,
    IdeExtension,
    Mcp,
    Framework,
    TimeWindow,
}

#[derive(Debug, Clone)]
pub struct AttributionConfidence {
    pub intent: f32,
    pub effect: f32,
    pub causality: f32,
}

#[derive(Debug, Clone)]
pub struct CorrelationEdge {
    pub source: CorrelationSource,
    pub confidence: AttributionConfidence,
    pub evidence_json: String,
}
