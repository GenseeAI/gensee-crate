#[derive(Debug, Clone)]
pub struct RiskScore {
    pub score: f32,
    pub explanation: String,
}

pub trait RiskClassifier {
    fn score(&self, features: &[f32]) -> RiskScore;
}
