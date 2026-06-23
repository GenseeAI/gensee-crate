use crate::events::AgentEvent;

#[derive(Debug, Clone)]
pub struct BehavioralFingerprint {
    pub process_tree_id: String,
    pub event_count: usize,
}

pub fn fingerprint(events: &[AgentEvent]) -> Option<BehavioralFingerprint> {
    let first = events.first()?;
    Some(BehavioralFingerprint {
        process_tree_id: first.attribution.process_tree_id.clone(),
        event_count: events.len(),
    })
}
