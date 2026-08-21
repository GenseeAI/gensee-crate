//! Provider-neutral decisions for network effects crossing an operation envelope.
//!
//! This module deliberately reasons about resolved destinations, protocols,
//! ports, expiry, and mediation requirements. It does not recognize package
//! managers, repository products, or attack signatures.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const NETWORK_BOUNDARY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkEffectKind {
    DirectConnect,
    Http { method: String, authority: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBoundaryEvent {
    pub schema_version: u32,
    pub operation_id: String,
    pub source_run_id: String,
    pub process_id: u32,
    /// An exact, already-resolved IP address. Hostname policy belongs at the
    /// DNS/HTTP mediator; the enforcement lease is always pinned to an IP.
    pub destination: String,
    pub protocol: NetworkProtocol,
    pub port: u16,
    pub effect: NetworkEffectKind,
    pub observed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpointGrant {
    pub destination: String,
    pub protocol: NetworkProtocol,
    pub ports: Vec<u16>,
    /// `None` is valid only for the operation's immutable baseline envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
}

/// A policy-authored tuple that is eligible for temporary authority. Keeping
/// destination, protocol, and ports in one record avoids accidentally
/// authorizing the cross-product of independent allowlists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkLeaseScope {
    pub destination: String,
    pub protocol: NetworkProtocol,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCapabilityEnvelope {
    #[serde(default)]
    pub grants: Vec<NetworkEndpointGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBoundaryPolicy {
    pub schema_version: u32,
    /// Additional CIDRs that are never eligible for new authority. The
    /// built-in private, local, metadata, and non-unicast restrictions are
    /// always enforced and cannot be removed here. An exact baseline grant can
    /// still represent a deliberately provisioned local mediator.
    #[serde(default)]
    pub restricted_destinations: Vec<String>,
    /// Exact endpoint scopes for which policy may create a direct, temporary
    /// lease. Empty means direct privilege expansion is unavailable.
    #[serde(default)]
    pub in_place_lease_scopes: Vec<NetworkLeaseScope>,
    pub max_in_place_lease_ttl_seconds: u64,
    /// Hard ceiling for simultaneously active temporary grants. A policy CIDR
    /// bounds eligible endpoints, but must not let an untrusted workload grow
    /// the active ruleset without bound by walking that CIDR address by
    /// address.
    #[serde(default = "default_max_active_in_place_leases")]
    pub max_active_in_place_leases: usize,
    #[serde(default)]
    pub http_gateway_available: bool,
    /// Exact HTTP methods the trusted mediator may execute. The default is
    /// read-only; trusted policy must opt into every mutating method.
    #[serde(default = "default_http_gateway_methods")]
    pub http_gateway_methods: Vec<String>,
    #[serde(default = "default_prefer_http_gateway")]
    pub prefer_http_gateway: bool,
}

fn default_http_gateway_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}

fn default_prefer_http_gateway() -> bool {
    true
}

fn default_max_active_in_place_leases() -> usize {
    64
}

// These are parsed once by the compiler rather than allocating strings and
// reparsing CIDRs for every boundary decision. Translation/tunnelling prefixes
// are restricted as prefixes, not only when their currently embedded IPv4
// value is private: the actual endpoint beyond a translator is not the IPv6
// address enforced by the operation's local nftables rule.
const MANDATORY_RESTRICTED_DESTINATIONS: &[(IpAddr, u8)] = &[
    (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
    (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    (IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)), 24),
    (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15),
    (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 4),
    (IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0)), 4),
    (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128),
    (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
    (IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)), 8),
    // RFC 6052 well-known and RFC 8215 local-use NAT64 prefixes.
    (
        IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0)),
        96,
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0)),
        48,
    ),
    // 6to4 and deprecated IPv4-compatible IPv6 encodings.
    (IpAddr::V6(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0)), 16),
    (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 96),
];

impl Default for NetworkBoundaryPolicy {
    fn default() -> Self {
        Self {
            schema_version: NETWORK_BOUNDARY_SCHEMA_VERSION,
            restricted_destinations: Vec::new(),
            in_place_lease_scopes: Vec::new(),
            max_in_place_lease_ttl_seconds: 60,
            max_active_in_place_leases: default_max_active_in_place_leases(),
            http_gateway_available: false,
            http_gateway_methods: default_http_gateway_methods(),
            prefer_http_gateway: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkBoundaryDisposition {
    AllowWithinEnvelope,
    AttachInPlaceLease,
    BrokerHttp,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBoundaryDecision {
    pub disposition: NetworkBoundaryDisposition,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<NetworkEndpointGrant>,
}

pub fn decide_network_boundary(
    event: &NetworkBoundaryEvent,
    envelope: &NetworkCapabilityEnvelope,
    policy: &NetworkBoundaryPolicy,
) -> NetworkBoundaryDecision {
    let destination = match validate_event(event, policy) {
        Ok(destination) => destination,
        Err(reason_code) => return deny(reason_code),
    };

    // The current envelope is operator-authored baseline authority. An exact
    // grant is therefore evaluated before the mandatory floor so deployments
    // can deliberately expose a narrowly scoped local mediator. Runtime
    // leases and broker decisions are evaluated below the floor and can never
    // use this exception to authorize a restricted destination.
    if envelope.grants.iter().any(|grant| {
        grant_allows(
            grant,
            destination,
            event.protocol,
            event.port,
            event.observed_at_ms,
        )
    }) {
        return NetworkBoundaryDecision {
            disposition: NetworkBoundaryDisposition::AllowWithinEnvelope,
            reason_code: "within_current_network_envelope".to_string(),
            lease: None,
        };
    }

    if MANDATORY_RESTRICTED_DESTINATIONS
        .iter()
        .any(|(network, prefix)| parsed_network_contains(*network, *prefix, destination))
        || policy
            .restricted_destinations
            .iter()
            .any(|cidr| cidr_contains(cidr, destination))
    {
        return deny("restricted_destination");
    }

    let brokerable = matches!(&event.effect, NetworkEffectKind::Http { method, .. }
        if policy.http_gateway_methods.iter().any(|allowed| allowed == &method.to_ascii_uppercase()));
    if brokerable && policy.http_gateway_available && policy.prefer_http_gateway {
        return NetworkBoundaryDecision {
            disposition: NetworkBoundaryDisposition::BrokerHttp,
            reason_code: "http_effect_has_trusted_mediator".to_string(),
            lease: None,
        };
    }

    let leaseable = policy.in_place_lease_scopes.iter().any(|scope| {
        cidr_contains(&scope.destination, destination)
            && scope.protocol == event.protocol
            && scope.ports.contains(&event.port)
    }) && policy.max_in_place_lease_ttl_seconds > 0;
    if leaseable {
        let active_lease_count = envelope
            .grants
            .iter()
            .filter(|grant| {
                grant.lease_id.is_some()
                    && grant
                        .expires_at_ms
                        .is_some_and(|expiry| event.observed_at_ms < expiry)
            })
            .count();
        if active_lease_count >= policy.max_active_in_place_leases {
            return deny("active_network_lease_limit_reached");
        }
        let ttl_seconds = event
            .requested_ttl_seconds
            .unwrap_or(policy.max_in_place_lease_ttl_seconds)
            .min(policy.max_in_place_lease_ttl_seconds);
        if ttl_seconds == 0 {
            return deny("invalid_network_lease_ttl");
        }
        return NetworkBoundaryDecision {
            disposition: NetworkBoundaryDisposition::AttachInPlaceLease,
            reason_code: "bounded_network_delta_is_locally_revocable".to_string(),
            lease: Some(NetworkEndpointGrant {
                destination: destination.to_string(),
                protocol: event.protocol,
                ports: vec![event.port],
                expires_at_ms: Some(
                    event
                        .observed_at_ms
                        .saturating_add(ttl_seconds.saturating_mul(1_000)),
                ),
                lease_id: None,
            }),
        };
    }

    if brokerable && policy.http_gateway_available {
        return NetworkBoundaryDecision {
            disposition: NetworkBoundaryDisposition::BrokerHttp,
            reason_code: "direct_network_delta_not_allowed_but_http_is_brokerable".to_string(),
            lease: None,
        };
    }

    deny("network_effect_cannot_be_safely_bounded")
}

fn validate_event(
    event: &NetworkBoundaryEvent,
    policy: &NetworkBoundaryPolicy,
) -> Result<IpAddr, &'static str> {
    if event.schema_version != NETWORK_BOUNDARY_SCHEMA_VERSION
        || policy.schema_version != NETWORK_BOUNDARY_SCHEMA_VERSION
        || event.operation_id.trim().is_empty()
        || event.source_run_id.trim().is_empty()
        || event.process_id == 0
        || event.port == 0
        || matches!(
            &event.effect,
            NetworkEffectKind::Http { method, authority }
                if method.trim().is_empty() || authority.trim().is_empty()
        )
    {
        return Err("invalid_network_boundary_event");
    }
    if policy
        .restricted_destinations
        .iter()
        .chain(
            policy
                .in_place_lease_scopes
                .iter()
                .map(|scope| &scope.destination),
        )
        .any(|cidr| !valid_cidr(cidr))
        || policy
            .in_place_lease_scopes
            .iter()
            .any(|scope| scope.ports.is_empty() || scope.ports.contains(&0))
        || policy
            .http_gateway_methods
            .iter()
            .any(|method| !valid_http_mediator_method(method))
    {
        return Err("invalid_network_boundary_policy");
    }
    event
        .destination
        .parse::<IpAddr>()
        .map(normalize_ip)
        .map_err(|_| "network_effect_requires_resolved_ip")
}

fn valid_http_mediator_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 32
        && method != "CONNECT"
        && method != "TRACE"
        && method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
}

fn valid_cidr(cidr: &str) -> bool {
    let (network, prefix) = match cidr.split_once('/') {
        Some((network, prefix)) => (network, prefix.parse::<u8>().ok()),
        None => (cidr, None),
    };
    matches!(
        (network.parse::<IpAddr>(), prefix),
        (Ok(IpAddr::V4(_)), None | Some(0..=32)) | (Ok(IpAddr::V6(_)), None | Some(0..=128))
    )
}

/// Treat IPv4-mapped IPv6 addresses as their IPv4 destination. Without this
/// normalization, `::ffff:127.0.0.1` could evade an IPv4 loopback restriction
/// while reaching the same socket through the kernel's mapped-address path.
fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn grant_allows(
    grant: &NetworkEndpointGrant,
    destination: IpAddr,
    protocol: NetworkProtocol,
    port: u16,
    now_ms: u64,
) -> bool {
    grant.protocol == protocol
        && grant.ports.contains(&port)
        && grant.expires_at_ms.is_none_or(|expiry| now_ms < expiry)
        && cidr_contains(&grant.destination, destination)
}

fn deny(reason_code: &str) -> NetworkBoundaryDecision {
    NetworkBoundaryDecision {
        disposition: NetworkBoundaryDisposition::Deny,
        reason_code: reason_code.to_string(),
        lease: None,
    }
}

fn cidr_contains(cidr: &str, address: IpAddr) -> bool {
    let (network, prefix) = match cidr.split_once('/') {
        Some((network, prefix)) => {
            let Ok(network) = network.parse::<IpAddr>() else {
                return false;
            };
            let Ok(prefix) = prefix.parse::<u8>() else {
                return false;
            };
            (network, Some(prefix))
        }
        None => {
            let Ok(network) = cidr.parse::<IpAddr>() else {
                return false;
            };
            (network, None)
        }
    };
    parsed_network_contains(
        network,
        prefix.unwrap_or(match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }),
        address,
    )
}

fn parsed_network_contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => ipv4_contains(network, address, prefix),
        (IpAddr::V6(network), IpAddr::V6(address)) => ipv6_contains(network, address, prefix),
        _ => false,
    }
}

fn ipv4_contains(network: Ipv4Addr, address: Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(network) & mask == u32::from(address) & mask
}

fn ipv6_contains(network: Ipv6Addr, address: Ipv6Addr, prefix: u8) -> bool {
    if prefix > 128 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    u128::from(network) & mask == u128::from(address) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(destination: &str, effect: NetworkEffectKind) -> NetworkBoundaryEvent {
        NetworkBoundaryEvent {
            schema_version: NETWORK_BOUNDARY_SCHEMA_VERSION,
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            process_id: 42,
            destination: destination.to_string(),
            protocol: NetworkProtocol::Tcp,
            port: 443,
            effect,
            observed_at_ms: 1_000,
            requested_ttl_seconds: Some(30),
        }
    }

    #[test]
    fn active_envelope_is_allowed_and_expired_lease_is_not() {
        let grant = NetworkEndpointGrant {
            destination: "203.0.113.8".to_string(),
            protocol: NetworkProtocol::Tcp,
            ports: vec![443],
            expires_at_ms: Some(2_000),
            lease_id: Some("lease_1".to_string()),
        };
        let mut envelope = NetworkCapabilityEnvelope {
            grants: vec![grant],
        };
        let policy = NetworkBoundaryPolicy::default();
        assert_eq!(
            decide_network_boundary(
                &event("203.0.113.8", NetworkEffectKind::DirectConnect),
                &envelope,
                &policy,
            )
            .disposition,
            NetworkBoundaryDisposition::AllowWithinEnvelope
        );
        envelope.grants[0].expires_at_ms = Some(999);
        assert_eq!(
            decide_network_boundary(
                &event("203.0.113.8", NetworkEffectKind::DirectConnect),
                &envelope,
                &policy,
            )
            .disposition,
            NetworkBoundaryDisposition::Deny
        );
    }

    #[test]
    fn bounded_public_delta_receives_a_short_lease() {
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![NetworkLeaseScope {
                destination: "8.8.8.0/24".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
            }],
            ..NetworkBoundaryPolicy::default()
        };
        let decision = decide_network_boundary(
            &event("8.8.8.8", NetworkEffectKind::DirectConnect),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(
            decision.disposition,
            NetworkBoundaryDisposition::AttachInPlaceLease
        );
        assert_eq!(decision.lease.unwrap().expires_at_ms, Some(31_000));
    }

    #[test]
    fn http_read_is_brokered_when_gateway_is_available() {
        let policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let decision = decide_network_boundary(
            &event(
                "8.8.8.8",
                NetworkEffectKind::Http {
                    method: "GET".to_string(),
                    authority: "packages.example".to_string(),
                },
            ),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(decision.disposition, NetworkBoundaryDisposition::BrokerHttp);
    }

    #[test]
    fn mutating_http_is_brokered_only_when_explicitly_in_policy() {
        let post = event(
            "8.8.8.8",
            NetworkEffectKind::Http {
                method: "POST".to_string(),
                authority: "api.example".to_string(),
            },
        );
        let default_policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        assert_eq!(
            decide_network_boundary(
                &post,
                &NetworkCapabilityEnvelope::default(),
                &default_policy,
            )
            .disposition,
            NetworkBoundaryDisposition::Deny
        );
        let opt_in_policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            http_gateway_methods: vec!["GET".to_string(), "HEAD".to_string(), "POST".to_string()],
            ..NetworkBoundaryPolicy::default()
        };
        assert_eq!(
            decide_network_boundary(&post, &NetworkCapabilityEnvelope::default(), &opt_in_policy,)
                .disposition,
            NetworkBoundaryDisposition::BrokerHttp
        );
    }

    #[test]
    fn private_redirect_is_denied_even_when_http_is_brokerable() {
        let policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let decision = decide_network_boundary(
            &event(
                "10.20.0.2",
                NetworkEffectKind::Http {
                    method: "GET".to_string(),
                    authority: "challenge.internal".to_string(),
                },
            ),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(decision.disposition, NetworkBoundaryDisposition::Deny);
        assert_eq!(decision.reason_code, "restricted_destination");
    }

    #[test]
    fn ipv4_mapped_private_destination_cannot_bypass_restrictions() {
        let policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let decision = decide_network_boundary(
            &event(
                "::ffff:127.0.0.1",
                NetworkEffectKind::Http {
                    method: "GET".to_string(),
                    authority: "challenge.internal".to_string(),
                },
            ),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(decision.disposition, NetworkBoundaryDisposition::Deny);
        assert_eq!(decision.reason_code, "restricted_destination");
    }

    #[test]
    fn incomplete_http_effect_fails_closed() {
        let policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let decision = decide_network_boundary(
            &event(
                "8.8.8.8",
                NetworkEffectKind::Http {
                    method: "GET".to_string(),
                    authority: " ".to_string(),
                },
            ),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(decision.disposition, NetworkBoundaryDisposition::Deny);
        assert_eq!(decision.reason_code, "invalid_network_boundary_event");
    }

    #[test]
    fn unbounded_or_unresolved_effects_fail_closed() {
        let policy = NetworkBoundaryPolicy::default();
        let unresolved = decide_network_boundary(
            &event("example.test", NetworkEffectKind::DirectConnect),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(unresolved.disposition, NetworkBoundaryDisposition::Deny);
        assert_eq!(
            unresolved.reason_code,
            "network_effect_requires_resolved_ip"
        );
    }

    #[test]
    fn invalid_policy_cidr_fails_closed() {
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![NetworkLeaseScope {
                destination: "not-a-cidr".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
            }],
            ..NetworkBoundaryPolicy::default()
        };
        let decision = decide_network_boundary(
            &event("8.8.8.8", NetworkEffectKind::DirectConnect),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(decision.disposition, NetworkBoundaryDisposition::Deny);
        assert_eq!(decision.reason_code, "invalid_network_boundary_policy");
    }

    #[test]
    fn temporary_authority_is_eligible_only_for_the_policy_authored_tuple() {
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![NetworkLeaseScope {
                destination: "8.8.8.8".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
            }],
            ..NetworkBoundaryPolicy::default()
        };
        let exact = decide_network_boundary(
            &event("8.8.8.8", NetworkEffectKind::DirectConnect),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(
            exact.disposition,
            NetworkBoundaryDisposition::AttachInPlaceLease
        );
        let lease = exact.lease.unwrap();
        assert_eq!(lease.destination, "8.8.8.8");
        assert_eq!(lease.protocol, NetworkProtocol::Tcp);
        assert_eq!(lease.ports, vec![443]);

        let mut wrong_port = event("8.8.8.8", NetworkEffectKind::DirectConnect);
        wrong_port.port = 80;
        let mut wrong_protocol = event("8.8.8.8", NetworkEffectKind::DirectConnect);
        wrong_protocol.protocol = NetworkProtocol::Udp;
        for outside_scope in [
            event("8.8.4.4", NetworkEffectKind::DirectConnect),
            wrong_port,
            wrong_protocol,
        ] {
            let decision = decide_network_boundary(
                &outside_scope,
                &NetworkCapabilityEnvelope::default(),
                &policy,
            );
            assert_eq!(decision.disposition, NetworkBoundaryDisposition::Deny);
            assert!(decision.lease.is_none());
        }
    }

    #[test]
    fn unknown_local_address_paths_never_gain_authority_from_broad_policy() {
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![
                NetworkLeaseScope {
                    destination: "0.0.0.0/0".to_string(),
                    protocol: NetworkProtocol::Tcp,
                    ports: vec![443],
                },
                NetworkLeaseScope {
                    destination: "::/0".to_string(),
                    protocol: NetworkProtocol::Tcp,
                    ports: vec![443],
                },
            ],
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let hidden_paths = [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.255.254",
            "192.0.0.1",
            "192.168.1.2",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:7f00:1",
            "::ffff:a00:1",
            "64:ff9b::a00:1",
            "64:ff9b:1::a00:1",
            "2002:0a00:0001::",
            "::7f00:1",
        ];
        for destination in hidden_paths {
            for effect in [
                NetworkEffectKind::DirectConnect,
                NetworkEffectKind::Http {
                    method: "GET".to_string(),
                    authority: "artifact.example".to_string(),
                },
            ] {
                let decision = decide_network_boundary(
                    &event(destination, effect),
                    &NetworkCapabilityEnvelope::default(),
                    &policy,
                );
                assert_eq!(
                    decision.disposition,
                    NetworkBoundaryDisposition::Deny,
                    "unexpected authority for {destination}"
                );
                assert_eq!(decision.reason_code, "restricted_destination");
                assert!(decision.lease.is_none());
            }
        }
    }

    #[test]
    fn active_temporary_lease_count_is_bounded_independently_of_cidr_scope() {
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![NetworkLeaseScope {
                destination: "8.8.8.0/24".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
            }],
            max_active_in_place_leases: 2,
            ..NetworkBoundaryPolicy::default()
        };
        let envelope = NetworkCapabilityEnvelope {
            grants: vec![
                NetworkEndpointGrant {
                    destination: "8.8.8.1".to_string(),
                    protocol: NetworkProtocol::Tcp,
                    ports: vec![443],
                    expires_at_ms: Some(2_000),
                    lease_id: Some("lease_1".to_string()),
                },
                NetworkEndpointGrant {
                    destination: "8.8.8.2".to_string(),
                    protocol: NetworkProtocol::Tcp,
                    ports: vec![443],
                    expires_at_ms: Some(2_000),
                    lease_id: Some("lease_2".to_string()),
                },
            ],
        };
        let decision = decide_network_boundary(
            &event("8.8.8.3", NetworkEffectKind::DirectConnect),
            &envelope,
            &policy,
        );
        assert_eq!(decision.disposition, NetworkBoundaryDisposition::Deny);
        assert_eq!(decision.reason_code, "active_network_lease_limit_reached");
        assert!(decision.lease.is_none());
    }

    #[test]
    fn deliberately_local_baseline_grant_does_not_authorize_sibling_effects() {
        let envelope = NetworkCapabilityEnvelope {
            grants: vec![NetworkEndpointGrant {
                destination: "10.30.0.5".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![3128],
                expires_at_ms: None,
                lease_id: None,
            }],
        };
        let mut exact = event("10.30.0.5", NetworkEffectKind::DirectConnect);
        exact.port = 3128;
        assert_eq!(
            decide_network_boundary(&exact, &envelope, &NetworkBoundaryPolicy::default())
                .disposition,
            NetworkBoundaryDisposition::AllowWithinEnvelope
        );

        let mut wrong_port = exact.clone();
        wrong_port.port = 3129;
        let mut wrong_protocol = exact.clone();
        wrong_protocol.protocol = NetworkProtocol::Udp;
        let mut sibling = exact;
        sibling.destination = "10.30.0.6".to_string();
        for outside_scope in [wrong_port, wrong_protocol, sibling] {
            assert_eq!(
                decide_network_boundary(
                    &outside_scope,
                    &envelope,
                    &NetworkBoundaryPolicy::default(),
                )
                .disposition,
                NetworkBoundaryDisposition::Deny
            );
        }
    }

    #[test]
    fn malformed_temporary_endpoint_scope_fails_closed() {
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![NetworkLeaseScope {
                destination: "8.8.8.8".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![0],
            }],
            ..NetworkBoundaryPolicy::default()
        };
        let decision = decide_network_boundary(
            &event("8.8.8.8", NetworkEffectKind::DirectConnect),
            &NetworkCapabilityEnvelope::default(),
            &policy,
        );
        assert_eq!(decision.disposition, NetworkBoundaryDisposition::Deny);
        assert_eq!(decision.reason_code, "invalid_network_boundary_policy");
    }
}
