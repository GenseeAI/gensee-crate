#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "the end-to-end enforcement demo requires Linux" >&2
  exit 77
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "run the end-to-end enforcement demo as root" >&2
  exit 77
fi
for command in cargo ip nft jq python3 openssl sha256sum; do
  command -v "$command" >/dev/null || {
    echo "missing prerequisite: $command" >&2
    exit 77
  }
done
if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "cgroup v2 is required" >&2
  exit 77
fi

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${GENSEE_DEMO_ROOT:-}" ]]; then
  RUNTIME_ROOT="$GENSEE_DEMO_ROOT"
  if [[ -e "$RUNTIME_ROOT" ]]; then
    echo "GENSEE_DEMO_ROOT must name a path that does not exist" >&2
    exit 2
  fi
  mkdir -m 700 "$RUNTIME_ROOT"
else
  RUNTIME_ROOT="$(mktemp -d /tmp/gensee-end-to-end-demo.XXXXXX)"
fi
INTERFACE="gsdemo${BASHPID}"
INTERFACE="${INTERFACE:0:15}"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  ip link delete "$INTERFACE" 2>/dev/null || true
}
trap cleanup EXIT

step() {
  printf '\n[%s] %s\n' "$1" "$2"
}

export GENSEE_HOME="$RUNTIME_ROOT/state"
mkdir -m 700 \
  "$GENSEE_HOME" \
  "$RUNTIME_ROOT/operator" \
  "$RUNTIME_ROOT/operator/catalog-store" \
  "$RUNTIME_ROOT/negative-workspace" \
  "$RUNTIME_ROOT/positive-workspace" \
  "$RUNTIME_ROOT/promoted"
touch "$RUNTIME_ROOT/server.log"

ip link add "$INTERFACE" type dummy
ip address add 192.0.2.2/32 dev "$INTERFACE"
ip link set "$INTERFACE" up
python3 "$REPOSITORY_ROOT/integrations/boundary/generic-proof/server.py" \
  "$RUNTIME_ROOT/server.log" &
SERVER_PID=$!
for _ in $(seq 1 100); do
  if grep -q 'listening:18080' "$RUNTIME_ROOT/server.log" \
    && grep -q 'listening:18081' "$RUNTIME_ROOT/server.log"; then
    break
  fi
  sleep 0.05
done
grep -q 'listening:18080' "$RUNTIME_ROOT/server.log"
grep -q 'listening:18081' "$RUNTIME_ROOT/server.log"

if [[ -n "${GENSEE_BINARY:-}" ]]; then
  GENSEE="$GENSEE_BINARY"
else
  cargo build -p gensee-crate-cli
  GENSEE="$REPOSITORY_ROOT/target/debug/gensee"
fi
[[ -x "$GENSEE" ]]

step 1 "Operator creates safe contract templates"
"$GENSEE" boundary catalog template \
  --profile deny-all \
  --contract-id restricted_network_probe_v1 \
  --operation-class restricted_network_probe \
  --output "$RUNTIME_ROOT/operator/negative-template.json"
"$GENSEE" boundary catalog template \
  --profile structured-result \
  --contract-id approved_structured_transform_v1 \
  --operation-class approved_structured_transform \
  --product-path out/result.json \
  --verifier-profile structured_result_policy_v1 \
  --destination-root "$RUNTIME_ROOT/promoted" \
  --active-pointer current \
  --output "$RUNTIME_ROOT/operator/positive-template.json"

jq '
  .execution.max_runtime_seconds = 20 |
  .capabilities.network = {
    mode: "allow_exact",
    allowed_endpoints: [{destination: "192.0.2.2", protocol: "tcp", ports: [18080]}]
  } |
  .product.max_bytes = 4096
' "$RUNTIME_ROOT/operator/positive-template.json" \
  >"$RUNTIME_ROOT/operator/positive-contract.json"

step 2 "Operator approves identities, intent classes, verifier, and promotion policy"
openssl rand -hex 32 >"$RUNTIME_ROOT/operator/organization.seed"
openssl rand -hex 32 >"$RUNTIME_ROOT/operator/analyzer.seed"
openssl rand -hex 32 >"$RUNTIME_ROOT/operator/verifier.seed"
"$GENSEE" boundary catalog public-key \
  --key "$RUNTIME_ROOT/operator/organization.seed" \
  --output "$RUNTIME_ROOT/operator/organization-public.hex"
"$GENSEE" boundary catalog public-key \
  --key "$RUNTIME_ROOT/operator/analyzer.seed" \
  --output "$RUNTIME_ROOT/operator/analyzer-public.hex"
"$GENSEE" boundary catalog public-key \
  --key "$RUNTIME_ROOT/operator/verifier.seed" \
  --output "$RUNTIME_ROOT/operator/verifier-public.hex"

install -o root -g root -m 0500 \
  "$REPOSITORY_ROOT/integrations/boundary/end-to-end-demo/verifier.py" \
  "$RUNTIME_ROOT/operator/verifier.py"
VERIFIER_EXECUTABLE_DIGEST="sha256:$(sha256sum "$RUNTIME_ROOT/operator/verifier.py" | awk '{print $1}')"
jq -n \
  --arg executable "$RUNTIME_ROOT/operator/verifier.py" \
  --arg executable_digest "$VERIFIER_EXECUTABLE_DIGEST" \
  '{
    verifier_id: "demo_structured_result_verifier",
    policy_version: "demo_policy_v1",
    executable: $executable,
    executable_sha256: $executable_digest,
    args: [],
    working_directory: "/",
    max_runtime_seconds: 20
  }' >"$RUNTIME_ROOT/operator/verifier-config.json"
VERIFIER_CONFIG_DIGEST="sha256:$(jq -cj . "$RUNTIME_ROOT/operator/verifier-config.json" | sha256sum | awk '{print $1}')"

NOW_MS="$(( $(date +%s) * 1000 ))"
EXPIRES_MS="$(( NOW_MS + 3600000 ))"
UID_VALUE="$(id -u)"
ANALYZER_PUBLIC="$(tr -d '\n' <"$RUNTIME_ROOT/operator/analyzer-public.hex")"
VERIFIER_PUBLIC="$(tr -d '\n' <"$RUNTIME_ROOT/operator/verifier-public.hex")"
jq -n \
  --slurpfile negative "$RUNTIME_ROOT/operator/negative-template.json" \
  --slurpfile positive "$RUNTIME_ROOT/operator/positive-contract.json" \
  --argjson now "$NOW_MS" \
  --argjson expires "$EXPIRES_MS" \
  --argjson uid "$UID_VALUE" \
  --arg analyzer_public "$ANALYZER_PUBLIC" \
  --arg verifier_public "$VERIFIER_PUBLIC" \
  --arg verifier_config_digest "$VERIFIER_CONFIG_DIGEST" \
  '{
    schema_version: 1,
    catalog_id: "generic_demo_catalog",
    organization_id: "example_organization",
    version: 1,
    issued_at_ms: $now,
    expires_at_ms: $expires,
    contracts: [
      {
        contract: $negative[0],
        owner: {application_id: "demo_workload", owning_team: "platform_security"},
        approval: {
          approval_id: "approval_restricted_probe_v1",
          approved_by: "security_review",
          approved_at_ms: $now,
          expires_at_ms: $expires
        }
      },
      {
        contract: $positive[0],
        owner: {application_id: "demo_workload", owning_team: "platform_security"},
        approval: {
          approval_id: "approval_structured_transform_v1",
          approved_by: "security_review",
          approved_at_ms: $now,
          expires_at_ms: $expires
        }
      }
    ],
    selectors: [
      {
        selector_id: "root_restricted_probe",
        caller: {uid: $uid},
        operation_class: "restricted_network_probe",
        contract_id: "restricted_network_probe_v1"
      },
      {
        selector_id: "root_structured_transform",
        caller: {uid: $uid},
        operation_class: "approved_structured_transform",
        contract_id: "approved_structured_transform_v1"
      }
    ],
    intent_analyzers: [{
      analyzer_id: "demo_intent_analyzer",
      public_key_hex: $analyzer_public,
      model_identity: "demo_bounded_model_v1",
      minimum_confidence_bps: 9000,
      allowed_operation_classes: [
        "restricted_network_probe",
        "approved_structured_transform"
      ]
    }],
    operation_services: [],
    semantic_verifiers: [{
      verifier_id: "demo_structured_result_verifier",
      public_key_hex: $verifier_public,
      profiles: ["structured_result_policy_v1"],
      policy_versions: ["demo_policy_v1"],
      require_isolation: true,
      isolated_runtime_config_digest: $verifier_config_digest
    }],
    fallback: {on_ambiguous_intent: "deny"}
  }' >"$RUNTIME_ROOT/operator/catalog.json"

jq -n '{
  schema_version: 1,
  analyzer_id: "demo_intent_analyzer",
  model_identity: "demo_bounded_model_v1",
  classes: [
    {
      operation_class: "approved_structured_transform",
      intercept: 0,
      weights: {trajectory_approved_transform: 12000, trajectory_restricted_probe: -12000}
    },
    {
      operation_class: "restricted_network_probe",
      intercept: 0,
      weights: {trajectory_approved_transform: -12000, trajectory_restricted_probe: 12000}
    }
  ]
}' >"$RUNTIME_ROOT/operator/intent-model.json"

"$GENSEE" boundary catalog sign \
  --catalog "$RUNTIME_ROOT/operator/catalog.json" \
  --key "$RUNTIME_ROOT/operator/organization.seed" \
  --key-id organization_root_v1 \
  --output "$RUNTIME_ROOT/operator/catalog.signed.json"
"$GENSEE" boundary catalog verify \
  --catalog "$RUNTIME_ROOT/operator/catalog.signed.json" \
  --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex"
"$GENSEE" boundary catalog install \
  --catalog "$RUNTIME_ROOT/operator/catalog.signed.json" \
  --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex" \
  --root "$RUNTIME_ROOT/operator/catalog-store"
"$GENSEE" boundary catalog status \
  --root "$RUNTIME_ROOT/operator/catalog-store" \
  --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex"
CATALOG="$RUNTIME_ROOT/operator/catalog-store/current.json"

create_trajectory() {
  local name="$1"
  local feature="$2"
  local timestamp
  timestamp="$(( $(date +%s) * 1000 ))"
  jq -n \
    --arg evidence_id "trajectory_${name}" \
    --arg feature "$feature" \
    --argjson timestamp "$timestamp" \
    '{
      history_complete: true,
      trajectory: [{
        evidence_id: $evidence_id,
        kind: "normalized_behavior",
        digest: ("sha256:" + ("7a" * 32)),
        trust_domain: "host_telemetry",
        started_at_ms: $timestamp,
        finished_at_ms: $timestamp,
        features: [$feature]
      }]
    }' >"$RUNTIME_ROOT/${name}-trajectory.json"
}

analyze_operation() {
  local name="$1"
  shift
  "$GENSEE" boundary intent observe \
    --trajectory "$RUNTIME_ROOT/${name}-trajectory.json" \
    --output "$RUNTIME_ROOT/${name}-observation.json" -- "$@"
  "$GENSEE" boundary intent analyze \
    --catalog "$CATALOG" \
    --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex" \
    --observation "$RUNTIME_ROOT/${name}-observation.json" \
    --model "$RUNTIME_ROOT/operator/intent-model.json" \
    --analyzer-key "$RUNTIME_ROOT/operator/analyzer.seed" \
    --ttl-seconds 300 \
    --output "$RUNTIME_ROOT/${name}-inference.signed.json"
  "$GENSEE" boundary intent resolve \
    --catalog "$CATALOG" \
    --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex" \
    --observation "$RUNTIME_ROOT/${name}-observation.json" \
    --inference "$RUNTIME_ROOT/${name}-inference.signed.json" \
    --output "$RUNTIME_ROOT/${name}-resolution.json" -- "$@"
}

WORKLOAD="$REPOSITORY_ROOT/integrations/boundary/end-to-end-demo/workload.py"

step 3 "Negative demo: inferred operation gets no network authority"
create_trajectory negative trajectory_restricted_probe
NEGATIVE_COMMAND=(python3 "$WORKLOAD" negative)
analyze_operation negative "${NEGATIVE_COMMAND[@]}"
"$GENSEE" boundary run \
  --catalog "$CATALOG" \
  --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex" \
  --observation "$RUNTIME_ROOT/negative-observation.json" \
  --inference "$RUNTIME_ROOT/negative-inference.signed.json" \
  --workspace "$RUNTIME_ROOT/negative-workspace" \
  --manifest "$RUNTIME_ROOT/negative-operation-manifest.json" \
  -- "${NEGATIVE_COMMAND[@]}" >"$RUNTIME_ROOT/negative-run.log"

jq -e '
  .admission.selected_operation_class == "restricted_network_probe" and
  .contract_id == "restricted_network_probe_v1" and
  .enforcement.network_mode == "deny_all" and
  ([.enforcement.denied_network_effects[].packets] | add // 0) > 0 and
  ([.enforcement.allowed_network_effects[].packets] | add // 0) == 0 and
  .process.execution_subject_drained == true and
  .product == null and
  .promotion.performed == false
' "$RUNTIME_ROOT/negative-operation-manifest.json" >/dev/null
if grep -q 'accepted:18081' "$RUNTIME_ROOT/server.log"; then
  echo "negative demo failed: prohibited endpoint received traffic" >&2
  exit 1
fi
printf 'negative result: prohibited connection denied; no product was eligible for promotion\n'

step 4 "Positive demo: exact authority, isolated verification, revocation, promotion"
create_trajectory positive trajectory_approved_transform
POSITIVE_COMMAND=(python3 "$WORKLOAD" positive)
analyze_operation positive "${POSITIVE_COMMAND[@]}"
"$GENSEE" boundary run \
  --catalog "$CATALOG" \
  --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex" \
  --observation "$RUNTIME_ROOT/positive-observation.json" \
  --inference "$RUNTIME_ROOT/positive-inference.signed.json" \
  --workspace "$RUNTIME_ROOT/positive-workspace" \
  --manifest "$RUNTIME_ROOT/positive-operation-manifest.json" \
  -- "${POSITIVE_COMMAND[@]}" >"$RUNTIME_ROOT/positive-run.log"

"$GENSEE" boundary verifier request \
  --manifest "$RUNTIME_ROOT/positive-operation-manifest.json" \
  --ttl-seconds 300 \
  --output "$RUNTIME_ROOT/verifier-request.json"
"$GENSEE" boundary verifier run \
  --catalog "$CATALOG" \
  --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex" \
  --manifest "$RUNTIME_ROOT/positive-operation-manifest.json" \
  --request "$RUNTIME_ROOT/verifier-request.json" \
  --config "$RUNTIME_ROOT/operator/verifier-config.json" \
  --verifier-key "$RUNTIME_ROOT/operator/verifier.seed" \
  --output "$RUNTIME_ROOT/verifier-receipt.json"
"$GENSEE" boundary verifier verify \
  --catalog "$CATALOG" \
  --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex" \
  --request "$RUNTIME_ROOT/verifier-request.json" \
  --receipt "$RUNTIME_ROOT/verifier-receipt.json"
"$GENSEE" boundary promotion apply \
  --catalog "$CATALOG" \
  --trusted-key "$RUNTIME_ROOT/operator/organization-public.hex" \
  --manifest "$RUNTIME_ROOT/positive-operation-manifest.json" \
  --verifier-request "$RUNTIME_ROOT/verifier-request.json" \
  --verifier-receipt "$RUNTIME_ROOT/verifier-receipt.json" \
  --expected-current none \
  --output "$RUNTIME_ROOT/promotion-receipt.json"

for _ in $(seq 1 100); do
  grep -q 'descendant-revoked' "$RUNTIME_ROOT/server.log" && break
  sleep 0.05
done
grep -q 'roundtrip:18080' "$RUNTIME_ROOT/server.log"
grep -q 'descendant-established' "$RUNTIME_ROOT/server.log"
grep -q 'descendant-revoked' "$RUNTIME_ROOT/server.log"

jq -e '
  .admission.selected_operation_class == "approved_structured_transform" and
  .contract_id == "approved_structured_transform_v1" and
  .enforcement.network_mode == "allow_exact" and
  ([.enforcement.allowed_network_effects[].packets] | add // 0) > 0 and
  ([.enforcement.denied_network_effects[].packets] | add // 0) == 0 and
  .process.execution_subject_drained == true and
  .product.structurally_valid == true
' "$RUNTIME_ROOT/positive-operation-manifest.json" >/dev/null
jq -e '
  .claims.verdict == "accept" and
  .claims.isolation.network_denied == true and
  .claims.isolation.process_creation_denied == true and
  .claims.isolation.filesystem_mutation_denied == true and
  .claims.reason_codes == ["structured_result_policy_passed"]
' "$RUNTIME_ROOT/verifier-receipt.json" >/dev/null
ACTIVE_TARGET="$(readlink "$RUNTIME_ROOT/promoted/current")"
cmp \
  "$RUNTIME_ROOT/promoted/$ACTIVE_TARGET" \
  "$(jq -r .staged_workspace "$RUNTIME_ROOT/positive-operation-manifest.json")/out/result.json"

jq -n \
  --slurpfile negative "$RUNTIME_ROOT/negative-operation-manifest.json" \
  --slurpfile positive "$RUNTIME_ROOT/positive-operation-manifest.json" \
  --slurpfile verifier "$RUNTIME_ROOT/verifier-receipt.json" \
  --slurpfile promotion "$RUNTIME_ROOT/promotion-receipt.json" \
  '{
    catalog: {
      id: $positive[0].admission.catalog_id,
      version: $positive[0].admission.catalog_version
    },
    negative: {
      operation_id: $negative[0].operation_id,
      selected_contract: $negative[0].contract_id,
      denied_packets: ([$negative[0].enforcement.denied_network_effects[].packets] | add // 0),
      allowed_packets: ([$negative[0].enforcement.allowed_network_effects[].packets] | add // 0),
      promoted: false
    },
    positive: {
      operation_id: $positive[0].operation_id,
      selected_contract: $positive[0].contract_id,
      allowed_packets: ([$positive[0].enforcement.allowed_network_effects[].packets] | add // 0),
      execution_subject_drained: $positive[0].process.execution_subject_drained,
      product_digest: $positive[0].product.digest,
      verifier_verdict: $verifier[0].claims.verdict,
      verifier_isolated: ($verifier[0].claims.isolation != null),
      active_target: $promotion[0].active_target
    }
  }' >"$RUNTIME_ROOT/demo-summary.json"

step 5 "Demo passed"
jq . "$RUNTIME_ROOT/demo-summary.json"
printf '\nEvidence retained at %s\n' "$RUNTIME_ROOT"
