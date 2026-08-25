#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "generic boundary proof requires Linux" >&2
  exit 77
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "run this proof as root" >&2
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
RUNTIME_ROOT="$(mktemp -d /tmp/gensee-generic-proof.XXXXXX)"
INTERFACE="gensee-proof0"
SERVER_PID=""
SYSTEM_KEY_DIR_CREATED="false"
SYSTEM_KEYS_INSTALLED="false"

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  ip link delete "$INTERFACE" 2>/dev/null || true
  if [[ "$SYSTEM_KEYS_INSTALLED" == "true" ]]; then
    rm -f /etc/gensee/catalog-root-public-key.hex \
      /etc/gensee/operation-manifest-signing-key.hex \
      /etc/gensee/operation-manifest-public-key.hex
  fi
  if [[ "$SYSTEM_KEY_DIR_CREATED" == "true" ]]; then
    rmdir /etc/gensee 2>/dev/null || true
  fi
  rm -rf "$RUNTIME_ROOT"
}
trap cleanup EXIT

export GENSEE_HOME="$RUNTIME_ROOT/state"
mkdir -m 700 "$GENSEE_HOME" "$RUNTIME_ROOT/workspace" "$RUNTIME_ROOT/promoted"
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

openssl rand -hex 32 >"$RUNTIME_ROOT/organization.seed"
openssl rand -hex 32 >"$RUNTIME_ROOT/analyzer.seed"
openssl rand -hex 32 >"$RUNTIME_ROOT/verifier.seed"
openssl rand -hex 32 >"$RUNTIME_ROOT/proof.seed"
openssl rand -hex 32 >"$RUNTIME_ROOT/manifest.seed"
"$GENSEE" boundary catalog public-key \
  --key "$RUNTIME_ROOT/organization.seed" --output "$RUNTIME_ROOT/organization-public.hex"
"$GENSEE" boundary catalog public-key \
  --key "$RUNTIME_ROOT/analyzer.seed" --output "$RUNTIME_ROOT/analyzer-public.hex"
"$GENSEE" boundary catalog public-key \
  --key "$RUNTIME_ROOT/verifier.seed" --output "$RUNTIME_ROOT/verifier-public.hex"
"$GENSEE" boundary catalog public-key \
  --key "$RUNTIME_ROOT/proof.seed" --output "$RUNTIME_ROOT/proof-public.hex"
"$GENSEE" boundary catalog public-key \
  --key "$RUNTIME_ROOT/manifest.seed" --output "$RUNTIME_ROOT/manifest-public.hex"

if [[ ! -d /etc/gensee ]]; then
  mkdir -m 700 /etc/gensee
  SYSTEM_KEY_DIR_CREATED="true"
fi
if [[ -e /etc/gensee/catalog-root-public-key.hex \
  || -e /etc/gensee/operation-manifest-signing-key.hex \
  || -e /etc/gensee/operation-manifest-public-key.hex ]]; then
  echo "refusing to replace installed Gensee trust material; use a dedicated proof host" >&2
  exit 77
fi
install -m 600 "$RUNTIME_ROOT/organization-public.hex" \
  /etc/gensee/catalog-root-public-key.hex
install -m 600 "$RUNTIME_ROOT/manifest.seed" \
  /etc/gensee/operation-manifest-signing-key.hex
install -m 644 "$RUNTIME_ROOT/manifest-public.hex" \
  /etc/gensee/operation-manifest-public-key.hex
SYSTEM_KEYS_INSTALLED="true"

NOW_MS="$(( $(date +%s) * 1000 ))"
EXPIRES_MS="$(( NOW_MS + 3600000 ))"
UID_VALUE="$(id -u)"
ANALYZER_PUBLIC="$(tr -d '\n' <"$RUNTIME_ROOT/analyzer-public.hex")"
VERIFIER_PUBLIC="$(tr -d '\n' <"$RUNTIME_ROOT/verifier-public.hex")"

install -o root -g root -m 0500 \
  "$REPOSITORY_ROOT/integrations/boundary/generic-proof/verifier.py" \
  "$RUNTIME_ROOT/verifier.py"
VERIFIER_EXECUTABLE_DIGEST="sha256:$(sha256sum "$RUNTIME_ROOT/verifier.py" | awk '{print $1}')"
jq -n \
  --arg executable "$RUNTIME_ROOT/verifier.py" \
  --arg executable_digest "$VERIFIER_EXECUTABLE_DIGEST" \
  '{
    verifier_id: "conformance_verifier",
    policy_version: "conformance_policy_v1",
    executable: $executable,
    executable_sha256: $executable_digest,
    args: [],
    working_directory: "/",
    max_runtime_seconds: 20
  }' >"$RUNTIME_ROOT/verifier-config.json"
VERIFIER_CONFIG_DIGEST="sha256:$(jq -cj . "$RUNTIME_ROOT/verifier-config.json" | sha256sum | awk '{print $1}')"

jq -n \
  --argjson now "$NOW_MS" \
  --argjson expires "$EXPIRES_MS" \
  --argjson uid "$UID_VALUE" \
  --arg analyzer_public "$ANALYZER_PUBLIC" \
  --arg verifier_public "$VERIFIER_PUBLIC" \
  --arg verifier_config_digest "$VERIFIER_CONFIG_DIGEST" \
  --arg promotion_root "$RUNTIME_ROOT/promoted" \
  '{
    schema_version: 1,
    catalog_id: "generic_boundary_conformance",
    organization_id: "example_organization",
    version: 1,
    issued_at_ms: $now,
    expires_at_ms: $expires,
    contracts: [{
      contract: {
        schema_version: 1,
        contract_id: "bounded_structured_transform_v1",
        operation_class: "structured_transform",
        execution: {max_runtime_seconds: 20, require_os_execution_binding: true},
        capabilities: {network: {mode: "allow_exact", allowed_endpoints: [{
          destination: "192.0.2.2", protocol: "tcp", ports: [18080]
        }]}},
        product: {
          kind: "structured_result",
          path: "out/result.json",
          max_bytes: 4096,
          max_entries: 1,
          reject_symlinks: true,
          reject_special_files: true,
          semantic_verifier_profile: "structured_result_v1",
          promotion: {destination_root: $promotion_root, active_pointer: "current"}
        }
      },
      owner: {application_id: "generic_test_workload", owning_team: "security"},
      approval: {
        approval_id: "approval_generic_v1",
        approved_by: "security_review",
        approved_at_ms: $now,
        expires_at_ms: $expires
      }
    }],
    selectors: [{
      selector_id: "root_generic_transform",
      caller: {uid: $uid},
      operation_class: "structured_transform",
      contract_id: "bounded_structured_transform_v1"
    }],
    intent_analyzers: [{
      analyzer_id: "conformance_analyzer",
      public_key_hex: $analyzer_public,
      model_identity: "conformance_intent_model_v1",
      minimum_confidence_bps: 9000,
      allowed_operation_classes: ["structured_transform"]
    }],
    operation_services: [],
    semantic_verifiers: [{
      verifier_id: "conformance_verifier",
      public_key_hex: $verifier_public,
      profiles: ["structured_result_v1"],
      policy_versions: ["conformance_policy_v1"],
      require_isolation: true,
      isolated_runtime_config_digest: $verifier_config_digest
    }],
    fallback: {on_ambiguous_intent: "deny"}
  }' >"$RUNTIME_ROOT/catalog.json"

"$GENSEE" boundary catalog sign \
  --catalog "$RUNTIME_ROOT/catalog.json" \
  --key "$RUNTIME_ROOT/organization.seed" \
  --key-id "organization_root_v1" \
  --output "$RUNTIME_ROOT/catalog.signed.json"

WORKLOAD=(python3 "$REPOSITORY_ROOT/integrations/boundary/generic-proof/workload.py")
"$GENSEE" boundary intent observe \
  --output "$RUNTIME_ROOT/observation.json" -- "${WORKLOAD[@]}"
INFERENCE_NOW="$(( $(date +%s) * 1000 ))"
jq -n \
  --argjson issued "$INFERENCE_NOW" \
  --argjson expires "$(( INFERENCE_NOW + 300000 ))" \
  '{
    schema_version: 1,
    inference_id: "conformance_inference",
    analyzer_id: "conformance_analyzer",
    model_identity: "conformance_intent_model_v1",
    observation_digest: ("sha256:" + ("0" * 64)),
    issued_at_ms: $issued,
    expires_at_ms: $expires,
    candidates: [{
      operation_class: "structured_transform",
      confidence_bps: 9500,
      rationale_code: "behavioral_trajectory_match",
      evidence_ids: []
    }]
  }' >"$RUNTIME_ROOT/inference.json"
"$GENSEE" boundary intent attest \
  --observation "$RUNTIME_ROOT/observation.json" \
  --inference "$RUNTIME_ROOT/inference.json" \
  --analyzer-key "$RUNTIME_ROOT/analyzer.seed" \
  --output "$RUNTIME_ROOT/inference.signed.json"

"$GENSEE" boundary run \
  --catalog "$RUNTIME_ROOT/catalog.signed.json" \
  --observation "$RUNTIME_ROOT/observation.json" \
  --inference "$RUNTIME_ROOT/inference.signed.json" \
  --workspace "$RUNTIME_ROOT/workspace" \
  --manifest "$RUNTIME_ROOT/operation-manifest.json" \
  -- "${WORKLOAD[@]}"

"$GENSEE" boundary verifier request \
  --manifest "$RUNTIME_ROOT/operation-manifest.json" \
  --ttl-seconds 300 \
  --output "$RUNTIME_ROOT/verifier-request.json"
"$GENSEE" boundary verifier run \
  --catalog "$RUNTIME_ROOT/catalog.signed.json" \
  --trusted-key "$RUNTIME_ROOT/organization-public.hex" \
  --manifest "$RUNTIME_ROOT/operation-manifest.json" \
  --request "$RUNTIME_ROOT/verifier-request.json" \
  --manifest "$RUNTIME_ROOT/operation-manifest.json" \
  --config "$RUNTIME_ROOT/verifier-config.json" \
  --verifier-key "$RUNTIME_ROOT/verifier.seed" \
  --output "$RUNTIME_ROOT/verifier-receipt.json"
"$GENSEE" boundary verifier verify \
  --catalog "$RUNTIME_ROOT/catalog.signed.json" \
  --trusted-key "$RUNTIME_ROOT/organization-public.hex" \
  --request "$RUNTIME_ROOT/verifier-request.json" \
  --receipt "$RUNTIME_ROOT/verifier-receipt.json"

"$GENSEE" boundary promotion apply \
  --catalog "$RUNTIME_ROOT/catalog.signed.json" \
  --trusted-key "$RUNTIME_ROOT/organization-public.hex" \
  --manifest "$RUNTIME_ROOT/operation-manifest.json" \
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
if grep -q 'accepted:18081' "$RUNTIME_ROOT/server.log"; then
  echo "unexpected endpoint received traffic" >&2
  exit 1
fi
sleep 0.2
[[ "$(grep -c 'accepted:18080' "$RUNTIME_ROOT/server.log")" -eq 2 ]]

BUNDLE="$RUNTIME_ROOT/proof-bundle"
mkdir -m 700 "$BUNDLE" "$BUNDLE/promoted-workspace" "$BUNDLE/promoted-workspace/out"
cp "$RUNTIME_ROOT/catalog.signed.json" "$BUNDLE/catalog.signed.json"
cp "$RUNTIME_ROOT/organization-public.hex" "$BUNDLE/organization-public.hex"
cp "$RUNTIME_ROOT/observation.json" "$BUNDLE/observation.json"
cp "$RUNTIME_ROOT/inference.signed.json" "$BUNDLE/inference.signed.json"
cp "$RUNTIME_ROOT/operation-manifest.json" "$BUNDLE/operation-manifest.json"
cp "$RUNTIME_ROOT/verifier-request.json" "$BUNDLE/verifier-request.json"
cp "$RUNTIME_ROOT/verifier-receipt.json" "$BUNDLE/verifier-receipt.json"
cp "$RUNTIME_ROOT/promotion-receipt.json" "$BUNDLE/promotion-receipt.json"
ACTIVE_TARGET="$(readlink "$RUNTIME_ROOT/promoted/current")"
cp -p "$RUNTIME_ROOT/promoted/$ACTIVE_TARGET" "$BUNDLE/promoted-workspace/out/result.json"

"$GENSEE" boundary proof sign --bundle "$BUNDLE" --key "$RUNTIME_ROOT/proof.seed"
"$GENSEE" boundary proof verify \
  --bundle "$BUNDLE" --trusted-key "$RUNTIME_ROOT/proof-public.hex"

jq -e '
  .enforcement.os_execution_binding_established == true and
  ([.enforcement.allowed_network_effects[].packets] | add) > 0 and
  ([.enforcement.denied_network_effects[].packets] | add) > 0 and
  .process.execution_subject_drained == true and
  .product.structurally_valid == true
' "$RUNTIME_ROOT/operation-manifest.json" >/dev/null

jq -e '
  .claims.isolation.profile == "linux_landlock_seccomp_no_write_no_network_no_fork_v1" and
  .claims.isolation.network_denied == true and
  .claims.isolation.process_creation_denied == true and
  .claims.isolation.filesystem_mutation_denied == true and
  .claims.reason_codes == ["fixture_semantics_valid", "isolation_verified"]
' "$RUNTIME_ROOT/verifier-receipt.json" >/dev/null

echo "generic privileged boundary proof passed"
