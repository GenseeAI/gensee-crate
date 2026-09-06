#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/gensee-cowork-scope.XXXXXX")"
trap 'rm -rf "$test_directory"' EXIT
xcrun clang -fobjc-arc -fblocks -Wno-nullability-completeness -mmacosx-version-min=13.0 \
  -framework Foundation -lEndpointSecurity -lbsm \
  "$repository_root/macos/GenseeCrate/Tests/CoworkEndpointScopeTests.m" \
  -o "$test_directory/cowork-scope-tests"
"$test_directory/cowork-scope-tests" "$repository_root/integrations/claude-cowork/signing-identity-fixture.json"
