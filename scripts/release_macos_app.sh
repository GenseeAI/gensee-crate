#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The Gensee Crate macOS release must be built on macOS." >&2
  exit 1
fi

release_version="${1:-}"
if [ -z "$release_version" ]; then
  echo "Usage: NOTARYTOOL_PROFILE=<keychain-profile> $0 <version>" >&2
  echo "Example: NOTARYTOOL_PROFILE=gensee-crate $0 0.3.1" >&2
  exit 1
fi
release_version="${release_version#v}"

notary_profile="${NOTARYTOOL_PROFILE:-}"
if [ -z "$notary_profile" ]; then
  echo "NOTARYTOOL_PROFILE must name credentials stored with 'notarytool store-credentials'." >&2
  exit 1
fi

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/.." && pwd)"
macos_project="$repository_root/macos/GenseeCrate"
project_spec="$macos_project/project.yml"
export_options="$macos_project/DeveloperIDExportOptions.plist"
declared_version="$(awk '/MARKETING_VERSION:/ { print $2; exit }' "$project_spec")"

if [ "$release_version" != "$declared_version" ]; then
  echo "Requested version $release_version does not match MARKETING_VERSION $declared_version." >&2
  exit 1
fi

for tool in cargo codesign hdiutil lipo rustup xcodebuild xcodegen xcrun; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required tool '$tool' was not found." >&2
    exit 1
  fi
done

for rust_target in aarch64-apple-darwin x86_64-apple-darwin; do
  if ! rustup target list --installed | grep -qx "$rust_target"; then
    echo "Install the missing Rust target with: rustup target add $rust_target" >&2
    exit 1
  fi
done

release_workspace="$(mktemp -d "${TMPDIR:-/tmp}/gensee-crate-release.XXXXXX")"
archive_path="$release_workspace/GenseeCrate.xcarchive"
export_path="$release_workspace/export"
dmg_staging="$release_workspace/dmg"
artifact_directory="$repository_root/dist"
artifact_path="$artifact_directory/Gensee-Crate.dmg"
app_path="$export_path/Gensee Crate.app"
extension_path="$app_path/Contents/Library/SystemExtensions/ai.gensee.crate.endpoint-security.systemextension"
cli_path="$app_path/Contents/Resources/bin/gensee"

cleanup() {
  rm -rf "$release_workspace"
}
trap cleanup EXIT

mkdir -p "$export_path" "$dmg_staging" "$artifact_directory"

(
  cd "$macos_project"
  xcodegen generate --spec project.yml
)

xcodebuild archive \
  -project "$macos_project/GenseeCrate.xcodeproj" \
  -scheme GenseeCrate \
  -configuration Release \
  -destination "generic/platform=macOS" \
  -archivePath "$archive_path" \
  -allowProvisioningUpdates

xcodebuild -exportArchive \
  -archivePath "$archive_path" \
  -exportPath "$export_path" \
  -exportOptionsPlist "$export_options" \
  -allowProvisioningUpdates

# Xcode exports the host and system extension with Developer ID, but the Rust CLI
# is an embedded resource rather than an Xcode target. Re-sign it with the same
# Developer ID identity and then re-seal the containing app bundle.
developer_id_application="$(
  codesign -dv --verbose=4 "$app_path" 2>&1 \
    | sed -n 's/^Authority=\(Developer ID Application:.*\)$/\1/p' \
    | head -n 1
)"
if [ -z "$developer_id_application" ]; then
  echo "Could not determine the exported app's Developer ID Application identity." >&2
  exit 1
fi

codesign \
  --force \
  --sign "$developer_id_application" \
  --identifier ai.gensee.crate.cli \
  --options runtime \
  --timestamp \
  "$cli_path"
codesign \
  --force \
  --sign "$developer_id_application" \
  --options runtime \
  --timestamp \
  --preserve-metadata=identifier,requirements,entitlements \
  "$app_path"

codesign --verify --deep --strict --verbose=4 "$app_path"
if ! codesign -dv --verbose=4 "$cli_path" 2>&1 | grep 'flags=.*runtime' >/dev/null; then
  echo "The embedded Gensee CLI is missing Hardened Runtime." >&2
  exit 1
fi
lipo "$app_path/Contents/MacOS/Gensee Crate" -verify_arch x86_64 arm64
lipo "$extension_path/Contents/MacOS/ai.gensee.crate.endpoint-security" -verify_arch x86_64 arm64
lipo "$cli_path" -verify_arch x86_64 arm64

/usr/bin/ditto "$app_path" "$dmg_staging/Gensee Crate.app"
ln -s /Applications "$dmg_staging/Applications"
hdiutil create \
  -volname "Gensee Crate" \
  -srcfolder "$dmg_staging" \
  -format UDZO \
  -ov \
  "$artifact_path"

xcrun notarytool submit "$artifact_path" \
  --keychain-profile "$notary_profile" \
  --wait
xcrun stapler staple "$artifact_path"
xcrun stapler validate "$artifact_path"

echo
echo "Release artifact: $artifact_path"
shasum -a 256 "$artifact_path"
