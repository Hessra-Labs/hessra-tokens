#!/usr/bin/env bash
# Build the npm-publishable wasm package (@hessra/cap-token).
#
# Always use this instead of calling wasm-pack directly: wasm-pack regenerates
# pkg/package.json on every build, which (a) resets the package name to the
# crate name "hessra-cap-token-wasm" instead of the published "@hessra/cap-token"
# (a 0.2.0 escaped to npm under that wrong name), and (b) omits the generated
# snippets/ directory from the "files" whitelist, shipping a tarball whose wasm
# imports a missing file and fails to load in every consumer (this broke
# @hessra/cap-token 0.1.0 on npm).
#
# After this script: cd pkg && npm publish --access public
set -euo pipefail
cd "$(dirname "$0")"

wasm-pack build --target bundler --out-dir pkg

python3 - <<'EOF'
import json

with open("pkg/package.json") as f:
    pkg = json.load(f)
pkg["name"] = "@hessra/cap-token"
if "snippets/" not in pkg["files"]:
    pkg["files"].insert(0, "snippets/")
with open("pkg/package.json", "w") as f:
    json.dump(pkg, f, indent=2)
    f.write("\n")
print(f"pkg/package.json patched: {pkg['name']}@{pkg['version']}, files {pkg['files']}")
EOF

echo "Verifying the tarball ..."
listing=$(cd pkg && npm publish --dry-run 2>&1 || true)
echo "$listing" | grep -q "snippets/" || {
  echo "ERROR: snippets/ missing from tarball"
  exit 1
}
echo "$listing" | grep -q "@hessra/cap-token@" || {
  echo "ERROR: tarball is not named @hessra/cap-token"
  exit 1
}
echo "OK: tarball is @hessra/cap-token and includes snippets/"
