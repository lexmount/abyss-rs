#!/bin/sh
# Run the real packaged binaries through the piped installer using local assets.
set -eu

release=$(cd "$1" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/abyss-release-smoke.XXXXXX")
trap 'rm -rf "$work"' 0
trap 'exit 1' 1 2 15
mkdir "$work/commands"
# Only replace the download transport; hashing, unpacking and installation are real.
cat > "$work/commands/curl" <<'EOF'
#!/bin/sh
set -eu
output=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) output=$2; shift 2 ;;
        *) url=$1; shift ;;
    esac
done
cp "$ABYSS_RELEASE_FIXTURE/${url##*/}" "$output"
EOF
chmod 0755 "$work/commands/curl"
cat "$release/install.sh" | env PATH="$work/commands:$PATH" \
    ABYSS_RELEASE_FIXTURE="$release" DESTDIR="$work/stage" sh
for binary in abyss abyss-broker abyss-delivery-plugin; do
    "$work/stage/usr/local/bin/$binary" --help >/dev/null
done
"$work/stage/usr/local/bin/abyss" version
printf 'Packaged CLI installation smoke test passed.\n'
