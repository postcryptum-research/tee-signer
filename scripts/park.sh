#!/usr/bin/env bash
# Parking routine (owner's rule, 2026-11-03): at the end of a working session, remove the dev
# session's OWN temporary files and leave nothing stray on the shared machines. Deletes ONLY the
# build artifacts this project creates under its own tree; release binaries and state are kept;
# shared scratch (/tmp, /tmp/claude-1000) is reported, never swept — that is the operator's call.
#   scripts/park.sh            laptop only
#   scripts/park.sh --remote   also read-only checks on the Hetzner box and the Azure node
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
echo "== laptop: debug build profiles under $ROOT (release binaries stay)"
for d in owner/owner-cli host/signerd core enclave/rcore tools/seed-leak-vector; do
  [ -d "$ROOT/$d/target/debug" ] && { du -sh "$ROOT/$d/target/debug" | awk '{print "   removing "$1" "$2}'; rm -rf "$ROOT/$d/target/debug"; }
done
echo "== laptop: sizes to know about (not touched)"
du -sh "$ROOT"/{owner/owner-cli,host/signerd,core,enclave/rcore}/target 2>/dev/null | awk '{print "   "$1" "$2}'
[ -d /tmp/claude-1000 ] && echo "   scratch /tmp/claude-1000: $(du -sh /tmp/claude-1000 2>/dev/null | cut -f1) (shared between sessions; clean by hand if needed)"
echo "== laptop: tunnels (expected: 7390 T1, 7395 T2, 7398 Hetzner node RPC)"
echo "   $(ss -ltn 2>/dev/null | awk '{print $4}' | grep -E ':739[0-9]$' | sort -u | tr '\n' ' ')"
df -h / | tail -1 | awk '{print "   root fs: "$3" used, "$4" free ("$5")"}'
if [ "${1:-}" = "--remote" ]; then
  echo "== hetzner box (read-only): forwards, build outputs, disk"
  ssh -o BatchMode=yes -o ConnectTimeout=15 andrey@94.130.18.162 'echo "   forwards: $(pgrep -af "[E]xitOnForwardFailure" | grep -oE "127.0.0.1:739[0-9]:[0-9.]+:[0-9]+" | tr "\n" " ")"; echo "   ~/tee-signer-out: $(du -sh ~/tee-signer-out 2>/dev/null | cut -f1) (build evidence, kept)"; df -h / | tail -1 | awk "{print \"   disk: \"\$3\" used, \"\$4\" free (\"\$5\")\"}"' 2>&1
  echo "== azure node (read-only): throwaway containers, own dir, disk (C-R5-3)"
  ssh -o BatchMode=yes -o ConnectTimeout=15 andrey@94.130.18.162 'ssh -o BatchMode=yes -o ConnectTimeout=15 azureuser@52.236.130.102 "stray=\$(docker ps -a --format \"{{.Names}}\" | grep -E \"^tee-.*-test\" | tr \"\\n\" \" \"); echo \"   throwaway containers: \${stray:-none}\"; echo \"   ~/tee-signer: \$(ls ~/tee-signer | tr \"\\n\" \" \")\"; df -h / | tail -1 | awk \"{print \\\"   disk: \\\"\\\$3\\\" used, \\\"\\\$4\\\" free (\\\"\\\$5\\\")\\\"}\""' 2>&1
fi
echo "== parked"
