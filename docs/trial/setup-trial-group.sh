#!/usr/bin/env bash
# Builds a disposable update group for a supervised trial of `rpl group`:
#   - parent + two dependants sharing its network (network_mode: service:parent), on an INTERNAL Docker network, no published port;
#   - parent and dep-a on a deliberately old image (alpine:3.18.0), dep-b on an image with no finding (recreated only);
#   - its own rpl.json, state directory, backup directory and Trivy cache: nothing of an existing rpl setup is read or written.
# Usage: setup-trial-group.sh <new empty directory> <path to the risk-patch-loop checkout>
set -euo pipefail
T="${1:?usage: setup-trial-group.sh <new empty directory> <risk-patch-loop checkout>}"
RPL="${2:?usage: setup-trial-group.sh <new empty directory> <risk-patch-loop checkout>}"
[ -f "$RPL/rpl/groupapply.py" ] || { echo "refusing: $RPL is not a checkout that contains rpl/groupapply.py"; exit 1; }
if [ -e "$T" ] && [ -n "$(ls -A "$T" 2>/dev/null)" ]; then echo "refusing: $T exists and is not empty"; exit 1; fi
if docker ps -a --format '{{.Names}}' | grep -q '^rpltrial-'; then echo "refusing: containers named rpltrial-* already exist"; exit 1; fi
mkdir -p "$T"/proj/dep-a/config/db "$T"/proj/dep-b/config "$T"/state "$T"/backups "$T"/trivy-cache
T="$(cd "$T" && pwd)"; RPL="$(cd "$RPL" && pwd)"

cat > "$T/proj/compose.yaml" <<'YAML'
name: rpltrial
services:
  parent:
    image: alpine:3.18.0
    command: sleep infinity
    init: true
    networks: [isolated]
    labels:
      # Read by `rpl inventory` only, to DECLARE an exposure: without it the score of an unexposed container can never reach ACT.
      # No port is published and the network is internal. If a Traefik with the Docker provider runs on this host it may log
      # this router; it cannot reach the container.
      traefik.enable: "true"
      traefik.http.routers.rpltrial.rule: "Host(`rpl-trial.example.test`)"
  dep-a:
    image: alpine:3.18.0
    command: sleep infinity
    init: true
    network_mode: "service:parent"
    volumes:
      - ./dep-a/config:/config
  dep-b:
    image: busybox:1.36
    command: sleep infinity
    init: true
    network_mode: "service:parent"
    volumes:
      - ./dep-b/config:/config
networks:
  isolated:
    internal: true
YAML

echo '{"version": 1}' > "$T/proj/dep-a/config/settings.json"
echo 'not-a-real-secret' > "$T/proj/dep-a/config/secret.key"; chmod 600 "$T/proj/dep-a/config/secret.key"
echo 'pretend database v1' > "$T/proj/dep-a/config/db/app.sqlite"
ln -s settings.json "$T/proj/dep-a/config/current.json"
echo 'a = 1' > "$T/proj/dep-b/config/dep-b.conf"

cat > "$T/rpl.json" <<JSON
{
  "state_dir": "$T/state",
  "backup_dir": "$T/backups",
  "trivy_cache": "$T/trivy-cache",
  "roles_file": "$T/roles.json",
  "tunnel_hosts_file": "$T/tunnel-hosts.json",
  "snapshot_command": null,
  "health_timeout_s": 60,
  "groups": {"rpltrial-parent-1": {"policy": "ask", "reason": "supervised trial group", "confirmed": true, "controls": ["members_healthy"]}}
}
JSON
# Declared for the trial only: both roles, so that a fixable HIGH finding scores 50 (ACT) at the declared exposure.
echo '{"control_plane": ["rpltrial-parent-1", "rpltrial-dep-a-1"], "untrusted_input": ["rpltrial-parent-1", "rpltrial-dep-a-1"]}' > "$T/roles.json"
echo '["rpl-trial.example.test"]' > "$T/tunnel-hosts.json"

# `rpl scan` scans every running image. This wrapper only NARROWS it to the trial project; it supplies no result and skips no check.
cat > "$T/scan-trial-only.py" <<'PY'
import subprocess, sys
from rpl import scan
real = scan.images_running
def only_trial():
    wanted = set(subprocess.run(["docker", "ps", "--filter", "label=com.docker.compose.project=rpltrial", "--format", "{{.Image}}"],
                                capture_output=True, text=True).stdout.split())
    return {name: ref for name, ref in real().items() if name in wanted}
scan.images_running = only_trial
sys.exit(scan.main(sys.argv[1:]))
PY

cat > "$T/env.sh" <<ENV
export RPL_CONFIG="$T/rpl.json"
export PYTHONPATH="$RPL"
export F="$T/proj/compose.yaml"
export T="$T"
rpl() { python3 -m rpl "\$@"; }
ENV

docker compose -f "$T/proj/compose.yaml" up -d
echo
echo "trial group ready in $T"
echo "next: source $T/env.sh"
