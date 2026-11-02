"""Test doubles. Nothing here touches the network (beyond 127.0.0.1), a real Docker, Trivy or the clock.

FakeRegistry   a local HTTP server that speaks enough of the registry API: token, tag list, manifest.
FakeHost       stands in for rpl.patch.Host: it interprets the docker / curl command lines `rpl patch` issues,
               keeps a tiny model of "which image runs", and records every command in order.
"""
import hashlib
import json
import os
import re
import threading
import types
import urllib.request
from urllib.parse import parse_qs, urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock


# ---- registry ------------------------------------------------------------------------------------------------------

class FakeRegistry:
    """tags: {repo: [tags]}; digests: {(repo, tag): digest}; broken: {repo: how} with how in
    {"500", "401", "not-json", "no-token"}. Every request is recorded in .requests as (method, path, Authorization)."""

    def __init__(self, tags=None, digests=None, broken=None, page_size=None, link_base=None, loop=False):
        """page_size: serve tag lists in pages of that size with a `Link: <...>; rel="next"` header (distribution spec).
        link_base: build the Link URL on this base instead of a relative one (another host). loop: the next link never advances."""
        self.tags, self.digests, self.broken = tags or {}, digests or {}, broken or {}
        self.page_size, self.link_base, self.loop = page_size, link_base, loop
        self.requests = []
        reg = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", headers=None):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _json(self, obj):
                self._send(200, json.dumps(obj).encode(), {"Content-Type": "application/json"})

            def handle_any(self):
                reg.requests.append((self.command, self.path, self.headers.get("Authorization")))
                m = re.match(r"^/token\?.*scope=repository:(.+):pull", self.path)
                if m:
                    if reg.broken.get(m.group(1)) == "no-token":
                        return self._json({})
                    return self._json({"token": "tok-" + m.group(1)})
                m = re.match(r"^/v2/(.+)/(tags/list|manifests/(.+?))(\?.*)?$", self.path)
                if not m:
                    return self._send(404)
                repo = m.group(1)
                if self.headers.get("Authorization") != "Bearer tok-" + repo:
                    return self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}')
                how = reg.broken.get(repo)
                if how == "500":
                    return self._send(500, b"boom")
                if how == "401":
                    return self._send(401, b"denied")
                if how == "not-json":
                    return self._send(200, b"<html>maintenance</html>")
                if m.group(2) == "tags/list":
                    if repo not in reg.tags:
                        return self._send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}')
                    if how == "null-tags":
                        return self._json({"name": repo, "tags": None})
                    tags = reg.tags[repo]
                    if not reg.page_size:
                        return self._json({"name": repo, "tags": tags})
                    last = parse_qs(urlsplit(self.path).query).get("last", [None])[0]
                    start = tags.index(last) + 1 if last in tags else 0
                    page = tags[start:start + reg.page_size]
                    headers = {"Content-Type": "application/json"}
                    if start + reg.page_size < len(tags) or reg.loop:
                        nxt = page[-1] if not reg.loop else (last or tags[0])
                        headers["Link"] = f'<{reg.link_base or ""}/v2/{repo}/tags/list?n={reg.page_size}&last={nxt}>; rel="next"'
                    return self._send(200, json.dumps({"name": repo, "tags": page}).encode(), headers)
                digest = reg.digests.get((repo, m.group(3)))
                if digest is None:
                    return self._send(404)
                return self._send(200, b"{}", {"Docker-Content-Digest": digest, "Content-Type": "application/vnd.oci.image.index.v1+json"})

            do_GET = do_HEAD = handle_any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)      # port 0: the OS picks a free one
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)

    def __enter__(self):
        self._thread.start()
        # Both supported registries are redirected to this server; the environment's proxy settings are bypassed.
        self._patch = mock.patch.dict("rpl.fixcheck.ENDPOINTS", {
            "ghcr.io": {"token": self.url + "/token?scope=repository:{repo}:pull", "api": self.url},
            "docker.io": {"token": self.url + "/token?scope=repository:{repo}:pull", "api": self.url}})
        self._patch.start()
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
        return self

    def __exit__(self, *exc):
        urllib.request.install_opener(None)
        self._patch.stop()
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(5)


# ---- docker host ---------------------------------------------------------------------------------------------------

def done(rc=0, out="", err=""):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


IMAGE_LINE = re.compile(r"^\s*image:\s*(.*?)\s*(#.*)?$")
SERVICE_KEY = re.compile(r"""^\s*["']?([A-Za-z0-9_.-]+)["']?\s*:\s*(#.*)?$""")


def image_id(ref):
    """The image ID a ref resolves to in the fake: same ref, same ID (what Docker's local store does for a tag)."""
    return "sha256:" + hashlib.sha256(ref.encode()).hexdigest()[:16]


def parse_services(path):
    """{service: {"image": resolved image or None, "build": bool}} for a simple compose file (one level of keys under `services:`).
    `${VAR:-default}` resolves to its default, as `docker compose config` would with VAR unset."""
    out, in_services, child, cur = {}, False, None, None
    for line in open(path, encoding="utf-8"):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_services, child, cur = text.split("#")[0].strip() == "services:", None, None
            continue
        if not in_services:
            continue
        if child is None:
            child = indent
        if indent == child:
            m = SERVICE_KEY.match(line)
            cur = m.group(1) if m else None
            if cur:
                out[cur] = {"image": None, "build": False}
        elif cur:
            m = IMAGE_LINE.match(line)
            if m and indent == child + 2 and line.lstrip().startswith("image:"):
                v = m.group(1)
                mv = re.match(r"^\$\{[A-Za-z_]+:-([^}]*)\}$", v)
                out[cur]["image"] = mv.group(1) if mv else v
            elif line.lstrip().startswith("build:") and indent == child + 2:
                out[cur]["build"] = True
    return out


class FakeHost:
    """Fake of rpl.patch.Host for ONE compose file; the service under test is `service`.

    The model: the running container's image is whatever the compose file says for that service at the moment of the last
    successful `compose up`. `unhealthy_images` makes a container of that image start but never become healthy;
    `route_codes` maps image -> HTTP status (or a list of statuses, consumed one per request, the last one repeating);
    `up_fails_for` makes `compose up` exit 1 WITHOUT touching the running container (what Docker does when an image cannot
    be pulled); `up_noop_for` makes it exit 0 WITHOUT touching the running container. `container` is the container name
    (default: the service name; real Compose says <project>-<service>-1). `dry_raw` replaces the dry-run output.
    Unknown commands raise: a test cannot silently run something it did not plan."""

    def __init__(self, compose_file, service="app", running_image=None, *, unhealthy_images=(), route_codes=None,
                 up_fails_for=(), up_noop_for=(), vpn=False, network_mode="", config_ok=True, config_rejects=(), dry_recreates=None,
                 dry_rc=0, dump_ok=True, snapshot_rc=0, dry_prefix="", container=None, dry_raw=None, rebuilt_on_up=None,
                 stopped=False, shared_image_with=(), curl_rc=None, raise_on_up=None):
        """stopped: the container exists but is not running until the first `compose up` (`ps -a` sees it, `ps` does not).
        shared_image_with: other services whose resolved image follows the service under test (a shared YAML anchor).
        curl_rc: image -> exit code curl returns while that image runs (the status it prints is still route_codes').
        raise_on_up: an exception raised by the first `compose up` that is not a dry run."""
        self.stopped, self.shared_image_with = stopped, set(shared_image_with)
        self.curl_rc, self.raise_on_up = curl_rc or {}, raise_on_up
        self.compose_file, self.service = compose_file, service
        self.container = container or service
        self.running = running_image or self._file_image()
        self.unhealthy_images, self.route_codes = set(unhealthy_images), {k: (list(v) if isinstance(v, list) else v) for k, v in (route_codes or {}).items()}
        self.up_fails_for, self.up_noop_for = set(up_fails_for), set(up_noop_for)
        self.network_mode, self.config_ok, self.config_rejects = ("service:gluetun" if vpn else network_mode), config_ok, set(config_rejects)
        self.dry_recreates, self.dry_rc, self.dump_ok, self.snapshot_rc = dry_recreates, dry_rc, dump_ok, snapshot_rc
        self.dry_prefix, self.dry_raw = dry_prefix, dry_raw
        self.ids = {}                            # image ref -> image ID override
        self.rebuilt_on_up = rebuilt_on_up or {}  # image ref -> ID the ref resolves to after a `compose up` of it
        self.calls, self.clock = [], 1_000_000.0
        self.up_images = []                      # image each `compose up` was asked for, in order

    # the Host interface
    def now(self):
        return self.clock

    def sleep(self, seconds):
        self.clock += seconds

    def run(self, cmd, **kw):
        self.calls.append(list(cmd))
        return self._dispatch(list(cmd))

    # helpers for assertions
    def kinds(self):
        """The sequence of steps, as short names, for ordering assertions."""
        out = []
        for c in self.calls:
            k = self._kind(c)
            if k and (not out or out[-1] != k):
                out.append(k)
        return out

    def _file_image(self):
        return (parse_services(self.compose_file).get(self.service) or {}).get("image")

    def _kind(self, c):
        if c[:2] == ["sh", "-c"]:
            return "snapshot"
        if c[:2] == ["docker", "exec"] and "pg_dump" in c:
            return "dump"
        if c[:2] == ["docker", "cp"]:
            return "dump-copy"
        if c[:2] == ["docker", "exec"] and "pg_restore" in c:
            return "dump-verify"
        if c[:2] == ["docker", "compose"]:
            rest = c[4:]
            if rest[:2] == ["config", "-q"]:
                return "validate"
            if rest[:1] == ["config"]:
                return "inspect-config"
            if rest[:1] == ["up"]:
                return "dry-run" if "--dry-run" in rest else "up"
            if rest[:1] == ["ps"]:
                return "ps"
        if c[:2] == ["docker", "inspect"]:
            return "inspect"
        if c[0] == "curl":
            return "route"
        return None

    def _dispatch(self, c):
        k = self._kind(c)
        if k == "snapshot":
            return done(self.snapshot_rc, "snapshot taken" if not self.snapshot_rc else "", "" if not self.snapshot_rc else "no space")
        if k == "dump":
            return done(0 if self.dump_ok else 1, "", "" if self.dump_ok else "pg_dump: error")
        if k == "dump-copy":
            if self.dump_ok:
                with open(c[3], "wb") as f:
                    f.write(b"PGDMP" + b"x" * 100)
            return done(0 if self.dump_ok else 1)
        if k == "dump-verify":
            return done(0, "\n".join(f"; entry {i}" for i in range(12)))
        if k == "validate":
            bad = self._file_image() in self.config_rejects
            return done(1 if bad else 0, "", "invalid compose file" if bad else "")
        if k == "inspect-config":
            if not self.config_ok:
                return done(1, "", "cannot load")
            services = {}
            parsed = parse_services(self.compose_file)
            for name, info in parsed.items():
                svc = {"network_mode": self.network_mode if name == self.service else ""}
                if name in self.shared_image_with:
                    svc["image"] = (parsed.get(self.service) or {}).get("image")
                elif info["image"] is not None:
                    svc["image"] = info["image"]
                if info["build"]:
                    svc["build"] = {"context": ".", "dockerfile": "Dockerfile"}
                services[name] = svc
            return done(0, json.dumps({"services": services}))
        if k == "dry-run":
            if self.dry_raw is not None:
                return done(self.dry_rc, "", self.dry_raw)
            names = self.dry_recreates if self.dry_recreates is not None else [self.container]
            return done(self.dry_rc, "", "\n".join(f" {self.dry_prefix}Container {n}  Recreate" for n in names))
        if k == "up":
            image = self._file_image()
            self.up_images.append(image)
            self.stopped = False
            if self.raise_on_up is not None:
                error, self.raise_on_up = self.raise_on_up, None
                raise error
            if image in self.up_fails_for:
                return done(1, "", f"Error response from daemon: manifest for {image} not found")
            if image in self.rebuilt_on_up:
                self.ids[image] = self.rebuilt_on_up[image]
            if image not in self.up_noop_for:
                self.running = image
            return done(0, "", f" Container {self.container}  Started")
        if k == "ps":
            exists = self.running and (self.stopped is False or "-a" in c)
            return done(0, "cid-1\n" if exists else "")
        if k == "inspect":
            healthy = self.running not in self.unhealthy_images
            return done(0, json.dumps([{"Name": "/" + self.container, "Image": self.ids.get(self.running) or image_id(self.running), "Config": {"Image": self.running},
                                        "State": {"Running": True, "Health": {"Status": "healthy" if healthy else "starting"}}}]))
        if k == "route":
            code = self.route_codes.get(self.running, 200)
            if isinstance(code, list):
                code = code.pop(0) if len(code) > 1 else code[0]
            return done(self.curl_rc.get(self.running, 0), str(code))
        raise AssertionError(f"FakeHost: unplanned command {c}")


def write_compose(directory, image, service="app"):
    path = os.path.join(directory, "compose.yaml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"services:\n  {service}:\n    image: {image}\n    restart: unless-stopped\n")
    return path


def write_compose_text(directory, text):
    path = os.path.join(directory, "compose.yaml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def rpl_config(directory, **overrides):
    """Write an rpl.json under `directory` (all paths inside it) and return its path. Use with mock.patch.dict(os.environ, {"RPL_CONFIG": path})."""
    cfg = {"state_dir": os.path.join(directory, "state"), "backup_dir": os.path.join(directory, "backups"),
           "trivy_cache": os.path.join(directory, "trivy-cache"), "apps_file": os.path.join(directory, "patch-apps.json"),
           "route_check_url": "https://proxy.example.test/", "health_timeout_s": 30, "route_timeout_s": 30,
           "snapshot_command": "true", "kev_url": "file://" + os.path.join(directory, "kev.json")}
    cfg.update(overrides)
    path = os.path.join(directory, "rpl.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    return path
