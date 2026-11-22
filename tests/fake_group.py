"""A fake Docker host for ONE compose project that holds an update group (a parent and the services that share its network).

It keeps a small model of what real Docker does and that the group apply depends on:
  - a recreated container gets a NEW container ID;
  - a dependant remembers the ID of the parent it was created against (`HostConfig.NetworkMode: container:<id>`), so a dependant that
    was not recreated after its parent still points at the old, dead namespace: its exit address can no longer be read;
  - `compose up` that fails leaves the existing container as it was; `compose stop` stops it.
Every real `compose up` must carry --no-deps and --force-recreate, or the fake raises. Unknown commands raise.
What it does NOT model: image pulls, volumes, real health checks, real networking, timing, Docker's own error texts.
"""
import json
import os

from .fakes import done, image_id, parse_services

HOST_ADDRESS, TUNNEL_ADDRESS = "203.0.113.1", "198.51.100.7"


class GroupHost:
    def __init__(self, compose_file, parent, dependants, standalone=(), project="proj", binds=None):
        self.compose_file, self.parent, self.dependants, self.standalone, self.project = compose_file, parent, list(dependants), list(standalone), project
        self.binds = binds or {}                 # service -> [absolute host paths mounted into it]
        self.clock = 1_000_000.0
        self.calls, self.log = [], []            # every command; and (verb, service) for stop / up
        self.fail_up_images = set()              # `compose up` exits 1 for a service whose file image is one of these
        self.unhealthy_images = set()            # a container of one of these images starts and never becomes healthy
        self.stop_fails = set()                  # services `compose stop` fails for
        self.leak_images = set()                 # while the parent runs one of these, it exits with the host's own address
        self.dependant_leak_images = set()       # a dependant running one of these exits with the host's own address
        self.ids = {}                            # image ref -> image ID override
        self.extras = []                         # raw `docker inspect` objects of containers outside the project
        self.hooks = {}                          # (verb, service) -> callable run just before the command takes effect
        self.dry_extra = []                      # more container names the dry run claims it would recreate
        self.ps_all_rc = 0
        self.c = {}
        images = parse_services(compose_file)
        for svc in [parent, *self.dependants, *self.standalone]:
            self.c[svc] = {"n": 1, "image": images[svc]["image"], "running": True, "ns": None}
        for svc in self.dependants:
            self.c[svc]["ns"] = self.cid(parent)

    # ---- the Host interface
    def now(self):
        return self.clock

    def sleep(self, seconds):
        self.clock += seconds

    def run(self, cmd, **kw):
        cmd = list(cmd)
        self.calls.append(cmd)
        if cmd[:2] == ["sh", "-c"]:
            return done(0, "snapshot taken")
        if cmd[0] == "curl":
            return done(0, HOST_ADDRESS + "\n")
        if cmd[:2] == ["docker", "run"]:
            return self._address(cmd[cmd.index("--network") + 1].split(":", 1)[1])
        if cmd[:3] == ["docker", "ps", "-aq"]:
            return done(self.ps_all_rc, "\n".join([self.cid(s) for s in self.c] + [e["Id"] for e in self.extras]))
        if cmd[:2] == ["docker", "inspect"]:
            return done(0, json.dumps([self._inspect(ref) for ref in cmd[2:]]))
        if cmd[:4] == ["docker", "compose", "-f", self.compose_file]:
            return self._compose(cmd[4:])
        raise AssertionError(f"GroupHost: unplanned command {cmd}")

    # ---- helpers for tests
    def name(self, svc):
        return f"{self.project}-{svc}-1"

    def cid(self, svc):
        return f"{svc}-c{self.c[svc]['n']}"

    def file_image(self, svc):
        return parse_services(self.compose_file)[svc]["image"]

    def verbs(self):
        return [(v, s) for v, s in self.log]

    def attached(self):
        """Dependants whose network namespace is the CURRENT parent container."""
        return [s for s in self.dependants if self.c[s]["ns"] == self.cid(self.parent)]

    # ---- the model
    def _service_of(self, ref):
        for svc in self.c:
            if ref in (self.cid(svc), self.name(svc)):
                return svc
        return None

    def _inspect(self, ref):
        for e in self.extras:
            if ref in (e["Id"], e["Name"].lstrip("/")):
                return e
        svc = self._service_of(ref)
        if svc is None:
            raise AssertionError(f"GroupHost: inspect of an unknown container {ref}")
        c = self.c[svc]
        healthy = c["image"] not in self.unhealthy_images
        return {"Id": self.cid(svc), "Name": "/" + self.name(svc), "Image": self.ids.get(c["image"]) or image_id(c["image"]),
                "Config": {"Image": c["image"]}, "HostConfig": {"NetworkMode": "container:" + c["ns"] if c["ns"] else "default"},
                "State": {"Running": c["running"], "Health": {"Status": "healthy" if healthy else "starting"}}}

    def _address(self, container):
        svc = self._service_of(container)
        c = self.c[svc]
        if not c["running"] or (svc in self.dependants and c["ns"] != self.cid(self.parent)) or not self.c[self.parent]["running"]:
            return done(1, "")                   # a dead namespace answers nothing
        leak = self.c[self.parent]["image"] in self.leak_images or c["image"] in self.dependant_leak_images
        return done(0, (HOST_ADDRESS if leak else TUNNEL_ADDRESS) + "\n")

    def _compose(self, rest):
        if rest[:2] == ["config", "-q"]:
            return done(0)
        if rest[:1] == ["config"]:
            services = {}
            for svc in self.c:
                services[svc] = {"image": self.file_image(svc), "network_mode": f"service:{self.parent}" if svc in self.dependants else "",
                                 "volumes": [{"type": "bind", "source": p, "target": "/mnt/" + os.path.basename(p)} for p in self.binds.get(svc, [])]}
            return done(0, json.dumps({"services": services}))
        if rest[:1] == ["ps"]:
            svc = rest[-1]
            return done(0, self.cid(svc) + "\n" if (self.c[svc]["running"] or "-a" in rest) else "")
        if rest[:1] == ["stop"]:
            svc = rest[-1]
            self._hook("stop", svc)
            self.log.append(("stop", svc))
            if svc in self.stop_fails:
                return done(1, "", "cannot stop container")
            self.c[svc]["running"] = False
            return done(0)
        if rest[:1] == ["up"]:
            services = [x for x in rest[1:] if not x.startswith("-")]
            if "--dry-run" in rest:
                return done(0, "", "\n".join(f" Container {n}  Recreate" for n in [self.name(s) for s in services] + self.dry_extra))
            if "--no-deps" not in rest or "--force-recreate" not in rest or len(services) != 1:
                raise AssertionError(f"GroupHost: a real `up` must recreate ONE service with --no-deps --force-recreate, got {rest}")
            svc = services[0]
            self._hook("up", svc)
            self.log.append(("up", svc))
            image = self.file_image(svc)
            if image in self.fail_up_images:
                return done(1, "", f"Error response from daemon: manifest for {image} not found")
            c = self.c[svc]
            c.update(n=c["n"] + 1, image=image, running=True)
            c["ns"] = self.cid(self.parent) if svc in self.dependants else None
            return done(0, "", f" Container {self.name(svc)}  Started")
        raise AssertionError(f"GroupHost: unplanned compose command {rest}")

    def _hook(self, verb, svc):
        fn = self.hooks.get((verb, svc))
        if fn:
            fn()
