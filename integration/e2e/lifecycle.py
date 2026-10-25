#!/usr/bin/env python3
"""Test-only stock-client lifecycle, invoked exclusively through run.sh.

No synthetic control replies or direct tkad mutations: every authority change is
made by the unmodified tailscale CLI. Observations use the real tailscaled LocalAPI
(/tka/status and /status), not CLI text parsing. Source contracts: Tailscale
v1.102.0 client/local/tailnetlock.go, ipn/ipnstate/ipnstate.go, and
control/controlclient/direct.go (LoginInteractive regenerates the node key).
Rotation completes Headscale's real `auth register` flow only after observing
an AuthURL and checking the old identity remains committed while auth is pending.
Negative requests use stock-generated signatures and require explicit upstream
HTTP rejection; CLI-local validation failures and timeouts do not count.

This proves client netmap admission, not packet delivery, production isolation,
power-loss durability, or immediate revocation of already-installed peers during
an outage. DERP is deliberately unavailable on loopback: only control-plane state
is asserted. All subprocesses and state belong to this one disposable invocation.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
TIMEOUT = 90


class Failure(Exception):
    pass


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("local-tailscaled.sock", timeout=4)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Harness:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="omnet-e2e-", dir="/tmp"))
        self.root.chmod(0o700)
        self.bin = args.bin_dir.resolve()
        self.headscale = args.headscale.resolve()
        self.tkad = args.tkad.resolve()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("TS_", "HEADSCALE_", "OMNET_", "TAILSCALE_"))
                    and k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        self.env.update(HOME=str(self.root / "home"), XDG_CONFIG_HOME=str(self.root / "config"),
                        XDG_CACHE_HOME=str(self.root / "cache"), TS_NO_LOGS_NO_SUPPORT="true",
                        NO_PROXY="*")
        for name in ("home", "config", "cache", "authority"):
            (self.root / name).mkdir(mode=0o700)
        self.processes = {}
        self.clients = {}
        self.events = []
        self.sequence = 0
        self.url = "http://127.0.0.1:18080"
        self.hsenv = dict(self.env, OMNET_TKAD_SOCKET=str(self.root / "authority/tkad.sock"),
                          OMNET_TKAD_ADMIN_USER_ID="1")
        self.hsconfig = self.root / "headscale.json"
        # Headscale accepts JSON through Viper. A nonempty local-only DERP map is
        # mandatory upstream even when no data-plane checks are requested.
        # Local DERP files use Go YAML field names, unlike the remote JSON API.
        (self.root / "derp.yaml").write_text(
            "regions:\n  999:\n    regionid: 999\n    regioncode: e2e\n"
            "    regionname: Isolated E2E\n    nodes:\n"
            "      - name: e2e\n        regionid: 999\n        hostname: localhost\n"
            "        ipv4: 127.0.0.1\n        derpport: 9\n        stunport: -1\n")
        self.hsconfig.write_text(json.dumps({
            "server_url": self.url, "listen_addr": "127.0.0.1:18080",
            "metrics_listen_addr": "127.0.0.1:19090", "grpc_listen_addr": "127.0.0.1:15043",
            "grpc_allow_insecure": False, "disable_check_updates": True,
            "unix_socket": str(self.root / "headscale.sock"), "unix_socket_permission": "0600",
            "noise": {"private_key_path": str(self.root / "noise.key")},
            "database": {"type": "sqlite", "sqlite": {"path": str(self.root / "headscale.sqlite"),
                                                       "write_ahead_log": True}},
            "prefixes": {"v4": "100.64.0.0/24", "allocation": "sequential"},
            "dns": {"magic_dns": False, "override_local_dns": False,
                    "base_domain": "e2e.invalid", "nameservers": {"global": []}},
            "derp": {"server": {"enabled": False}, "urls": [],
                     "paths": [str(self.root / "derp.yaml")], "auto_update_enabled": False},
            "logtail": {"enabled": False}, "log": {"level": "info"},
            "policy": {"mode": "file"}, "node": {"ephemeral": {"inactivity_timeout": "30m"}},
        }))

    def start(self, label, argv, env=None):
        old = self.processes.get(label)
        if old and old.poll() is None:
            raise Failure("attempt to duplicate process " + label)
        self.sequence += 1
        with open(self.root / f"{self.sequence:03}-{label}.log", "wb") as log:
            proc = subprocess.Popen([str(x) for x in argv], stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, env=env or self.env,
                                    cwd=self.root, start_new_session=True)
        self.processes[label] = proc
        return proc

    def stop(self, label, crash=False):
        proc = self.processes.pop(label, None)
        if not proc or proc.poll() is not None:
            return
        os.killpg(proc.pid, signal.SIGKILL if crash else signal.SIGTERM)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=8)

    def command(self, label, argv, env=None, timeout=40, require=True):
        self.sequence += 1
        try:
            result = subprocess.run([str(x) for x in argv], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=timeout, env=env or self.env, cwd=self.root)
        except subprocess.TimeoutExpired as exc:
            raise Failure(label + " timed out (not counted as a negative-test success)") from exc
        (self.root / f"{self.sequence:03}-{label}.stdout").write_bytes(result.stdout)
        (self.root / f"{self.sequence:03}-{label}.stderr").write_bytes(result.stderr)
        if require and result.returncode != 0:
            raise Failure(label + f" returned {result.returncode}; private log retained only with --keep")
        return result

    def hs(self, *args):
        result = self.command("headscale-cli", [self.headscale, "--config", self.hsconfig,
                                               *args, "--output", "json"], env=self.hsenv)
        return json.loads(result.stdout)

    def cli(self, name, *args, require=True):
        return self.command(name + "-cli", [self.bin / "tailscale", "--socket",
                                           self.clients[name]["socket"], *args], require=require)

    def local(self, name, endpoint="tka/status"):
        connection = UnixHTTP(self.clients[name]["socket"])
        try:
            connection.request("GET", "/localapi/v0/" + endpoint,
                               headers={"Sec-Tailscale": "localapi", "Connection": "close"})
            response = connection.getresponse()
            data = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(data) > 1024 * 1024:
                raise Failure("LocalAPI read failed on " + name)
            return json.loads(data)
        finally:
            connection.close()

    def wait(self, label, predicate, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for service in ("tkad", "headscale"):
                p = self.processes.get(service)
                if p and p.poll() is not None and not getattr(self, "outage", False):
                    raise Failure(service + f" exited unexpectedly ({p.returncode}) during " + label)
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, http.client.HTTPException, json.JSONDecodeError):
                pass  # The same bounded predicate must eventually positively succeed.
            time.sleep(0.25)
        raise Failure("timed out awaiting " + label)

    def check(self, condition, message):
        if not condition:
            raise Failure(message)

    def receipt(self, name, **details):
        self.events.append({"scenario": name, "verdict": "PASS", **details})
        print("PASS: " + name, flush=True)

    def start_tkad(self, initialize=False):
        argv = [self.tkad, self.root / "authority"]
        if initialize:
            argv.append("--init")
        self.start("tkad", argv)
        # Connect only: do not act as a trusted adapter or fabricate any RPC.
        def ready():
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(1)
                sock.connect(str(self.root / "authority/tkad.sock"))
            return True
        self.wait("tkad socket", ready)

    def start_headscale(self):
        self.start("headscale", [self.headscale, "--config", self.hsconfig, "serve"], self.hsenv)
        def healthy():
            with urllib.request.urlopen(self.url + "/health", timeout=2) as response:
                return response.status == 200
        self.wait("Headscale health", healthy)

    def start_client(self, name, user=None):
        if name not in self.clients:
            directory = self.root / name
            directory.mkdir(mode=0o700)
            self.clients[name] = {"socket": directory / "tailscaled.sock", "dir": directory,
                                  "user": user}
        client = self.clients[name]
        self.start(name, [self.bin / "tailscaled", "--tun=userspace-networking", "--port=0",
                          "--socket=" + str(client["socket"]),
                          "--state=" + str(client["dir"] / "tailscaled.state"),
                          "--statedir=" + str(client["dir"])])
        self.wait(name + " LocalAPI", lambda: self.local(name, "status"))

    def login(self, name):
        key = self.hs("preauthkeys", "create", "--user", str(self.clients[name]["user"]),
                      "--expiration", "1h", "--reusable")["key"]
        # The authentication key is kept in the private runtime directory, not
        # printed in the test receipt. All CLI calls select an explicit socket.
        keyfile = self.clients[name]["dir"] / "auth-key"
        keyfile.write_text(key)
        args = [self.bin / "tailscale", "--socket", self.clients[name]["socket"], "up",
                "--login-server=" + self.url, "--auth-key=file:" + str(keyfile),
                "--hostname=" + name, "--accept-dns=false", "--accept-routes=false",
                "--timeout=45s"]
        self.stop(name + "-up")
        self.start(name + "-up", args)

    def rotate_interactively(self, name):
        old_key = self.keys(name)[0]
        old_url = self.local(name, "status").get("AuthURL")
        before = [n for n in self.hs("nodes", "list") if n["node_key"] == old_key]
        self.check(len(before) == 1, "rotation requires one committed original identity")
        original = before[0]
        self.stop(name + "-up")
        # Deliberately supply no preauth key: the stock LoginInteractive flow
        # generates and signs the new key, then requires real controller auth.
        proc = self.start(name + "-up", [
            self.bin / "tailscale", "--socket", self.clients[name]["socket"], "up",
            "--login-server=" + self.url, "--force-reauth", "--hostname=" + name,
            "--accept-dns=false", "--accept-routes=false", "--timeout=45s"])

        def pending_auth():
            self.check(proc.poll() is None, "interactive rotation exited before authentication")
            url = self.local(name, "status").get("AuthURL")
            return url if url and url != old_url else None

        url = self.wait("interactive rotation authentication URL", pending_auth, timeout=30)
        match = re.fullmatch(re.escape(self.url) + r"/register/([A-Za-z0-9_-]+)", url)
        self.check(match is not None, "unexpected interactive registration URL")

        def uncommitted():
            nodes = [n for n in self.hs("nodes", "list") if n["id"] == original["id"]]
            return (proc.poll() is None and len(nodes) == 1 and
                    nodes[0]["node_key"] == old_key and nodes[0]["user"]["id"] == original["user"]["id"])

        self.stable("rotation waits for authenticated registration", uncommitted, seconds=1)
        # CLI auth registration is the upstream non-OIDC operator flow. The
        # registration ID and its output stay only in the private runtime logs.
        registered = self.hs("auth", "register", "--auth-id", match.group(1),
                             "--user", original["user"]["name"])
        self.check(registered["id"] == original["id"] and
                   registered["user"]["id"] == original["user"]["id"],
                   "interactive registration changed node or user identity")
        self.wait("authenticated rotation CLI completion", lambda: proc.poll() is not None, timeout=30)
        self.check(proc.returncode == 0, "authenticated rotation CLI failed")

    def joined(self, name):
        st = self.local(name, "status")
        return (st.get("Self") or {}).get("ID") and self.local(name).get("NodeKey")

    def connected(self, name):
        status = self.local(name, "status")
        # Cached client state alone must not satisfy a server recovery check.
        return status.get("BackendState") == "Running" and (status.get("Self") or {}).get("Online")

    def keys(self, name):
        status = self.local(name)
        return status["NodeKey"], status["PublicKey"]

    @staticmethod
    def peers(status, field):
        return {p["NodeKey"] for p in status.get(field) or []}

    def admitted(self, observer, nodekey):
        status = self.local(observer)
        normal = self.local(observer, "status")
        return (status["Enabled"] and nodekey in self.peers(status, "VisiblePeers")
                and nodekey not in self.peers(status, "FilteredPeers")
                and nodekey in (normal.get("Peer") or {}))

    def rejected(self, observer, nodekey):
        status = self.local(observer)
        normal = self.local(observer, "status")
        return (status["Enabled"] and nodekey in self.peers(status, "FilteredPeers")
                and nodekey not in self.peers(status, "VisiblePeers")
                and nodekey not in (normal.get("Peer") or {}))

    def same_head(self, names, expected=None):
        states = [self.local(n) for n in names]
        head = states[0].get("Head")
        return head and all(s.get("Enabled") and s.get("Head") == head for s in states) and (
            expected is None or head == expected)

    def stable(self, label, predicate, seconds=3):
        self.wait(label, predicate)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.check(predicate(), label + " regressed during stable observation")
            time.sleep(0.25)

    def restart_all(self):
        for name in self.clients:
            self.stop(name + "-up")
            self.stop(name)
        self.stop("headscale")
        self.stop("tkad", crash=True)
        self.start_tkad()
        self.start_headscale()
        for name in self.clients:
            self.start_client(name)

    def scenario(self):
        for path in (self.headscale, self.tkad, self.bin / "tailscale", self.bin / "tailscaled"):
            self.check(path.is_file() and os.access(path, os.X_OK), "missing executable: " + str(path))
        provenance = json.loads((self.bin / "stock-client.json").read_text())
        self.check(provenance["version"] == "v1.102.0", "wrong stock-client version")
        for name in ("tailscale", "tailscaled"):
            digest = hashlib.sha256((self.bin / name).read_bytes()).hexdigest()
            self.check(digest == provenance["sha256"][name], "stock-client provenance mismatch: " + name)
        self.receipt("stock-client-artifacts", version=provenance["version"], sha256=provenance["sha256"])
        self.start_tkad(initialize=True)
        self.start_headscale()
        owner = self.hs("users", "create", "owner")
        member = self.hs("users", "create", "member")
        self.check(int(owner["id"]) == 1, "fresh DB owner ID differs from explicit adapter configuration")
        for name in ("a", "b"):
            self.start_client(name, int(owner["id"]))
            self.login(name)
            self.wait(name + " registration", lambda n=name: self.joined(n))
        akey, apub = self.keys("a")
        bkey, bpub = self.keys("b")
        self.wait("pre-lock peer roster", lambda: bkey in (self.local("a", "status").get("Peer") or {}))
        output = self.cli("a", "lock", "init", "--confirm", "--gen-disablements=1", apub, bpub)
        secrets = re.findall(rb"disablement-secret:[0-9A-Fa-f]{64}", output.stdout)
        self.check(len(secrets) == 1, "init did not return exactly one disablement secret")
        secret = secrets[0].decode("ascii")
        self.wait("initialized authority", lambda: self.same_head(["a", "b"]) and
                  self.local("a")["NodeKeySigned"] and self.local("b")["NodeKeySigned"] and
                  self.admitted("a", bkey) and self.admitted("b", akey))
        self.receipt("init-and-initial-roster-signatures")

        self.start_client("c", int(member["id"]))
        self.login("c")
        self.wait("unsigned node registration", lambda: self.joined("c"))
        ckey, cpub = self.keys("c")
        self.stable("unsigned peer rejection", lambda: self.rejected("a", ckey) and
                    self.rejected("b", ckey) and self.local("c")["Enabled"] and
                    not self.local("c")["NodeKeySigned"])
        self.receipt("new-unsigned-node-filtered-by-stock-clients")
        self.cli("b", "lock", "sign", ckey, cpub)
        self.wait("signature-only notification", lambda: self.admitted("a", ckey) and
                  self.admitted("b", ckey) and self.local("c")["NodeKeySigned"])
        self.receipt("sign-and-signature-only-peer-notification")

        # The stock client signs its rotation wrapper, but that is not a user
        # login. Complete upstream interactive auth before accepting the change.
        self.rotate_interactively("c")
        self.wait("client node-key rotation", lambda: self.joined("c") and
                  self.keys("c")[0] != ckey and self.local("c")["NodeKeySigned"])
        rotated = self.keys("c")[0]
        self.wait("rotated peer signature", lambda: self.admitted("a", rotated) and self.admitted("b", rotated))
        rotation = self.local("c")["NodeKeySignature"]
        self.check(rotation.get("SigKind") == 2 and rotation.get("Nested"), "client did not retain a rotation signature")
        for observer in ("a", "b"):
            self.check(ckey not in (self.local(observer, "status").get("Peer") or {}), "old node key remained visible")
        self.receipt("stock-client-node-key-rotation",
                     authentication="headscale-auth-register", pending_rotation_uncommitted=True)

        # A real, valid stock-generated signature for the retired key must reach
        # the daemon and get 404. Local validation failures and transport failures
        # are not passes, and the rejection must not poison other clients.
        rotation_head = self.local("a")["Head"]
        failed = self.cli("a", "lock", "sign", ckey, cpub, require=False)
        self.check(failed.returncode > 0 and b"404" in failed.stderr + failed.stdout,
                   "retired-key sign must produce explicit 404, not success or local validation failure")
        self.stable("rejected signature leaves active tailnet healthy", lambda:
                    self.same_head(["a", "b", "c"], rotation_head) and
                    all(self.connected(n) for n in ("a", "b", "c")) and
                    self.admitted("a", rotated) and self.admitted("b", rotated) and
                    self.local("c")["NodeKeySigned"])
        self.receipt("retired-node-key-signature-request-rejected", http_status=404)

        # Disabling automatic re-sign is deliberate: it makes key removal's
        # authorization effect observable rather than transparently repairing it.
        self.cli("a", "lock", "remove", "--re-sign=false", bpub)
        self.wait("authority-key removal", lambda: self.same_head(["a", "b", "c"]) and
                  all(bpub not in {k["Key"] for k in self.local(n)["TrustedKeys"]} for n in ("a", "b", "c")))
        self.stable("removed authority rejects its rotated node", lambda: self.rejected("a", rotated) and
                    self.rejected("b", rotated) and not self.local("c")["NodeKeySigned"])
        self.receipt("authority-key-removal-invalidates-rotated-node")
        self.cli("a", "lock", "sign", rotated, cpub)
        self.wait("surviving authority re-sign", lambda: self.admitted("a", rotated) and self.local("c")["NodeKeySigned"])

        head = self.local("a")["Head"]
        state_id = self.local("a")["StateID"]
        self.restart_all()
        self.wait("persisted active authority", lambda: self.same_head(["a", "b", "c"], head) and
                  self.admitted("a", rotated) and self.local("c")["NodeKeySigned"] and
                  all(self.connected(n) and self.local(n)["StateID"] == state_id for n in ("a", "b", "c")))
        self.check(self.keys("c")[0] == rotated, "restart changed node identity")
        self.check({k["Key"] for k in self.local("a")["TrustedKeys"]} == {apub}, "removed key returned after recovery")
        self.receipt("daemon-controller-and-client-persisted-recovery")

        # c belongs to the non-owner Headscale user. Its real client validates
        # this known-good secret locally, then the authenticated controller must
        # deny the operation; possession of the secret is not an admin assertion.
        denied = self.cli("c", "lock", "disable", secret, require=False)
        self.check(denied.returncode > 0 and b"403" in denied.stderr + denied.stdout,
                   "non-owner disable must produce explicit 403, not success, timeout, or local validation failure")
        self.stable("owner policy preserves authority", lambda: self.same_head(["a", "b", "c"], head)
                    and all(self.local(n)["StateID"] == state_id for n in ("a", "b", "c")))
        self.receipt("non-owner-valid-secret-disable-denied", http_status=403)

        self.start_client("d", int(member["id"]))
        self.login("d")
        self.wait("outage test unsigned registration", lambda: self.joined("d"))
        dkey, dpub = self.keys("d")
        self.wait("outage test initial rejection", lambda: self.rejected("a", dkey))
        self.outage = True
        self.stop("tkad", crash=True)
        for operation in (("sign", dkey, dpub), ("disable", secret)):
            failed = self.cli("a", "lock", *operation, require=False)
            self.check(failed.returncode > 0 and b"503" in failed.stderr + failed.stdout,
                       "outage must produce explicit 503, not success, timeout, or local CLI validation failure")
        self.stable("outage retains client protection", lambda: self.local("a")["Enabled"] and
                    self.local("a")["Head"] == head and self.rejected("a", dkey))
        self.start_client("e", int(member["id"]))
        self.login("e")
        # Positive observation of the upstream registration failure, plus actual
        # client state, distinguishes a rejected request from a merely slow join.
        def registration_rejected():
            logs = list(self.root.glob("*-e.log"))
            if not logs:
                return False
            data = logs[-1].read_bytes()
            # RegisterResponse.Error is an upstream application-level rejection,
            # unlike the TKA RPCs' HTTP503. Require a completed negative response.
            return (b"RegisterReq: got response; nodeKeyExpired=false, machineAuthorized=false; authURL=false" in data
                    and b"Received error:" in data
                    and self.local("e", "status").get("BackendState") == "NeedsLogin")
        self.wait("registration receives explicit outage rejection", registration_rejected, timeout=30)
        self.check(not self.joined("e"), "fresh client joined during tkad outage")
        self.receipt("daemon-outage-sign-disable-and-registration-fail-closed")
        self.start_tkad()
        self.outage = False
        self.wait("outage recovery retains authority", lambda: self.same_head(["a", "b", "c", "d"], head))
        self.wait("retry joins after daemon recovery", lambda: self.joined("e"))
        ekey, _ = self.keys("e")
        self.wait("retry remains unsigned", lambda: self.rejected("a", ekey) and self.rejected("a", dkey))
        self.receipt("outage-recovery-does-not-authorize-failed-mutations")

        self.cli("a", "lock", "disable", secret)
        names = list(self.clients)
        self.wait("disable propagates to all stock clients", lambda: all(not self.local(n)["Enabled"] for n in names)
                  and all(k in (self.local("a", "status").get("Peer") or {}) for k in (rotated, dkey, ekey)))
        self.receipt("disable-unfilters-previously-unsigned-peers")
        self.restart_all()
        self.wait("persisted disablement", lambda: all(self.connected(n) and not self.local(n)["Enabled"] for n in names)
                  and all(k in (self.local("a", "status").get("Peer") or {}) for k in (rotated, dkey, ekey)))
        self.receipt("disablement-persists-across-full-restart")

    def close(self):
        for label in reversed(list(self.processes)):
            self.stop(label)
        if self.args.keep:
            print("Private disposable state retained at " + str(self.root), file=sys.stderr)
        else:
            shutil.rmtree(self.root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outer-netns", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "build/e2e")
    parser.add_argument("--headscale", type=Path, default=ROOT / "build/headscale")
    parser.add_argument("--tkad", type=Path, default=ROOT / "build/tkad")
    parser.add_argument("--run-uid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--run-gid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--result", type=Path, help="write a redacted machine-readable receipt")
    args = parser.parse_args()
    if os.readlink("/proc/self/ns/net") == args.outer_netns or {n for _, n in socket.if_nameindex()} != {"lo"}:
        print("NOT_RUN: requires a fresh loopback-only network namespace; use run.sh", file=sys.stderr)
        return 77
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    # Stock clients pause control traffic with only loopback. A namespace-local
    # dummy link satisfies their network monitor without providing any egress.
    subprocess.run(["ip", "link", "add", "e2e0", "type", "dummy"], check=True)
    subprocess.run(["ip", "addr", "add", "192.0.2.1/32", "dev", "e2e0"], check=True)
    subprocess.run(["ip", "link", "set", "e2e0", "up"], check=True)
    if args.run_uid is not None or args.run_gid is not None:
        if args.run_uid is None or args.run_gid is None or args.run_uid <= 0 or args.run_gid < 0:
            raise SystemExit("privileged launcher requires a non-root invoking UID and its GID")
        os.setgroups([])
        os.setresgid(args.run_gid, args.run_gid, args.run_gid)
        os.setresuid(args.run_uid, args.run_uid, args.run_uid)
        if os.getuid() != args.run_uid or os.geteuid() != args.run_uid:
            raise SystemExit("failed to drop namespace setup privileges")
    os.umask(0o077)
    harness = Harness(args)
    result = {"verdict": "FAIL", "suite": "stock-client-tailnet-lock-v1.102.0", "scenarios": harness.events}
    try:
        harness.scenario()
        result["verdict"] = "PASS"
        returncode = 0
    except (Failure, OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        result["failure"] = str(exc)
        print("FAIL: " + str(exc), file=sys.stderr)
        returncode = 1
    finally:
        harness.close()
    if args.result:
        args.result.resolve().write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return returncode


if __name__ == "__main__":
    sys.exit(main())
