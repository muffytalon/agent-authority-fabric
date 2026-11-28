"""Step 8's acceptance in Compose (WEEK2_PLAN step 8, §4, C-POSTURE).

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/check.py [--keep]

It builds the images and starts the topology as its own Compose project, `pep-check`, from
empty volumes (`down -v` first), so it never touches a `pep-gate1` stack. Then it checks:
  1. the credentials' owners and modes (§4);
  2. every volume's and socket's owner and mode, as the containers left them (§4);
  3. C-POSTURE, apart from the probe service (step 9). The profile's socket and io_uring
     denials run natively, under the profile, from the glibc image's perl; the int 0x80 and
     x32 routes are checked in the profile's text here, and run for real in step 9's C-NET.
     Also what config/pep's limits need of the PEP's container (RV5);
  4. the step 7 flows: the router's rows, noise going to its own file, reads, payments, a
     step-up approved, declined and timed out, every broker outcome, a wrong credential, a
     refused Call Proof, a restart's replay, and server b over its own network;
  5. that pep-log keeps its records across `docker restart` and `docker kill` of the PEP;
  6. the oracle's join (§2a) over the logs the oracle service mounts.
The step-up timeout waits out the PEP's 45 s. The project is torn down at the end, unless
--keep. One line per check, then a verdict; exits 0 only if every check passed. Tokens never
reach the output.
"""
import base64, hashlib, io, json, os, re, stat, subprocess, sys, tarfile, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT = "pep-check"
COMPOSE_FILES = ["compose.yaml"]   # compose/kit.py adds compose/gate1.yaml
PROFILE = os.path.join(ROOT, "seccomp-unix-only.json")
PROBE_IMAGE = "pep-gate1/tool-a:dev"   # debian:bookworm-slim, whose perl-base is Essential
HARDENED = {"pep", "oracle", "agent", "operator"}   # the AF_UNIX-only profile (§4)
SERVICES = ["pep", "broker", "oracle", "tool-a", "tool-b"]
failures = []


def redact(text):
    return re.sub(r"eyJ[A-Za-z0-9_\-.]+", "<token>", str(text))


def expect(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else ": " + redact(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)
    return ok


def run(args, input=None, check=True, timeout=600):
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    if check and result.returncode != 0:
        raise SystemExit(f"{' '.join(args)} exited {result.returncode}:\n{redact(result.stdout + result.stderr)}")
    return result


def dc(*args, **kwargs):
    files = [arg for name in COMPOSE_FILES for arg in ("-f", name)]
    return run(["docker", "compose", "-p", PROJECT, *files, *args], **kwargs)


def container(service):
    return dc("ps", "-q", service).stdout.strip()


def inspect(name):
    return json.loads(run(["docker", "inspect", name]).stdout)[0]


def fetch(service, path):
    """A file's text from a running service's container (docker cp runs in the daemon)."""
    result = subprocess.run(["docker", "cp", f"{container(service)}:{path}", "-"], capture_output=True, cwd=ROOT)
    if result.returncode != 0:
        return ""
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        member = archive.next()
        return archive.extractfile(member).read().decode()


def lines(service, path):
    # The journal is preallocated, so it ends in NULs.
    return [json.loads(line) for line in fetch(service, path).split("\0", 1)[0].splitlines() if line]


def pointer(value, path):
    for part in path.strip("/").split("/"):
        if isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        elif isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


# --- the operator and the agent, one container each time (E1, RV4 #3) ---

def operator(request):
    out = dc("run", "--rm", "-T", "--no-deps", "operator", "-", input=json.dumps(request), check=False, timeout=120)
    try:
        return json.loads(out.stdout)
    except ValueError:
        return {"transport": out.stderr.strip()}


def agent(method, name=None, params=None, token=""):
    args = ["run", "--rm", "-T", "--no-deps", "agent", method] + ([name] if name else []) + [json.dumps(params or {})]
    out = dc(*args, input=token + "\n", check=False, timeout=120)
    try:
        return json.loads(out.stdout)
    except ValueError:
        return {"transport": out.stderr.strip()}


def call(tool, arguments, token):
    return agent("tools/call", tool, {"name": tool, "arguments": arguments}, token)


def start_episode(intent):
    reply = operator({"call": "start_episode", "intent": intent})
    return pointer(reply, "/result/episode_token"), pointer(reply, "/result/eid"), reply


def code(reply):
    return pointer(reply, "/error/message") or pointer(reply, "/error/data/code") or json.dumps(reply)


def denied(reply):
    return "PEP_DENIED" in json.dumps(reply)


def unavailable(reply):
    return "PEP_UNAVAILABLE" in json.dumps(reply)


def awaiting_approval(deadline_s=20):
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        first = pointer(operator({"call": "pending"}), "/result/approvals/0")
        if first:
            return first
        time.sleep(0.2)
    return None


def raw_status(request):
    """Sends raw bytes to the agent socket as the agent's uid, and returns the status line."""
    script = (
        'use Socket; my $in = do { local $/; <STDIN> }; socket(my $s, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!"; '
        'connect($s, pack_sockaddr_un("/run/pep/agent.sock")) or die "connect: $!"; '
        'syswrite($s, $in) // die "write: $!"; my $line = <$s>; print $line // ""')
    return run(["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--security-opt", f"seccomp={PROFILE}",
                "--user", "20001:20001", "-v", f"{PROJECT}_pep-sock:/run/pep",
                "--entrypoint", "perl", PROBE_IMAGE, "-e", script], input=request).stdout.strip()


def mcp_post(method, body):
    return (f"POST /mcp HTTP/1.1\r\nHost: pep\r\nAccept: application/json, text/event-stream\r\n"
            f"Content-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}")


def tool_b_with_a_wrong_verifier():
    """Recreates tool-b with a verifier no broker credential matches."""
    with tempfile.TemporaryDirectory(prefix="pep-check-") as work:
        verifier = os.path.join(work, "wrong-verifier")
        with open(verifier, "w") as f:
            f.write(hashlib.sha256(b"not the broker's credential").hexdigest())
        os.chmod(verifier, 0o444)
        override = os.path.join(work, "override.yaml")
        with open(override, "w") as f:
            json.dump({"services": {"tool-b": {"volumes": [
                {"type": "bind", "source": verifier, "target": "/run/credential.sha256", "read_only": True}]}}}, f)
        run(["docker", "compose", "-p", PROJECT, "--project-directory", ROOT, "-f", os.path.join(ROOT, "compose.yaml"),
             "-f", override, "up", "-d", "--wait", "--wait-timeout", "120", "--no-deps", "tool-b"])


def publish_a_stranger_key():
    """Overwrites the PEP's published key, as the PEP's uid, with the P-256 generator: a valid
    key the PEP never signs with. The PEP's next boot renames its own key over it."""
    point = bytes.fromhex("04"
                          "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                          "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    encoded = base64.urlsafe_b64encode(point).decode().rstrip("=")
    run(["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", "--user", "20002:20003", "-v", f"{PROJECT}_pep-pub:/p",
         "--entrypoint", "tee", PROBE_IMAGE, "/p/call-proof.pub"], input=encoded + "\n")


def in_background(function, *args):
    box = {}
    thread = threading.Thread(target=lambda: box.update(reply=function(*args)))
    thread.start()
    return thread, box


# --- 1. credentials ---

def check_credentials():
    secrets = os.environ.get("PEP_SECRETS_DIR", "")
    info = os.lstat(secrets)
    expect("secrets directory is private (§4)", stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
           and info.st_mode & 0o077 == 0, f"mode {info.st_mode & 0o7777:o}, owner {info.st_uid}")
    for name, owner in [("broker-credential-a", 20003), ("broker-credential-b", 20003),
                        ("broker-credential-a.sha256", 20005), ("broker-credential-b.sha256", 20008)]:
        info = os.lstat(os.path.join(secrets, name))
        expect(f"{name}: a file owned {owner}:{owner}, mode 0400 (§4)",
               stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_gid == owner
               and info.st_mode & 0o7777 == 0o400,
               f"owner {info.st_uid}:{info.st_gid}, mode {info.st_mode & 0o7777:o}")


# --- 2. volumes ---

# (volume, entry, owner, mode, type): §4's directories, and the sockets bind_safe_listener made.
VOLUME_LAYOUT = [
    ("pep-sock", "", "20002:20001", "2750", "d"),
    ("pep-sock", "agent.sock", "20002:20001", "660", "s"),
    ("pep-sock", "agent.sock.lock", "20002:20001", "600", "f"),
    ("broker-sock", "", "20003:20002", "2750", "d"),
    ("broker-sock", "broker.sock", "20003:20002", "660", "s"),
    ("broker-sock", "broker.sock.lock", "20003:20002", "600", "f"),
    ("pep-ctl", "", "20002:20004", "2750", "d"),
    ("pep-ctl", "ctl.sock", "20002:20004", "660", "s"),
    ("pep-ctl", "ctl.sock.lock", "20002:20004", "600", "f"),
    ("pep-pub", "", "20002:20003", "2750", "d"),
    ("pep-state", "", "20002:20002", "700", "d"),
    ("pep-log", "", "20002:20007", "2750", "d"),
    ("broker-state", "", "20003:20007", "2750", "d"),
    ("tool-a-state", "", "20005:20007", "2750", "d"),
    ("tool-b-state", "", "20008:20007", "2750", "d"),
]
LOGS = [("pep-log", "decisions.jsonl"), ("pep-log", "decisions.jsonl.protocol"), ("broker-state", "broker.jsonl"),
        ("tool-a-state", "tool.jsonl"), ("tool-b-state", "tool.jsonl")]


def volume_listing():
    """Every volume's entries, seen read-only by root with only CAP_DAC_READ_SEARCH."""
    volumes = sorted({volume for volume, *_ in VOLUME_LAYOUT})
    mounts = [arg for volume in volumes for arg in ("-v", f"{PROJECT}_{volume}:/v/{volume}:ro")]
    out = run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--cap-add", "DAC_READ_SEARCH", "--security-opt", "no-new-privileges:true", "--user", "0:0",
               *mounts, "--entrypoint", "find", PROBE_IMAGE, "/v", "-mindepth", "1", "-maxdepth", "2",
               "-printf", "%P|%U:%G|%m|%y\\n"]).stdout
    return {path: (owner, mode, kind) for path, owner, mode, kind in
            (line.split("|") for line in out.splitlines())}


def check_volumes():
    listing = volume_listing()
    for volume, entry, owner, mode, kind in VOLUME_LAYOUT:
        path = f"{volume}/{entry}" if entry else volume
        expect(f"volume {path}: {owner}, {mode}, {kind}", listing.get(path) == (owner, mode, kind), listing.get(path))
    owner, mode, kind = listing.get("pep-pub/call-proof.pub", ("", "0", ""))
    expect("pep-pub/call-proof.pub: the PEP's, readable by the broker's group 20003",
           kind == "f" and owner == "20002:20003" and int(mode, 8) & 0o040 and not int(mode, 8) & 0o022,
           (owner, mode, kind))
    for volume, name in LOGS:
        owner, mode, kind = listing.get(f"{volume}/{name}", ("", "0", ""))
        expect(f"log {volume}/{name}: group 20007 can read it (the oracle)",
               kind == "f" and owner.endswith(":20007") and int(mode, 8) & 0o040, (owner, mode, kind))


# --- 3. posture ---

def status_of(pid):
    fields = {}
    with open(f"/proc/{pid}/status") as status:
        for line in status:
            key, _, value = line.partition(":")
            fields[key] = value.strip()
    return fields


def cgroup_limit(pid, name):
    with open(f"/proc/{pid}/cgroup") as f:
        group = f.read().strip().split(":", 2)[2]
    with open(f"/sys/fs/cgroup{group}/{name}") as f:
        return f.read().strip()


def check_pep_limits():
    """What config/pep's limits need of the PEP's container, recomputed so neither can drift (RV5)."""
    with open(os.path.join(ROOT, "config/pep/config.json")) as f:
        config = json.load(f)
    limits = config["limits"]
    connections, control, episodes = limits["connections"], limits["control_connections"], limits["episodes"]
    info = inspect(container("pep"))
    pid = info["State"]["Pid"]
    expect("pep: a CPU limit is set", info["HostConfig"]["NanoCpus"] > 0, info["HostConfig"]["NanoCpus"])
    with open(f"/proc/{pid}/limits") as f:
        nofile = next(line.split()[3] for line in f if line.startswith("Max open files"))
    fds = 4 * connections + 2 * control + 64 * episodes + 128
    expect(f"pep: nofile {nofile} covers the {fds} its limits need", int(nofile) >= fds, nofile)
    threads = 3 * connections + 65 * episodes
    pids = cgroup_limit(pid, "pids.max")
    expect(f"pep: pids.max {pids} covers about {threads} threads", int(pids) >= threads, pids)
    bytes_needed = (72 * episodes + 2 * connections) << 20
    memory = cgroup_limit(pid, "memory.max")
    expect(f"pep: memory.max {memory} covers about {bytes_needed} bytes", int(memory) >= bytes_needed, memory)
    options = json.loads(run(["docker", "volume", "inspect", f"{PROJECT}_pep-log"]).stdout)[0]["Options"]["o"]
    size = re.search(r"size=(\d+)m", options)
    needed_log = config["log"]["max_bytes"] * 5 // 2
    expect(f"pep-log: its cap holds both logs and their rotations, {needed_log} bytes",
           size is not None and int(size.group(1)) << 20 >= needed_log, options)


def posture(label, name, service, profile):
    info = inspect(name)
    pid = info["State"]["Pid"]
    fields = status_of(pid)
    expect(f"{label}: CapEff 0, CapBnd 0", fields.get("CapEff") == "0" * 16 and fields.get("CapBnd") == "0" * 16,
           f"CapEff {fields.get('CapEff')} CapBnd {fields.get('CapBnd')}")
    expect(f"{label}: NoNewPrivs 1", fields.get("NoNewPrivs") == "1", fields.get("NoNewPrivs"))
    expect(f"{label}: Seccomp 2", fields.get("Seccomp") == "2", fields.get("Seccomp"))
    options = info["HostConfig"]["SecurityOpt"] or []
    seccomp = [option.split("=", 1)[1] for option in options if option.startswith("seccomp=")]
    if service in HARDENED:
        expect(f"{label}: runs the AF_UNIX-only profile", len(seccomp) == 1 and json.loads(seccomp[0]) == profile,
               "a different profile" if seccomp else "Docker's default")
        expect(f"{label}: network_mode none", info["HostConfig"]["NetworkMode"] == "none")
    else:
        expect(f"{label}: runs Docker's default profile (needs inet)", not seccomp, "a custom profile")
    expect(f"{label}: read-only root filesystem", info["HostConfig"]["ReadonlyRootfs"] is True)
    mounts = json.dumps(info["Mounts"]) + json.dumps(info["HostConfig"].get("Binds") or [])
    expect(f"{label}: no docker.sock", "docker.sock" not in mounts)
    return pid, info


def probe_profile(seccomp):
    """Native socket(2) over every family, and io_uring_setup(2), in a container like the agent."""
    script = (
        'my @o; for my $f (0..63) { my $ok = socket(my $s, $f, $f == 1 ? 1 : 2, 0); '
        'push @o, "$f:" . ($ok ? "ok" : ($!+0)); close $s if $ok } '
        '$! = 0; my $r = syscall(425, 1, 0); push @o, "uring:" . ($r == -1 ? ($!+0) : "ok"); print "@o\\n"')
    out = run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", *seccomp, "--user", "20001:20001",
               "--entrypoint", "perl", PROBE_IMAGE, "-e", script]).stdout
    return dict(item.split(":") for item in out.split())


def check_posture():
    with open(PROFILE) as f:
        profile = json.load(f)
    # The profile's text: no socketcall, no compat sub-architectures, no io_uring, and socket(2)
    # only for AF_UNIX, every other family refused with EAFNOSUPPORT (RV3 F10, RV4 #6).
    names = [name for rule in profile["syscalls"] for name in rule["names"]]
    expect("profile: no socketcall rule", "socketcall" not in names)
    x86 = [arch for arch in profile["archMap"] if arch["architecture"] == "SCMP_ARCH_X86_64"]
    expect("profile: x86_64 has no subArchitectures (no int 0x80, no x32)",
           len(x86) == 1 and x86[0].get("subArchitectures") == [], x86)
    allowed = [name for rule in profile["syscalls"] if rule["action"] == "SCMP_ACT_ALLOW" for name in rule["names"]]
    expect("profile: no io_uring syscall allowed", not [name for name in allowed if name.startswith("io_uring")])
    socket_rules = [rule for rule in profile["syscalls"] if "socket" in rule["names"]]
    expect("profile: socket(2) allowed for AF_UNIX only, else EAFNOSUPPORT",
           sorted((rule["action"], json.dumps(rule.get("args") or []), rule.get("errnoRet")) for rule in socket_rules) == sorted([
               ("SCMP_ACT_ALLOW", json.dumps([{"index": 0, "value": 1, "op": "SCMP_CMP_EQ"}]), None),
               ("SCMP_ACT_ERRNO", json.dumps([{"index": 0, "value": 1, "op": "SCMP_CMP_NE"}]), 97)]), socket_rules)
    # The profile in effect: the same probe under Docker's default and under ours.
    default = probe_profile([])
    expect("control: Docker's default profile lets AF_INET through (the probe can tell)", default.get("2") == "ok", default)
    ours = probe_profile(["--security-opt", f"seccomp={PROFILE}"])
    others = {family: result for family, result in ours.items() if family not in ("1", "uring") and result != "97"}
    expect("AF_UNIX-only profile: socket(AF_UNIX) works", ours.get("1") == "ok", ours.get("1"))
    expect("AF_UNIX-only profile: every other family 0..63 gets EAFNOSUPPORT", not others, others)
    expect("AF_UNIX-only profile: io_uring_setup is refused (EPERM, not EFAULT)", ours.get("uring") == "1", ours.get("uring"))
    # Every running container, and an agent and an operator held open on their stdin.
    for service in SERVICES:
        posture(service, container(service), service, profile)
    check_pep_limits()
    held = {}
    for service, args in [("agent", ["tools/list"]), ("operator", ["-"])]:
        name = f"{PROJECT}-{service}-posture"
        run(["docker", "rm", "-f", name], check=False)
        dc("run", "-d", "--no-deps", "--name", name, service, *args)
        held[service] = name
    try:
        time.sleep(1)
        for service, name in held.items():
            expect(f"{service} (held): still running", inspect(name)["State"]["Running"])
            pid, info = posture(f"{service} (held)", name, service, profile)
            if service != "agent":
                continue
            host = info["HostConfig"]
            pids, memory = cgroup_limit(pid, "pids.max"), cgroup_limit(pid, "memory.max")
            expect("agent: pids_limit 256 in effect", host["PidsLimit"] == 256 and pids == "256", (host["PidsLimit"], pids))
            expect("agent: mem_limit 1g in effect", host["Memory"] == 1 << 30 and memory == str(1 << 30), (host["Memory"], memory))
            with open(f"/proc/{pid}/mountinfo") as f:
                tmp = [line.split() for line in f if line.split()[4] == "/tmp"]
            options = set(tmp[0][5].split(",")) if len(tmp) == 1 else set()
            superblock = tmp[0][-1] if len(tmp) == 1 else ""
            expect("agent: a private, size-capped /tmp (tmpfs, 64m, nosuid, nodev, noexec)",
                   len(tmp) == 1 and "tmpfs" in tmp[0] and {"nosuid", "nodev", "noexec"} <= options
                   and "size=65536k" in superblock and "/tmp" not in json.dumps(info["Mounts"]), tmp)
    finally:
        for name in held.values():
            run(["docker", "rm", "-f", name], check=False)


# --- 4. the step 7 flows ---

def journal_results():
    return [record["result"] for record in lines("pep", "/var/lib/pep/journal.jsonl") if "result" in record]


def tool_calls(service, tool):
    return [line for line in lines("oracle", f"/logs/{service}/tool.jsonl") if line.get("tool") == tool]


def check_flows():
    # The router (M1): discovery needs no token; tools/list does.
    discover = agent("server/discover")
    expect("router: server/discover answers 2026-07-28", pointer(discover, "/result/supportedVersions/0") == "2026-07-28", discover)
    expect("router: tools/list without a token is PEP_DENIED", denied(agent("tools/list")))
    expect("router: tools/call without a token is PEP_DENIED",
           denied(agent("tools/call", "get_note", {"name": "get_note", "arguments": {"key": "k"}})))
    noise = fetch("oracle", "/logs/pep/decisions.jsonl.protocol")
    expect("noise: a refusal with no episode goes to its own file (RV5 V5)", "no episode token" in noise, noise[-300:])
    expect("noise: the decision log has none of it", "no episode token" not in fetch("oracle", "/logs/pep/decisions.jsonl"))
    status = raw_status("GET /mcp HTTP/1.1\r\nHost: pep\r\n\r\n")
    expect("router: GET /mcp is 405", status.startswith("HTTP/1.1 405"), status)
    ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}})
    status = raw_status(mcp_post("ping", ping))
    expect("router: ping is 404", status.startswith("HTTP/1.1 404"), status)
    cancelled = json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "x"}})
    status = raw_status(mcp_post("notifications/cancelled", cancelled))
    expect("router: notifications/cancelled is 202", status.startswith("HTTP/1.1 202"), status)

    token, eid, started = start_episode("pay")
    if not expect("operator: start_episode pay", bool(token and eid), started):
        return None
    tools = pointer(agent("tools/list", token=token), "/result/tools") or []
    expect("tools/list: both servers' six pinned tools", sorted(tool.get("name") for tool in tools) ==
           ["fetch", "get_invoice", "get_note", "pay_invoice", "save_note", "search_notes"], tools)

    # A read, and the payment it funds.
    invoice = call("get_invoice", {"invoice_id": "INV-1001"}, token)
    expect("read: get_invoice INV-1001", pointer(invoice, "/result/structuredContent/amount_due_minor") == 30000, invoice)
    paid = call("pay_invoice", {"invoice_id": "INV-1001", "amount": 30000, "currency": "USD"}, token)
    expect("payment: INV-1001 executed", pointer(paid, "/result/structuredContent/status") == "executed", paid)

    # A step-up, approved by the operator.
    call("get_invoice", {"invoice_id": "INV-2002"}, token)
    thread, box = in_background(call, "pay_invoice", {"invoice_id": "INV-2002", "amount": 60000, "currency": "USD"}, token)
    approval = awaiting_approval()
    expect("step-up: INV-2002 awaits approval", approval is not None)
    if approval:
        approved = operator({"call": "approve", "eid": approval["eid"], "rid": approval["rid"],
                             "action_digest": approval["action_digest"], "amount_minor": 60000})
        expect("operator: approve", "result" in approved, approved)
    thread.join()
    expect("step-up: INV-2002 executed after approval",
           pointer(box.get("reply"), "/result/structuredContent/status") == "executed", box.get("reply"))

    # Every broker outcome: declined at the tool, and unknown.
    call("get_invoice", {"invoice_id": "INV-3003"}, token)
    declined = call("pay_invoice", {"invoice_id": "INV-3003", "amount": 30000, "currency": "USD"}, token)
    expect("refused: INV-3003 declined at the tool", pointer(declined, "/result/structuredContent/status") == "declined", declined)
    call("get_invoice", {"invoice_id": "INV-4004"}, token)
    pending = call("pay_invoice", {"invoice_id": "INV-4004", "amount": 30000, "currency": "USD"}, token)
    expect("unknown: INV-4004 is PEP_UNAVAILABLE", unavailable(pending), pending)

    # An operator decline, then a step-up nobody approves: neither sends anything.
    sent = len(tool_calls("tool-a", "pay_invoice"))
    expect("tool-a: pay_invoice reached it four times (INV-1001 to INV-4004)", sent == 4, sent)
    call("get_invoice", {"invoice_id": "INV-5005"}, token)
    thread, box = in_background(call, "pay_invoice", {"invoice_id": "INV-5005", "amount": 60000, "currency": "USD"}, token)
    approval = awaiting_approval()
    if approval:
        refused = operator({"call": "decline", "eid": approval["eid"], "rid": approval["rid"],
                            "action_digest": approval["action_digest"], "amount_minor": 60000})
        expect("operator: decline", "result" in refused, refused)
    thread.join()
    expect("decline: INV-5005 is PEP_DENIED", denied(box.get("reply")), box.get("reply"))
    began = time.time()
    timed_out = call("pay_invoice", {"invoice_id": "INV-5005", "amount": 60000, "currency": "USD"}, token)
    expect(f"step-up timeout: INV-5005 is PEP_DENIED after {time.time() - began:.0f} s", denied(timed_out), timed_out)
    executions = tool_calls("tool-a", "pay_invoice")
    expect("tool-a: the decline and the timeout sent it nothing", len(executions) == sent, len(executions))
    expect("tool-a: two executed", sum(1 for line in executions if line.get("executed") is True) == 2, executions)
    results = journal_results()
    expect("journal: executed, executed, declined, unknown, released, released",
           results == ["executed", "executed", "declined", "unknown", "released", "released"], results)

    # Server b, over its own network and credential.
    notes, notes_eid, started = start_episode("notes")
    expect("operator: start_episode notes (a second intent, live beside pay)", bool(notes), started)
    saved = call("save_note", {"key": "k1", "text": "hello from compose"}, notes)
    expect("server b: save_note", "result" in saved and not pointer(saved, "/result/isError"), saved)
    note = call("get_note", {"key": "k1"}, notes)
    expect("server b: get_note reads it back", "hello from compose" in json.dumps(note), note)

    # A credential the tool server refuses executes nothing (C-CRED), and only suspends it.
    logged = len(lines("oracle", "/logs/tool-b/tool.jsonl"))
    tool_b_with_a_wrong_verifier()
    refused = call("save_note", {"key": "k2", "text": "must not execute"}, notes)
    expect("wrong credential: refused", denied(refused) or unavailable(refused), refused)
    expect("wrong credential: tool-b executed nothing", len(lines("oracle", "/logs/tool-b/tool.jsonl")) == logged)
    dc("up", "-d", "--wait", "--wait-timeout", "120", "--no-deps", "tool-b")
    deadline, reply = time.time() + 20, {}
    while time.time() < deadline:     # the next drift poll sets it serving again
        reply = call("get_note", {"key": "k1"}, notes)
        if "result" in reply:
            break
        time.sleep(1)
    expect("wrong credential: server b serves again with its own verifier", "result" in reply, reply)
    expect("operator: end_episode notes", "result" in operator({"call": "end_episode", "eid": notes_eid}))
    return token


def check_restart(old_token):
    # pep-log outlives the PEP's container because the oracle holds it (RV4 #10).
    before = fetch("oracle", "/logs/pep/decisions.jsonl")
    dc("restart", "pep")
    dc("up", "-d", "--wait", "--wait-timeout", "120", "--no-deps", "pep")
    after = fetch("oracle", "/logs/pep/decisions.jsonl")
    expect("pep-log: keeps its records across docker restart", before and after.startswith(before),
           f"{len(before)} then {len(after)} bytes")
    replayed = [line for line in dc("logs", "--no-color", "pep").stdout.splitlines() if "journal replayed" in line]
    expect("restart: the journal replays 1 unresolved entity", bool(replayed) and "1 unresolved entities" in replayed[-1],
           replayed[-1:] or "no replay line")
    if old_token:
        expect("restart: the old token is void (keys are per boot)",
               denied(call("get_invoice", {"invoice_id": "INV-1001"}, old_token)))
    token, eid, started = start_episode("pay")
    expect("restart: a new pay episode starts", bool(token), started)
    call("get_invoice", {"invoice_id": "INV-1001"}, token)
    expect("restart: INV-1001, paid, cannot be paid again",
           denied(call("pay_invoice", {"invoice_id": "INV-1001", "amount": 30000, "currency": "USD"}, token)))
    call("get_invoice", {"invoice_id": "INV-4004"}, token)
    expect("restart: INV-4004, unresolved, cannot be paid again",
           denied(call("pay_invoice", {"invoice_id": "INV-4004", "amount": 30000, "currency": "USD"}, token)))
    expect("restart: still two executed payments",
           sum(1 for line in tool_calls("tool-a", "pay_invoice") if line.get("executed") is True) == 2)

    # A Call Proof the broker refuses: never sent, so refused and released (P1).
    call("get_invoice", {"invoice_id": "INV-3003"}, token)
    sent = len(tool_calls("tool-a", "pay_invoice"))
    publish_a_stranger_key()
    reply = call("pay_invoice", {"invoice_id": "INV-3003", "amount": 30000, "currency": "USD"}, token)
    expect("refused proof: PEP_UNAVAILABLE", unavailable(reply), reply)
    expect("refused proof: the tool never ran", len(tool_calls("tool-a", "pay_invoice")) == sent)
    reasons = [line.get("reason") for line in lines("oracle", "/logs/broker/broker.jsonl")]
    expect("refused proof: the broker logged it", "call proof refused" in reasons, reasons[-3:])
    results = journal_results()
    expect("refused proof: the journal ends refused", results[-1:] == ["refused"], results[-3:])

    before = fetch("oracle", "/logs/pep/decisions.jsonl")
    run(["docker", "kill", container("pep")])
    dc("up", "-d", "--wait", "--wait-timeout", "120", "--no-deps", "pep")
    after = fetch("oracle", "/logs/pep/decisions.jsonl")
    expect("pep-log: keeps its records across docker kill", before and after.startswith(before),
           f"{len(before)} then {len(after)} bytes")
    token, _, started = start_episode("pay")
    invoice = call("get_invoice", {"invoice_id": "INV-1001"}, token)
    expect("restart: the new boot's key is published and accepted",
           pointer(invoice, "/result/structuredContent/amount_due_minor") == 30000, invoice or started)


# --- 6. the oracle's join (§2a) ---

def check_join():
    decisions = lines("oracle", "/logs/pep/decisions.jsonl")
    broker = lines("oracle", "/logs/broker/broker.jsonl")
    joined, problems = 0, []
    for service in ["tool-a", "tool-b"]:
        for execution in lines("oracle", f"/logs/{service}/tool.jsonl"):
            upstream_id = execution.get("upstream_id")
            hop = next((line for line in broker if line.get("upstream_id") == upstream_id), None)
            allow = hop and next((line for line in decisions if line.get("verdict") == "allow"
                                  and line.get("jti") == hop.get("jti")), None)
            if not allow:
                problems.append(f"{service} {upstream_id}: no broker hop or allow")
                continue
            if hop.get("verdict") != "forwarding":
                problems.append(f"{service} {upstream_id}: the broker's first line came after the upstream write")
            if (allow.get("upstream_id"), allow.get("action_digest"), allow.get("idempotency_key")) != (
                    upstream_id, execution.get("action_digest"), execution.get("idempotency_key")):
                problems.append(f"{service} {upstream_id}: the allow disagrees")
            if not any(line.get("outcome") and line.get("upstream_id") == upstream_id for line in decisions):
                problems.append(f"{service} {upstream_id}: no outcome record")
            joined += 1
    expect(f"oracle join: every execution ({joined}) joins to an allow and an outcome", joined > 0 and not problems, problems)
    for name in ["decisions.jsonl", "decisions.jsonl.protocol"]:
        expect(f"{name}: no token or proof", "eyJ" not in fetch("oracle", f"/logs/pep/{name}"))


def main():
    keep = "--keep" in sys.argv[1:]
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    check_credentials()
    dc("--profile", "run", "build")
    dc("down", "-v", "--remove-orphans")
    try:
        dc("up", "-d", "--wait", "--wait-timeout", "120")
        print("ok   topology: every service healthy", flush=True)
        time.sleep(1.1)   # the broker refuses proofs from its boot second (R1)
        check_volumes()
        check_posture()
        token = check_flows()
        check_restart(token)
        check_join()
    finally:
        if not keep:
            dc("down", "-v", "--remove-orphans", check=False)
    print(f"STEP 8 CHECKS {'PASSED' if not failures else f'FAILED ({len(failures)})'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
