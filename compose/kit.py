"""The Gate 1 kit (WEEK2_PLAN step 9, §3): G1's attacks, and G3's replays, in Compose.

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/kit.py [--keep] [--only TEXT]

It runs as its own Compose project, `pep-kit`, from empty volumes, with compose/gate1.yaml over
compose.yaml: the kit's fixtures and short deadlines (config/kit), a broker that captures proofs,
and the test-only `probe` and `injector`.

Every test declares what it expects before it runs (§2a): `deny`, nothing may reach a tool, or
`allow:N`, exactly N executions. Tests run one at a time. Each takes the oracle's mark after its
setup, makes its attempt, waits for every leg it started to end, and the oracle judges the window.
A test holds only if its attempt failed as it should and the oracle found nothing.

A denial alone proves little, because a broken fixture is denied too. So a test can name the
guard that must refuse it, and it fails if that guard's reason is not in the decision log.

The controls run first. A sandbox that blocks nothing because the probe is broken, or an oracle
that reads the wrong files, would otherwise look exactly like a clean result. `--only` runs the
tests whose name holds TEXT. Exits 0 only if everything held. Tokens never reach the output.
"""
import base64, json, os, re, subprocess, sys, time

import check
from check import dc, expect, fetch, in_background, journal_results, lines, pointer, run

check.PROJECT = "pep-kit"
check.COMPOSE_FILES = ["compose.yaml", "compose/gate1.yaml"]

PROFILES = ("--profile", "run", "--profile", "gate1")
BIN = "/usr/local/bin"
SOCKET = "/run/pep/agent.sock"
LOCK = SOCKET + ".lock"
CONTROL = "/run/pep-ctl/ctl.sock"
BROKER_SOCKET = "/run/broker/broker.sock"
DECISIONS = "/logs/pep/decisions.jsonl"
NOISE = DECISIONS + ".protocol"
BROKER_LOG = "/logs/broker/broker.jsonl"
PROOFS = "/logs/broker/proofs.jsonl"
PROOF_KEY = "dev.pep-sidecar/call-proof"
EPISODE_KEY = "dev.pep-sidecar/episode"
OUTCOME_KEY = "dev.pep-sidecar/outcome"
PROBE_IMAGE = "pep-gate1/probe:dev"
PROFILE = os.path.join(check.ROOT, "seccomp-unix-only.json")
AGENT_USER = "20001:20001"
LEGS_END_WITHIN_S = 6     # limits.upstream_timeout_ms in config/kit, and the tool's delay
IDLE_S = 12               # limits.episode_idle_ms in config/kit
LIFETIME_S = 25           # limits.episode_lifetime_ms in config/kit
PROOF_LIFETIME_S = 60     # T1: exp - iat
CLOCK_SKEW_S = 2
SIGSYS = "signal:31"
EACCES, ENOENT, EPERM, ESRCH = "13", "2", "1", "3"
EAFNOSUPPORT = "97"
AF_UNIX, AF_INET, AF_PACKET = 1, 2, 17
SOCK_STREAM, SOCK_RAW = 1, 3
SWEEP_ROWS = 4 * 64 * 3   # routes × families × types in net-probe.c
P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
PER_CLASS = 46            # G3: 22 classes in Compose, so at least 1,012 attempts
PLANNED_ATTACKS = 61      # §3


with open(os.path.join(check.ROOT, "config/kit/pep/config.json")) as config_file:
    _ids = json.load(config_file)["intents"]["pay"]["entities"]["ids"]
PLAIN = iter(i for i in _ids if i.startswith("INV-K"))
DECLINED = iter(i for i in _ids if i.startswith("INV-D"))
PENDING = iter(i for i in _ids if i.startswith("INV-U"))
SLOW = iter(i for i in _ids if i.startswith("INV-S"))
SMALL = iter(i for i in _ids if i.startswith("INV-M"))
SECRET_INTENTS = iter(f"secret-{n}" for n in range(1, 9))


# --- the oracle ---

def oracle(*args):
    return run(["docker", "exec", check.container("oracle"), f"{BIN}/stub-oracle", *args], check=False, timeout=60)


def mark():
    out = oracle("mark")
    if out.returncode != 0:
        raise SystemExit(f"the oracle cannot mark: {out.stderr.strip()}")
    return out.stdout.strip()


def judged(offsets, expected, wait=True):
    """The oracle's verdict, once every leg the test started has ended (§2a's window)."""
    deadline = time.time() + LEGS_END_WITHIN_S
    while True:
        out = oracle("judge", offsets, expected)
        if out.returncode == 2:
            raise SystemExit(f"the oracle cannot read the logs: {out.stderr.strip()}")
        verdict = json.loads(out.stdout)
        if not wait or verdict["open_legs"] == 0 or time.time() >= deadline:
            return verdict
        time.sleep(0.2)


def since(path, offset):
    return fetch("oracle", path).encode()[offset:].decode(errors="replace")


# --- agents ---

def raw_request(method, params=None, token=None, name=None, request_id=1, headers=(), meta=None):
    """The wire bytes of one MCP request, with what a pinned SDK sends (`stub-agent`, D2)."""
    body_meta = {"io.modelcontextprotocol/clientCapabilities": {},
                 "io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    if token is not None:
        body_meta[EPISODE_KEY] = token
    body_meta.update(meta or {})
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method,
                       "params": dict(params or {}, _meta=body_meta)}, separators=(",", ":"))
    head = ["POST /mcp HTTP/1.1", "Host: pep.local", "Accept: application/json, text/event-stream",
            "Content-Type: application/json", "MCP-Protocol-Version: 2026-07-28", f"Mcp-Method: {method}"]
    if name:
        head.append(f"Mcp-Name: {name}")
    if token is not None:
        head.append(f"Pep-Episode: {token}")
    head += list(headers)
    head += [f"Content-Length: {len(body.encode())}", "Connection: close", "", ""]
    return "\r\n".join(head) + body


def call_request(tool, arguments, token, **options):
    return raw_request("tools/call", {"name": tool, "arguments": arguments}, token, tool, **options)


def park(name, user, *mount):
    """A parked test container with the agent's posture (compose/gate1.yaml's `probe`). Each call
    into it is an exec, which takes a fraction of a new container's time."""
    run(["docker", "run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", "--security-opt", f"seccomp={PROFILE}", "--user", user,
         "--tmpfs", "/tmp:size=64m,mode=1777,nosuid,nodev,noexec", *mount,
         "--entrypoint", f"{BIN}/net-probe", PROBE_IMAGE, "park"], timeout=60)


def operator(request):
    """The scripted operator (H1), as uid 20004, from a parked container."""
    name = f"{check.PROJECT}-agent-operator"
    if run(["docker", "inspect", name], check=False).returncode != 0:
        park(name, "20004:20004", "-v", f"{network('pep-ctl')}:/run/pep-ctl")
    out = run(["docker", "exec", "-i", name, f"{BIN}/stub-operator", CONTROL, "-"],
              input=json.dumps(request), check=False, timeout=120)
    try:
        return json.loads(out.stdout)
    except ValueError:
        return {"transport": out.stderr.strip()}


class Agent:
    """One agent container, with its episode if it has an intent (E1: one container per episode,
    RV4 #3)."""
    serial = 0

    def __init__(self, intent=None, user=AGENT_USER, mounts=()):
        Agent.serial += 1
        self.name = f"{check.PROJECT}-agent-{Agent.serial}"
        self.token, self.eid = None, None
        if intent:
            deadline = time.time() + 20
            while True:   # an ended episode's intent frees once its last leg has ended (E1)
                reply = operator({"call": "start_episode", "intent": intent})
                self.token = pointer(reply, "/result/episode_token")
                self.eid = pointer(reply, "/result/eid")
                if self.token or time.time() >= deadline:
                    break
                time.sleep(0.3)
            if not self.token:
                raise SystemExit(f"no episode of {intent}: {check.redact(reply)}")
        park(self.name, user, "-v", f"{network('pep-sock')}:/run/pep", *mounts)

    def execute(self, *args, stdin=None):
        return run(["docker", "exec", "-i", self.name, *args], input=stdin, check=False, timeout=60)

    def call(self, tool, arguments):
        out = self.execute(f"{BIN}/stub-agent", SOCKET, "tools/call", tool,
                           json.dumps({"name": tool, "arguments": arguments}), stdin=self.token + "\n")
        try:
            return json.loads(out.stdout)
        except ValueError:
            return {"transport": out.stderr.strip()}

    def list_tools(self):
        out = self.execute(f"{BIN}/stub-agent", SOCKET, "tools/list", stdin=self.token + "\n")
        return json.loads(out.stdout)

    def lookup(self, invoice):
        return self.call("get_invoice", {"invoice_id": invoice})

    def pay(self, invoice, amount=1000, **extra):
        return self.call("pay_invoice", dict({"invoice_id": invoice, "amount": amount, "currency": "USD"}, **extra))

    def probe(self, *args):
        return self.execute(f"{BIN}/net-probe", *args).stdout.strip()

    def send(self, items):
        """Raw requests through `stub-injector pep`: the kinds of reply, then their counts."""
        stdin = "".join(json.dumps(item) + "\n" for item in items)
        out = self.execute(f"{BIN}/stub-injector", "pep", SOCKET, "-", stdin=stdin)
        rows = [json.loads(line) for line in out.stdout.splitlines()]
        return [row["reply"] for row in rows[:-1]], rows[-1] if rows else {}

    def end(self):
        if self.eid:
            operator({"call": "end_episode", "eid": self.eid})
            self.eid = None

    def close(self):
        self.end()
        run(["docker", "rm", "-f", self.name], check=False)


def denied(reply):
    return "PEP_DENIED" in json.dumps(reply)


def unavailable(reply):
    return "PEP_UNAVAILABLE" in json.dumps(reply)


def status(reply):
    return pointer(reply, "/result/structuredContent/status")


def docker_probe(*args, flags=()):
    """net-probe in a throwaway container with the agent's flags, apart from `flags`."""
    out = run(["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--user", AGENT_USER, *flags, "--entrypoint", f"{BIN}/net-probe", PROBE_IMAGE, *args], check=False, timeout=120)
    return out.stdout.strip()


def network(name):
    return f"{check.PROJECT}_{name}"


def tool_address(service, net):
    info = check.inspect(check.container(service))
    return info["NetworkSettings"]["Networks"][network(net)]["IPAddress"]


def restart_pep():
    run(["docker", "kill", check.container("pep")])
    dc("up", "-d", "--wait", "--wait-timeout", "120", "--no-deps", "pep")


# --- how a test runs ---

class Window:
    """One test: its agents, and the mark its window starts at."""

    def __init__(self):
        self.agents = []
        self.begin()

    def begin(self):
        self.offsets = mark()
        self.decisions_at = len(fetch("oracle", DECISIONS).encode())
        self.noise_at = len(fetch("oracle", NOISE).encode())
        self.expected_now = None

    def agent(self, intent=None):
        agent = Agent(intent)
        self.agents.append(agent)
        return agent

    def reasons(self):
        return since(DECISIONS, self.decisions_at) + since(NOISE, self.noise_at)

    def close(self):
        for agent in self.agents:
            agent.close()


ATTACKS = []
tally = {"held": 0, "failed": 0, "attacks": 0}


def attack(category, title, expected="deny", reason=None, leg_may_stay_open=False):
    def register(function):
        ATTACKS.append(dict(category=category, title=title, expected=expected, reason=reason,
                            open_ok=leg_may_stay_open, function=function))
        return function
    return register


def run_test(name, expected, reason, open_ok, function):
    window = Window()
    problems = []
    try:
        result = function(window)
        expected = window.expected_now or expected
        verdict = judged(window.offsets, expected, wait=not open_ok)
        follow_up = result() if callable(result) else result
        if follow_up:
            problems.append(f"attempt: {follow_up}")
        problems += [f"oracle: {finding}" for finding in verdict["findings"]]
        if verdict["open_legs"] and not open_ok:
            problems.append(f"{verdict['open_legs']} legs never ended")
        if reason:
            names = (reason,) if isinstance(reason, str) else reason
            logged = window.reasons()
            if not any(name in logged for name in names):
                problems.append(f"not refused for {names}: {sorted(set(re.findall(r'reason.:.([^,]{1,60})', logged)))[:4]}")
    finally:
        window.close()
    held = expect(f"{name} [{expected}]", not problems, "; ".join(problems))
    tally["held" if held else "failed"] += 1
    return held


# --- the controls: can each instrument tell? ---

def sweep(*flags, service=True):
    """net-probe's sweep as {(route, family, type): result}."""
    if service:
        out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "--user", AGENT_USER,
                 "--entrypoint", f"{BIN}/net-probe", "probe", "sweep", check=False, timeout=300).stdout
    else:
        out = docker_probe("sweep", flags=("--network", "none", *flags))
    rows = {}
    for line in out.splitlines():
        route, family, kind, result = line.split()
        rows[route, int(family), int(kind)] = result
    return rows


def judge_sweep(rows):
    """What is wrong with a sweep's rows, or None for AF_UNIX-only on every route."""
    if len(rows) != SWEEP_ROWS:
        return f"{len(rows)} rows of {SWEEP_ROWS}: the probe was cut short"
    made = [key for key, result in rows.items() if result == "ok" and not (key[0] == "native" and key[1] == AF_UNIX)]
    if made:
        return f"sockets made: {made[:8]}"
    if rows["native", AF_UNIX, SOCK_STREAM] != "ok":
        return "AF_UNIX failed natively, so the sweep ran broken"
    survived = [key for key, result in rows.items() if key[0] != "native" and result != SIGSYS]
    if survived:
        return f"a compat route was not killed: {[(key, rows[key]) for key in survived[:8]]}"
    other = {result for key, result in rows.items() if key[0] == "native" and key[1] != AF_UNIX}
    if other != {EAFNOSUPPORT}:
        return f"native families other than AF_UNIX gave {sorted(other)}, not only EAFNOSUPPORT"


def controls():
    """Each instrument must be able to see what it is there to see."""
    rows = sweep(service=False)
    expect("control: net-probe made every attempt", len(rows) == SWEEP_ROWS, len(rows))
    made = rows.get(("native", AF_INET, SOCK_STREAM))
    expect("control: Docker's default profile lets AF_INET through natively", made == "ok", made)
    # Whether a kernel has the compat ABIs is its own business: the profile must refuse them
    # either way. Recorded, because here they are real routes (RV4 #6).
    for route in ["int80", "socketcall", "x32"]:
        print(f"note control: {route} AF_INET under Docker's default profile: {rows.get((route, AF_INET, SOCK_STREAM))}", flush=True)
    expect("control: the sweep's judge flags Docker's default profile", judge_sweep(rows) is not None)
    reachable = docker_probe("connect", tool_address("tool-a", "tools_a"), "8080", "tcp",
                             flags=("--network", network("tools_a")))
    expect("control: net-probe's connect works where there is a network", reachable == "ok", reachable)

    good = {}

    def real_read(window):
        agent = window.agent("pay")
        good["agent"] = agent
        window.begin()
        reply = agent.lookup(next(PLAIN))
        if pointer(reply, "/result/structuredContent/amount_due_minor") != 1000:
            return f"the read failed: {reply}"
    if not run_test("control: the oracle sees a real read and joins it", "allow:1", None, False, real_read):
        return False

    def rightful_peer(window):
        agent = window.agent("notes")
        window.begin()
        params = {"name": "get_note", "arguments": {"key": "k"}}
        out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "--user", AGENT_USER, "probe", "tools/call",
                 "get_note", json.dumps(params), input=agent.token + "\n", check=False, timeout=120)
        if out.returncode != 0:
            return f"the rightful peer was refused: {out.stdout.strip() or out.stderr.strip()}"
    return run_test("control: the probe image is served from the agent's uid and gid", "allow:1", None, False, rightful_peer)


# --- C-UID: each probe passes the socket's mode by its group, holding a live token ---

def stolen_token(user, refusal):
    def attempt(window):
        agent = window.agent("notes")
        window.begin()
        params = {"name": "get_note", "arguments": {"key": "k"}}
        out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "--user", user, "probe", "tools/call", "get_note",
                 json.dumps(params), input=agent.token + "\n", check=False, timeout=120)
        if out.stdout.strip():
            return f"the PEP answered: {out.stdout.strip()}"
    return attempt


for _name, _user, _refusal in [
        ("wrong uid", "20009:20001", "peer uid 20009 is not the expected uid 20001"),
        ("root", "0:20001", "peer uid 0 is not the expected uid 20001"),
        ("overflow uid", "65534:20001", "peer uid 65534 is not the expected uid 20001"),
        ("uid right, gid wrong", "20001:20009", "peer gid 20009 is not the expected gid 20001")]:
    # Reaching accept() is the point of the group: a probe stopped by the socket's mode would
    # prove nothing about require_peer, so the refusal itself is required in the log.
    attack("C-UID", f"{_name} ({_user}) with a stolen live token", reason=_refusal)(stolen_token(_user, _refusal))


# --- C-LOCK ---

@attack("C-LOCK", "the agent cannot open the lock file")
def lock_open(window):
    agent = window.agent()
    if agent.probe("stat", LOCK) != "ok":
        return "the lock file is not where the attack looks"
    got = agent.probe("read", LOCK)
    if got != f"open:{EACCES}":
        return f"open gave {got}"


@attack("C-LOCK", "the agent cannot create or replace an entry in /run/pep")
def lock_plant(window):
    agent = window.agent()
    attempts = {
        "plant a file": agent.probe("open", "/run/pep/planted", "c"),
        "plant a symlink": agent.probe("symlink", "/etc/passwd", "/run/pep/agent.sock.old"),
        "unlink the socket": agent.probe("unlink", SOCKET),
        "unlink the lock": agent.probe("unlink", LOCK),
        "rename the socket": agent.probe("rename", SOCKET, "/run/pep/moved"),
    }
    wrong = {name: got for name, got in attempts.items() if got != EACCES}
    if wrong:
        return f"{wrong}"


# --- C-NET: two layers, the AF_UNIX-only profile and the empty network namespace ---

def blocked_twice(agent, address, port, proto):
    """The agent's own container stops it at socket(2). Without that profile, on `none`, it still
    gets nowhere, so neither layer rests on the other."""
    first = agent.probe("connect", address, str(port), proto)
    if first != f"socket:{EAFNOSUPPORT}":
        return f"{address}:{port}/{proto} under the profile gave {first}"
    second = docker_probe("connect", address, str(port), proto, flags=("--network", "none"))
    if second == "ok" or not second:
        return f"{address}:{port}/{proto} on network none gave {second!r}"


@attack("C-NET", "no route out")
def net_route(window):
    agent = window.agent()
    routes = agent.probe("cat", "/proc/net/route").splitlines()[1:]
    return f"routes: {routes}" if routes else blocked_twice(agent, "9.9.9.9", 80, "tcp")


@attack("C-NET", "no DNS")
def net_dns(window):
    agent = window.agent()
    servers = re.findall(r"^nameserver\s+(\S+)", agent.probe("cat", "/etc/resolv.conf"), re.M)
    for server in servers + ["1.0.0.1"]:
        if server.startswith("127."):
            got = agent.probe("connect", server, "53", "udp")
            if got != f"socket:{EAFNOSUPPORT}":
                return f"{server} gave {got}"
            continue
        problem = blocked_twice(agent, server, 53, "udp")
        if problem:
            return problem


@attack("C-NET", "no way into the tool networks")
def net_tools(window):
    agent = window.agent()
    for service, net in [("tool-a", "tools_a"), ("tool-b", "tools_b"), ("broker", "tools_a")]:
        problem = blocked_twice(agent, tool_address(service, net), 8080, "tcp")
        if problem:
            return f"{service}: {problem}"


@attack("C-NET", "no IPv6")
def net_ipv6(window):
    agent = window.agent()
    interfaces = [line for line in agent.probe("cat", "/proc/net/if_inet6").splitlines() if not line.rstrip().endswith("lo")]
    if interfaces and "open:" not in interfaces[0]:
        return f"interfaces: {interfaces}"
    return blocked_twice(agent, "2606:4700:4700::1111", 443, "tcp")


@attack("C-NET", "raw and packet sockets fail")
def net_raw(window):
    agent = window.agent()
    got = {"AF_INET raw": agent.probe("socket", str(AF_INET), str(SOCK_RAW)),
           "AF_PACKET raw": agent.probe("socket", str(AF_PACKET), str(SOCK_RAW))}
    if set(got.values()) != {EAFNOSUPPORT}:
        return f"{got}"


@attack("C-NET", "UDP/53 fails")
def net_udp(window):
    return blocked_twice(window.agent(), "8.8.8.8", 53, "udp")


@attack("C-NET", "DoH, TCP/443 to a resolver, fails")
def net_doh(window):
    return blocked_twice(window.agent(), "1.1.1.1", 443, "tcp")


@attack("C-NET", "no socket but AF_UNIX: native, int 0x80, socketcall, x32")
def net_sweep(window):
    return judge_sweep(sweep())


# --- C-PROC ---

def shared_pid_probe(*args):
    """The harder case than Compose's: the PEP's own PID namespace, as the agent's uid."""
    return docker_probe(*args, flags=("--network", "none", "--pid", f"container:{check.container('pep')}",
                                      "--security-opt", f"seccomp={PROFILE}"))


@attack("C-PROC", "ptrace of the PEP fails")
def proc_ptrace(window):
    agent = window.agent()
    host_pid = check.inspect(check.container("pep"))["State"]["Pid"]
    if str(host_pid) in agent.probe("pids").split():
        return "the PEP's pid is visible from the agent"
    got = agent.probe("ptrace", str(host_pid))
    if got != ESRCH:
        return f"from the agent's namespace: {got}"
    shared = shared_pid_probe("ptrace", "1")
    if shared != EPERM:
        return f"from the PEP's own namespace: {shared}"


@attack("C-PROC", "/proc/<pep>/mem is unreadable")
def proc_mem(window):
    if shared_pid_probe("stat", "/proc/1") != "ok":
        return "the shared namespace does not show the PEP"
    got = shared_pid_probe("read", "/proc/1/mem")
    if got != f"open:{EACCES}":
        return f"read gave {got}"


@attack("C-PROC", "the PEP's argv and env hold no key or credential")
def proc_args(window):
    info = check.inspect(check.container("pep"))
    with open(f"/proc/{info['State']['Pid']}/cmdline", "rb") as f:
        argv = f.read().decode(errors="replace").replace("\0", " ")
    environment = " ".join(info["Config"].get("Env") or [])
    for text in (argv, environment):
        if re.search(r"eyJ|BEGIN|credential|secret|[A-Za-z0-9+/_-]{40,}", text):
            return f"found in {text[:120]}"
    if "pep-sidecar" not in argv:
        return f"argv was not the PEP's: {argv[:80]}"


# --- C-FWD: what reached the tool (tool-a records every tools/call) ---

def recorded():
    return lines("oracle", "/logs/tool-a/requests.jsonl")


@attack("C-FWD", "no agent header reaches upstream", expected="allow:1")
def fwd_headers(window):
    agent = window.agent("notes")
    invoice = next(PLAIN)
    window.begin()
    kinds, _ = agent.send([{"request": call_request("get_invoice", {"invoice_id": invoice}, agent.token, headers=[
        "Authorization: Bearer agent-chosen", "Idempotency-Key: agent-chosen", "X-Agent: agent-chosen",
        "Traceparent: agent-chosen"])}])
    if kinds != ["accepted"]:
        return f"the call was {kinds}"

    def after():
        last = recorded()[-1]
        names = {name.lower() for name, _ in last["headers"]}
        if "agent-chosen" in json.dumps(last):
            return f"an agent value arrived: {sorted(names)}"
        if names & {"x-agent", "traceparent", "pep-episode", "idempotency-key"}:
            return f"an agent header arrived: {sorted(names)}"
    return after


@attack("C-FWD", "upstream _meta holds only PEP-built keys", expected="allow:1")
def fwd_meta(window):
    agent = window.agent("notes")
    invoice = next(PLAIN)
    window.begin()
    kinds, _ = agent.send([{"request": call_request("get_invoice", {"invoice_id": invoice}, agent.token, meta={
        "traceparent": "agent-chosen", "logLevel": "debug", "progressToken": "agent-chosen", "x.example/unknown": "agent-chosen"})}])
    if kinds != ["accepted"]:
        return f"the call was {kinds}"

    def after():
        body = json.loads(recorded()[-1]["body"])
        meta = body["params"].get("_meta", {})
        extra = set(meta) - {"io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientCapabilities",
                             "io.modelcontextprotocol/clientInfo"}
        if extra:
            return f"upstream _meta also holds {sorted(extra)}"
        if "agent-chosen" in json.dumps(body) or "eyJ" in json.dumps(body):
            return "an agent value or a token arrived"
    return after


@attack("C-FWD", "the upstream id is PEP-assigned", expected="allow:1")
def fwd_id(window):
    agent = window.agent("notes")
    invoice = next(PLAIN)
    window.begin()
    kinds, _ = agent.send([{"request": call_request("get_invoice", {"invoice_id": invoice}, agent.token, request_id="agent-chosen")}])
    if kinds != ["accepted"]:
        return f"the call was {kinds}"

    def after():
        upstream_id = json.loads(recorded()[-1]["body"])["id"]
        if not re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", str(upstream_id)):
            return f"the upstream id is {upstream_id!r}"
    return after


# --- C-RES: what a tool server answers cannot settle a payment ---

@attack("C-RES", "an outcome forged by the tool server is stripped and never trusted", expected="allow:0")
def res_forged(window):
    agent = window.agent("pay")
    agent.lookup("INV-R-FORGED")
    window.begin()
    reply = agent.pay("INV-R-FORGED")
    if OUTCOME_KEY in json.dumps(reply):
        return "the agent saw the reserved member"
    return journal_after("declined")


def res_unknown(invoice):
    def attempt(window):
        agent = window.agent("pay")
        agent.lookup(invoice)
        window.begin()
        reply = agent.pay(invoice)
        if not unavailable(reply):
            return f"the agent got {reply}"
        return journal_after("unknown")
    return attempt


attack("C-RES", "a response id mismatch settles nothing", expected="allow:1")(res_unknown("INV-R-WRONG-ID"))
attack("C-RES", "two responses in one body settle nothing", expected="allow:1")(res_unknown("INV-R-TWO"))


# --- C-EPI ---

def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def with_header_member(token):
    header, payload, signature = token.split(".")
    extended = json.loads(unb64(header))
    extended["jku"] = "https://attacker.example/keys"
    return f"{b64(json.dumps(extended).encode())}.{payload}.{signature}"


def forged_signature(token):
    head, _ = token.rsplit(".", 1)
    return f"{head}.{b64(bytes(64))}"


def trailing_bits(token):
    """The same 64 signature bytes, with a non-zero value in the unused bits of the last symbol."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return token[:-1] + alphabet[alphabet.index(token[-1]) ^ 1]


def high_s(token):
    head, signature = token.rsplit(".", 1)
    raw = unb64(signature)
    s = int.from_bytes(raw[32:], "big")
    return f"{head}.{b64(raw[:32] + (P256_ORDER - s).to_bytes(32, 'big'))}"


def standard_alphabet(token):
    return token.replace("-", "+").replace("_", "/")


def captured_proof():
    captured = lines("oracle", PROOFS)
    return json.loads(captured[-1]["body"])["params"]["_meta"][PROOF_KEY] if captured else None


def token_refused(mutate, reason="episode token refused"):
    def attempt(window):
        agent = window.agent("notes")
        served = agent.call("get_note", {"key": "k"})
        if "result" not in served:
            return f"the live token did not work: {served}"
        token = mutate(agent.token) if mutate else None
        window.begin()
        kinds, _ = agent.send([{"request": call_request("get_note", {"key": "k"}, token)}])
        if kinds != ["denied"]:
            return f"the call was {kinds}"
    return attempt


attack("C-EPI", "a missing token", reason="no episode token")(token_refused(None))
attack("C-EPI", "a malformed token: padding, charset, trailing bits")(token_refused(lambda token: token + "="))
attack("C-EPI", "a header member outside alg, typ and kid")(token_refused(with_header_member))
attack("C-EPI", "a forged signature")(token_refused(forged_signature))


@attack("C-EPI", "an idle token", reason="episode token refused")
def epi_idle(window):
    agent = window.agent("notes")
    served = agent.call("get_note", {"key": "k"})
    if "result" not in served:
        return f"the live token did not work: {served}"
    time.sleep(IDLE_S + CLOCK_SKEW_S + 1)
    window.begin()
    kinds, _ = agent.send([{"request": call_request("get_note", {"key": "k"}, agent.token)}])
    if kinds != ["denied"]:
        return f"the call was {kinds}"


@attack("C-EPI", "a Call Proof presented as an Episode Token", reason="episode token refused")
def epi_proof(window):
    agent = window.agent("notes")
    agent.call("get_note", {"key": "k"})
    proof = captured_proof()
    if not proof:
        return "no proof was captured"
    window.begin()
    kinds, _ = agent.send([{"request": call_request("get_note", {"key": "k"}, proof)}])
    if kinds != ["denied"]:
        return f"the call was {kinds}"


@attack("C-EPI", "the token of an ended episode", reason="episode token refused")
def epi_ended(window):
    agent = window.agent("notes")
    token = agent.token
    agent.end()
    window.begin()
    kinds, _ = agent.send([{"request": call_request("get_note", {"key": "k"}, token)}])
    if kinds != ["denied"]:
        return f"the call was {kinds}"


# --- C-CRED ---

@attack("C-CRED", "the agent and the PEP cannot read any tool server's credential")
def cred_read(window):
    agent = window.agent()
    for path in ["/run/credential-a", "/run/credential-b", "/run/credential.sha256"]:
        got = agent.probe("stat", path)
        if got != ENOENT:
            return f"the agent's {path}: {got}"
    mounts = json.dumps(check.inspect(check.container("pep"))["Mounts"])
    if "credential" in mounts:
        return f"the PEP mounts a credential: {mounts[:200]}"


@attack("C-CRED", "a rug-pulled tool-b cannot use its credential on tool-a")
def cred_rug_pull(window):
    address = tool_address("tool-a", "tools_a")
    # From tool-b's own network namespace, tool-a is not there.
    inside = docker_probe("connect", address, "8080", "tcp", flags=("--network", f"container:{check.container('tool-b')}"))
    if inside == "ok":
        return "tool-b reached tool-a's network"
    # Suppose it got there. Its own credential, which it sees on every call, buys nothing.
    credential = subprocess.run(["docker", "cp", f"{check.container('broker')}:/run/credential-b", "-"],
                                capture_output=True, check=False).stdout
    credential = check.tarfile.open(fileobj=check.io.BytesIO(credential)).extractfile("credential-b").read().decode()
    body = json.dumps({"jsonrpc": "2.0", "id": "stray", "method": "tools/call",
                       "params": {"name": "pay_invoice", "arguments": {"invoice_id": next(PLAIN), "amount": 1000, "currency": "USD"}}})
    request = (f"POST /mcp HTTP/1.1\r\nHost: tool-a\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\n"
               f"Accept: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}")
    out = run(["docker", "run", "--rm", "-i", "--network", network("tools_a"), "--read-only", "--cap-drop", "ALL",
               "--user", AGENT_USER, "--entrypoint", f"{BIN}/net-probe", PROBE_IMAGE, "tcp", address, "8080"],
              input=request, check=False, timeout=60)
    if not out.stdout.startswith("HTTP/1.1 403"):
        return f"tool-a answered {out.stdout[:40]!r}"


# --- C-CTL ---

@attack("C-CTL", "the agent cannot reach /run/pep-ctl")
def ctl_reach(window):
    agent = window.agent()
    got = agent.probe("unix", CONTROL)
    if got != ENOENT:
        return f"from the agent's container: {got}"
    # With the volume mounted anyway, the directory's mode still stops it.
    mounted = docker_probe("unix", CONTROL, flags=("--network", "none", "-v", f"{network('pep-ctl')}:/run/pep-ctl"))
    if mounted != EACCES:
        return f"with the volume mounted: {mounted}"


# --- C-OUT ---

def journal_after(expected):
    def after():
        results = journal_results()
        if results[-1:] != [expected]:
            return f"the journal ends {results[-3:]}"
    return after


@attack("C-OUT", "an agent disconnect after forwarding never releases the reservation", expected="allow:1")
def out_disconnect(window):
    agent = window.agent("pay")
    invoice = next(SLOW)
    agent.lookup(invoice)
    window.begin()
    args = {"invoice_id": invoice, "amount": 1000, "currency": "USD"}
    agent.send([{"request": call_request("pay_invoice", args, agent.token), "drop_after_ms": 300}])
    return journal_after("executed")


@attack("C-OUT", "notifications/cancelled naming a forwarded payment never releases it", expected="allow:1")
def out_cancelled(window):
    agent = window.agent("pay")
    invoice = next(SLOW)
    agent.lookup(invoice)
    window.begin()
    thread, box = in_background(agent.pay, invoice)
    time.sleep(0.4)
    upstream_id = json.loads(recorded()[-1]["body"])["id"]
    cancel = [raw_request("notifications/cancelled", {"requestId": request_id}, agent.token)
              for request_id in ("stub-agent-1", upstream_id)]
    agent.send([{"request": text} for text in cancel])
    thread.join()
    if status(box.get("reply")) != "executed":
        return f"the payment was {box.get('reply')}"
    return journal_after("executed")


# Inside one intent G_entity (4) refuses a used entity before G_budget (7) could: PaymentPending
# is what stops another intent (C-ENG, below).
SAME_INTENT_RETRY = ("EntityUsesExceeded", "PaymentPending")


@attack("C-OUT", "a retry after Unknown with a changed memo is refused", reason=SAME_INTENT_RETRY)
def out_memo(window):
    agent = window.agent("pay")
    invoice = next(PENDING)
    agent.lookup(invoice)
    agent.pay(invoice)
    agent.lookup(invoice)
    window.begin()
    reply = agent.pay(invoice, memo="a different digest")
    if not denied(reply):
        return f"the retry was {reply}"


@attack("C-OUT", "a PEP restart mid-payment leaves it NeedsReconcile", expected="allow:2", reason=SAME_INTENT_RETRY,
        leg_may_stay_open=True)
def out_restart(window):
    agent = window.agent("pay")
    invoice = next(SLOW)
    agent.lookup(invoice)
    window.begin()
    thread, _ = in_background(agent.pay, invoice)
    time.sleep(0.4)
    restart_pep()
    thread.join()
    agent.eid = None   # that episode died with the PEP
    next_agent = window.agent("pay")
    next_agent.lookup(invoice)
    reply = next_agent.pay(invoice)
    if not denied(reply):
        return f"the retry was {reply}"
    replayed = [line for line in dc("logs", "--no-color", "pep").stdout.splitlines() if "journal replayed" in line]
    if not replayed or " 0 unresolved" in replayed[-1]:
        return f"the journal replayed nothing unresolved: {replayed[-1:]}"


@attack("C-OUT", "with X unresolved, a payment to Y and then a retry of X is refused",
        expected="allow:1", reason=SAME_INTENT_RETRY)
def out_other_entity(window):
    first = window.agent("pay")
    unresolved = next(PENDING)
    first.lookup(unresolved)
    first.pay(unresolved)
    first.end()
    second = window.agent("pay")
    other = next(PLAIN)
    second.lookup(other)
    second.lookup(unresolved)
    window.begin()
    paid = second.pay(other)
    if status(paid) != "executed":
        return f"the payment to Y was {paid}"
    retried = second.pay(unresolved)
    if not denied(retried):
        return f"the retry of X was {retried}"


@attack("C-OUT", "an agent write before a restart is still tainted after it", reason="IntegrityViolation")
def out_taint(window):
    agent = window.agent("pay")
    invoice = next(PLAIN)
    agent.call("update_invoice", {"invoice_id": invoice, "text": "agent wrote this"})
    agent.eid = None
    restart_pep()
    fresh = window.agent("pay")
    fresh.lookup(invoice)
    window.begin()
    reply = fresh.pay(invoice)
    if not denied(reply):
        return f"the payment was {reply}"


@attack("C-OUT", "Secret data, a new episode of the intent, then a Public sink", reason="ConfidentialityViolation")
def out_ratchet(window):
    intent = next(SECRET_INTENTS)
    agent = window.agent(intent)
    read = agent.call("search_notes", {"query": "x"})
    if "result" not in read:
        return f"the secret read failed: {read}"
    agent.end()
    fresh = window.agent(intent)
    window.begin()
    reply = fresh.call("post_public", {"text": "from memory"})
    if not denied(reply):
        return f"the post was {reply}"


@attack("C-OUT", "a burst over the bucket is refused and issues no Call Proof", expected="any")
def out_burst(window):
    agent = window.agent("notes")
    before = len(lines("oracle", PROOFS))
    window.begin()
    kinds, counts = agent.send([{"request": call_request("get_note", {"key": "burst"}, agent.token)}] * 45)
    made = len(lines("oracle", PROOFS)) - before
    if not counts.get("unavailable"):
        return f"nothing was refused: {counts}"
    if made != counts.get("accepted"):
        return f"{made} proofs for {counts.get('accepted')} accepted calls"


@attack("C-OUT", "another intent's episode, in a fresh container, holds neither data nor helper")
def out_containers(window):
    intent = next(SECRET_INTENTS)
    first = window.agent(intent)
    if "result" not in first.call("search_notes", {"query": "x"}):
        return "the secret read failed"
    written = first.probe("open", "/tmp/loot", "c")
    if written != "ok":
        return f"the first agent could not even write to its own /tmp: {written}"
    second = window.agent("notes")
    window.begin()
    for path in ["/tmp/loot", "/run/pep/loot"]:
        got = second.probe("stat", path)
        if got != ENOENT:
            return f"{path}: {got}"


# --- C-ENG: end to end through the engine ---

def pay_refused(reply):
    return None if denied(reply) else f"the payment was {reply}"


@attack("C-ENG", "an entity id that looks like an allowed one", reason=("EntityNotAllowed", "ProvenanceMissing"))
def eng_homoglyph(window):
    agent = window.agent("pay")
    invoice = next(PLAIN)
    lookalike = invoice.replace("K", "К")    # a Cyrillic capital ka
    agent.lookup(lookalike)
    window.begin()
    return pay_refused(agent.pay(lookalike)) or pay_refused(agent.pay(invoice + "́"))


@attack("C-ENG", "an entity outside the intent", reason="EntityNotAllowed")
def eng_outside(window):
    agent = window.agent("small")
    invoice = next(PLAIN)
    agent.lookup(invoice)
    window.begin()
    return pay_refused(agent.pay(invoice))


@attack("C-ENG", "an amount taken from an unbound result field", reason="AmountNotBound")
def eng_unbound(window):
    agent = window.agent("pay")
    invoice = next(PLAIN)
    fee = pointer(agent.lookup(invoice), "/result/structuredContent/late_fee_minor")
    if fee != 50:
        return f"the unbound field is {fee}"
    window.begin()
    return pay_refused(agent.pay(invoice, amount=fee))


@attack("C-ENG", "a funding lookup laundered through a store write", reason="IntegrityViolation")
def eng_laundered(window):
    agent = window.agent("pay")
    invoice = next(PLAIN)
    agent.call("update_invoice", {"invoice_id": invoice, "text": "amount_due_minor: 1000"})
    agent.lookup(invoice)
    window.begin()
    return pay_refused(agent.pay(invoice))


@attack("C-ENG", "a value the agent wrote in one episode, as a witness in the next", reason="IntegrityViolation")
def eng_next_episode(window):
    agent = window.agent("pay")
    invoice = next(PLAIN)
    agent.call("update_invoice", {"invoice_id": invoice, "text": "agent wrote this"})
    agent.end()
    fresh = window.agent("pay")
    fresh.lookup(invoice)
    window.begin()
    return pay_refused(fresh.pay(invoice))


def secret_then(window):
    agent = window.agent(next(SECRET_INTENTS))
    read = agent.call("search_notes", {"query": "x"})
    return agent, None if "result" in read else f"the secret read failed: {read}"


@attack("C-ENG", "Secret data sent to a Public sink", reason="ConfidentialityViolation")
def eng_public_sink(window):
    agent, problem = secret_then(window)
    window.begin()
    return problem or pay_refused(agent.call("post_public", {"text": "the secret"}))


@attack("C-ENG", "Secret data through a free data argument", reason="ConfidentialityViolation")
def eng_free_argument(window):
    agent, problem = secret_then(window)
    invoice = next(PLAIN)
    agent.lookup(invoice)
    window.begin()
    return problem or pay_refused(agent.pay(invoice, memo="the secret"))


@attack("C-ENG", "a secret in chunks under 16 bytes, through a reader with no location",
        reason="ConfidentialityViolation")
def eng_chunks(window):
    agent = window.agent(next(SECRET_INTENTS))
    for index, chunk in enumerate(["hunter2-", "part-two"]):
        agent.call("save_note", {"key": f"chunk-{index}", "text": chunk})
    if "result" not in agent.call("search_notes", {"query": "hunter2"}):
        return "the reader failed"
    window.begin()
    return pay_refused(agent.call("post_public", {"text": "hunter2-part-two"}))


@attack("C-ENG", "a payment split to dodge step-up", reason="AmountNotBound")
def eng_split(window):
    agent = window.agent("pay")
    invoice = next(PLAIN)
    agent.lookup(invoice)
    window.begin()
    return pay_refused(agent.pay(invoice, amount=500))


@attack("C-ENG", "two concurrent payments funded by one lookup", expected="allow:1",
        reason=("PaymentPending", "ProvenanceConsumed"))
def eng_concurrent(window):
    agent = window.agent("pay")
    invoice = next(SLOW)
    agent.lookup(invoice)
    window.begin()
    first, first_box = in_background(agent.pay, invoice)
    second, second_box = in_background(agent.pay, invoice)
    first.join()
    second.join()
    if sum(status(box.get("reply")) == "executed" for box in (first_box, second_box)) != 1:
        return f"{first_box}, {second_box}"


@attack("C-ENG", "lookup, pay, lookup, pay while the first is still upstream", expected="allow:1", reason=SAME_INTENT_RETRY)
def eng_upstream(window):
    agent = window.agent("pay")
    invoice = next(SLOW)
    agent.lookup(invoice)
    window.begin()
    thread, box = in_background(agent.pay, invoice)
    time.sleep(0.4)
    agent.lookup(invoice)
    window.expected_now = "allow:2"   # the second lookup runs too
    retried = agent.pay(invoice)
    thread.join()
    if status(box.get("reply")) != "executed":
        return f"the first payment was {box.get('reply')}"
    return pay_refused(retried)


@attack("C-ENG", "the same invoice from a second intent while the first is NeedsReconcile", reason="PaymentPending")
def eng_second_intent(window):
    first = window.agent("pay")
    invoice = next(PENDING)
    first.lookup(invoice)
    first.pay(invoice)
    second = window.agent("pay2")
    second.lookup(invoice)
    window.begin()
    return pay_refused(second.pay(invoice))


@attack("C-ENG", "over per_call_max_minor, and past the cumulative cap", expected="allow:1",
        reason=("PerCallMaxExceeded", "CumulativeMaxExceeded"))
def eng_caps(window):
    agent = window.agent("pay")
    agent.lookup("INV-B001")
    small = window.agent("small")
    first, second = next(SMALL), next(SMALL)
    small.lookup(first)
    small.lookup(second)
    window.begin()
    over = agent.pay("INV-B001", amount=150000)
    paid = small.pay(first)
    past = small.pay(second)
    if status(paid) != "executed":
        return f"the payment inside the cap was {paid}"
    return pay_refused(over) or pay_refused(past)


@attack("C-ENG", "an undeclared nested argument", reason="UndeclaredArgument")
def eng_undeclared(window):
    agent = window.agent("pay")
    invoice = next(PLAIN)
    agent.lookup(invoice)
    window.begin()
    return pay_refused(agent.pay(invoice, nested={"amount": 1}))


@attack("C-ENG", "a tool name under the reserved pep/ prefix", reason="ToolNotPinned")
def eng_reserved(window):
    agent = window.agent("pay")
    window.begin()
    return pay_refused(agent.call("pep/trusted-input", {"value": 1}))


@attack("C-ENG", "a call to an unpinned tool", reason="ToolNotPinned")
def eng_unpinned(window):
    agent = window.agent("pay")
    window.begin()
    return pay_refused(agent.call("delete_everything", {}))


@attack("C-ENG", "a control method sent on the agent socket")
def eng_control(window):
    agent = window.agent("pay")
    window.begin()
    params = {"intent": "pay", "eid": agent.eid, "rid": 1, "action_digest": "x", "amount_minor": 1}
    kinds, _ = agent.send([{"request": raw_request(method, params, agent.token)}
                           for method in ("start_episode", "approve", "end_episode", "pending")])
    if "accepted" in kinds:
        return f"the agent socket answered {kinds}"


@attack("C-ENG", "a forged call-proof or outcome member in the agent's _meta", reason="ReservedMetaMember")
def eng_forged_meta(window):
    agent = window.agent("pay")
    invoice = next(PLAIN)
    agent.lookup(invoice)
    window.begin()
    args = {"invoice_id": invoice, "amount": 1000, "currency": "USD"}
    kinds, _ = agent.send([
        {"request": call_request("pay_invoice", args, agent.token, meta={PROOF_KEY: "eyJforged"})},
        {"request": call_request("pay_invoice", args, agent.token, meta={OUTCOME_KEY: "executed"})}])
    if kinds != ["denied", "denied"]:
        return f"the calls were {kinds}"


@attack("C-ENG", "a call to a tool of a quarantined server", reason="ToolQuarantined")
def eng_quarantined(window):
    run(["docker", "exec", check.container("tool-b"), "touch", "/var/lib/tool/drift"])
    restart_pep()
    agent = window.agent("notes")
    listed = [tool.get("name") for tool in pointer(agent.list_tools(), "/result/tools") or []]
    if "get_note" in listed or "get_invoice" not in listed:
        return f"tools/list shows {listed}"
    window.begin()
    return pay_refused(agent.call("get_note", {"key": "k"}))


# --- G3: replays of captured Call Proofs, and misuse of captured Episode Tokens (§3) ---

replays = {"attempts": 0, "accepted": 0, "classes": 0}


def capture_proofs(count):
    """`count` fresh read proofs, paced under the rate limit, and the same number of captured lines."""
    agent = Agent("pay")
    invoice = next(PLAIN)
    before = len(lines("oracle", PROOFS))
    request = call_request("get_invoice", {"invoice_id": invoice}, agent.token)
    agent.send([{"request": request, "delay_ms": 105}] * count)
    agent.close()
    return lines("oracle", PROOFS)[before:]


def capture_payment_proofs(count):
    agent = Agent("pay")
    before = len(lines("oracle", PROOFS))
    for _ in range(count):
        invoice = next(PLAIN)
        agent.lookup(invoice)
        agent.pay(invoice)
    agent.close()
    return [line for line in lines("oracle", PROOFS)[before:] if "pay_invoice" in line["body"]]


def proof_of(line):
    return json.loads(line["body"])["params"]["_meta"][PROOF_KEY]


def with_proof(line, proof):
    return dict(line, body=line["body"].replace(proof_of(line), proof))


def enough(items, count=PER_CLASS):
    return [items[index % len(items)] for index in range(count)]


def inject(items):
    stdin = "".join(json.dumps(item) + "\n" for item in items)
    out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "--entrypoint", f"{BIN}/stub-injector", "injector",
             "broker", BROKER_SOCKET, "20003", "20003", "-", input=stdin, check=False, timeout=180)
    return json.loads(out.stdout.strip().splitlines()[-1]) if out.stdout.strip() else {}


def replay_class(name, items, reason=None):
    """One class of proofs at the broker: none accepted, nothing reaches a tool."""
    def attempt(window):
        before = len(lines("oracle", BROKER_LOG))
        summary = inject(items)
        replays["attempts"] += summary.get("attempts", 0)
        replays["accepted"] += summary.get("accepted", 0)
        if summary.get("attempts") != len(items):
            return f"{summary.get('attempts')} of {len(items)} replayed"
        if summary.get("accepted"):
            return f"{summary['accepted']} accepted"
        if reason:
            reasons = {line.get("reason") for line in lines("oracle", BROKER_LOG)[before:]}
            if reasons != {reason}:
                return f"refused for {sorted(str(r) for r in reasons)}, not {reason}"
    replays["classes"] += 1
    return run_test(f"G3 proof: {name} ({len(items)})", "deny", None, False, attempt)


def token_class(name, agent, tokens, reply="denied"):
    """One class of tokens at the PEP: none accepted, nothing reaches a tool."""
    def attempt(window):
        items = [{"request": call_request("get_invoice", {"invoice_id": "INV-K300"}, token)} for token in tokens]
        kinds, counts = agent.send(items)
        replays["attempts"] += len(kinds)
        replays["accepted"] += counts.get("accepted", 0)
        if len(kinds) != len(tokens):
            return f"{len(kinds)} of {len(tokens)} sent"
        if set(kinds) != {reply}:
            return f"{counts}"
    replays["classes"] += 1
    return run_test(f"G3 token: {name} ({len(tokens)})", "deny", None, False, attempt)


def wait_for_proof_expiry():
    print(f"note G3: waiting {PROOF_LIFETIME_S + CLOCK_SKEW_S + 1} s for captured proofs to expire", flush=True)
    time.sleep(PROOF_LIFETIME_S + CLOCK_SKEW_S + 1)


def g3_proofs():
    reads = capture_proofs(PER_CLASS)
    payments = capture_payment_proofs(6)
    print(f"note G3: captured {len(reads)} read proofs and {len(payments)} payment proofs", flush=True)
    if not reads or not payments:
        expect("G3: proofs were captured", False)
        return
    replay_class("verbatim, reads as well as payments", enough(reads + payments), "call proof replayed")
    replay_class("after the reservation leaves Held", enough(payments), "call proof replayed")

    def other_rid(index, line):
        header, payload, signature = proof_of(line).split(".")
        claims = json.loads(unb64(payload))
        claims["rid"] = claims.get("rid", 0) + index + 1
        return with_proof(line, f"{header}.{b64(json.dumps(claims, separators=(',', ':')).encode())}.{signature}")
    replay_class("against a different rid", [other_rid(i, line) for i, line in enumerate(enough(payments))])
    replay_class("malleated high-S, same jti", [with_proof(line, high_s(proof_of(line))) for line in enough(reads)])
    replay_class("re-encoded with padding", [with_proof(line, proof_of(line) + "=") for line in enough(reads)])
    standard = [with_proof(line, standard_alphabet(proof_of(line))) for line in reads
                if standard_alphabet(proof_of(line)) != proof_of(line)]
    replay_class("re-encoded in the standard alphabet", enough(standard))
    replay_class("non-zero trailing bits", [with_proof(line, trailing_bits(proof_of(line))) for line in enough(reads)])
    agent = Agent("notes")
    replay_class("an Episode Token presented as a Call Proof", [with_proof(line, agent.token) for line in enough(reads)])
    agent.close()
    wait_for_proof_expiry()
    replay_class("after exp", enough(reads))

    fresh = capture_proofs(PER_CLASS)
    restart_pep()
    replay_class("after a PEP restart, a key from the previous boot", enough(fresh))

    fresh = capture_proofs(PER_CLASS)
    run(["docker", "kill", check.container("broker")])
    dc("up", "-d", "--wait", "--wait-timeout", "120", "--no-deps", "broker")
    time.sleep(1.1)
    replay_class("after a broker restart, issued before it booted", enough(fresh))

    # A proof issued in the broker's boot second: reads run across a restart, and any that land in
    # that second are refused on first use, then replayed.
    agent = Agent("pay")
    invoice = next(PLAIN)
    before_log, before_proofs = len(lines("oracle", BROKER_LOG)), len(lines("oracle", PROOFS))
    run(["docker", "kill", check.container("broker")])
    thread, _ = in_background(agent.send, [{"request": call_request("get_invoice", {"invoice_id": invoice}, agent.token),
                                            "delay_ms": 110}] * 18)
    dc("up", "-d", "--no-deps", "broker")
    thread.join()
    agent.close()
    in_boot_second = [line for line in lines("oracle", BROKER_LOG)[before_log:] if line.get("reason") == "call proof refused"]
    print(f"note G3: {len(in_boot_second)} calls landed in the broker's boot second", flush=True)
    window_lines = lines("oracle", PROOFS)[before_proofs:]
    if window_lines:
        time.sleep(1.1)
        replay_class("issued in the broker's boot second", enough(window_lines))
    else:
        expect("G3: a proof was captured around the broker's boot", False)


def g3_tokens():
    def rotate(tokens):
        return enough(tokens)

    # Live tokens, re-encoded.
    agent = Agent("notes")
    token = agent.token
    token_class("re-encoded with padding", agent, rotate([token + "=", token + "==", "=" + token]))
    token_class("re-encoded in the standard alphabet", agent, rotate([standard_alphabet(token) + "#", standard_alphabet(token).replace("A", "+")]))
    token_class("non-zero trailing bits", agent, rotate([trailing_bits(token)]))
    token_class("malleated high-S", agent, rotate([high_s(token)]))
    proof = captured_proof()
    token_class("a Call Proof presented as an Episode Token", agent, rotate([proof]))

    # From another peer: closed unread, so nothing is even answered.
    def other_peer(window):
        items = [{"request": call_request("get_invoice", {"invoice_id": "INV-K300"}, token)}] * PER_CLASS
        stdin = "".join(json.dumps(item) + "\n" for item in items)
        out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "--user", "20009:20001", "--entrypoint",
                 f"{BIN}/stub-injector", "probe", "pep", SOCKET, "-", input=stdin, check=False, timeout=120)
        rows = [json.loads(line) for line in out.stdout.splitlines()]
        counts = rows[-1] if rows else {}
        replays["attempts"] += len(rows) - 1
        replays["accepted"] += counts.get("accepted", 0)
        if counts.get("accepted") or len(rows) - 1 != PER_CLASS:
            return f"{counts}"
    replays["classes"] += 1
    run_test(f"G3 token: from another peer ({PER_CLASS})", "deny", None, False, other_peer)

    # After end_episode.
    ended = agent.token
    agent.end()
    token_class("after end_episode", agent, rotate([ended]))
    agent.close()

    # After the idle timeout.
    idle = Agent("notes")
    idle.call("get_note", {"key": "k"})
    time.sleep(IDLE_S + CLOCK_SKEW_S + 1)
    token_class("after the idle timeout", idle, rotate([idle.token]))
    idle.close()

    # After exp: kept busy, so only exp can be what ends it.
    busy = Agent("notes")
    deadline = time.time() + LIFETIME_S + CLOCK_SKEW_S + 1
    while time.time() < deadline:
        busy.call("get_note", {"key": "k"})
        time.sleep(2)
    token_class("after exp", busy, rotate([busy.token]))
    busy.close()

    # After a PEP restart.
    old = Agent("notes")
    old.call("get_note", {"key": "k"})
    restart_pep()
    old.eid = None
    token_class("after a PEP restart, a previous boot's key and kid", old, rotate([old.token]))
    old.close()


def remove_parked():
    """Parked containers are not Compose's, so `down` would find their volumes in use."""
    run(["sh", "-c", f"docker ps -aq --filter name={check.PROJECT}-agent- | xargs -r docker rm -f"], check=False)


def main():
    arguments = sys.argv[1:]
    keep = "--keep" in arguments
    only = arguments[arguments.index("--only") + 1] if "--only" in arguments else None
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    dc(*PROFILES, "build")
    remove_parked()
    dc(*PROFILES, "down", "-v", "--remove-orphans")
    try:
        dc("up", "-d", "--wait", "--wait-timeout", "120")
        time.sleep(1.1)   # the broker refuses proofs from its boot second (R1)
        if not controls():
            print("KIT STOPPED: a control failed, so no verdict below would mean anything")
            return 1
        for entry in ATTACKS:
            name = f"{entry['category']} {entry['title']}"
            if only and only not in name:
                continue
            tally["attacks"] += 1
            run_test(name, entry["expected"], entry["reason"], entry["open_ok"], entry["function"])
        if not only or only == "G3":
            g3_proofs()
            g3_tokens()
            print(f"note G3: {replays['accepted']} of {replays['attempts']} accepted, across {replays['classes']} classes "
                  "(in-process, beside G3: concurrent first uses, clock steps, claims for a reservation not Held)", flush=True)
    finally:
        if not keep:
            remove_parked()
            dc(*PROFILES, "down", "-v", "--remove-orphans", check=False)
    failures = len(check.failures)
    print(f"KIT: {tally['attacks']} of {PLANNED_ATTACKS} G1 attacks ran, {tally['held']} tests held, "
          f"{replays['attempts']} G3 attempts, {replays['accepted']} accepted; "
          f"{'all held' if not failures else f'{failures} FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
