"""Can the attacks fail? A sabotage run over C-ENG and C-OUT (WEEK2_PLAN §3, G1).

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/sabotage.py [--run TEXT] [--keep-going]

An attack that passes says nothing until it has been seen to fail. This copies the tree to a
temporary directory, wraps each defence in a switch read from `PEP_SABOTAGE`, and builds that copy
once, under its own image tag and project, so nothing here can reach the real images or the real
source. A baseline with every switch off must hold every attack, or the switches changed something.
Then each entry in RUNS starts a stack with its switches on and runs the attacks it should break,
through compose/kit.py, judged by the same oracle.

- **caught:** the oracle saw a bypass, or the attempt succeeded. The attack can see that defence go.
- **refused elsewhere:** the only complaint is that the call was refused for another reason. That
  is defence in depth, and it does not count: the attack never got past.
- **survived:** the attack held with its defence gone, so it has not been shown able to fail.

Writes `reports/Gate1 sabotage report.md`. Exits 0 only if the baseline held, every attack in C-ENG
and C-OUT was caught, and no sabotage left its attack unmoved: each is aimed at one defence, so a
survivor is a blind attack, even if another sabotage catches it. The substitutions fail loudly if
the source moves. Takes about an hour. It never touches `src/` here, and no switch exists outside
the temporary copy.
"""
import datetime, os, re, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = "reports/Gate1 sabotage report.md"
TAG = ":sabotage"
PROJECT = "pep-sabotage"
GROUPS = ("C-ENG", "C-OUT")
ALL_ATTACKS = 28
RESULT = re.compile(r"^(ok  |FAIL) ((?:C-ENG|C-OUT) .+?) \[(.+?)\](?:: (.*))?$")


def off(name):
    return f'crate::sabotage::off("{name}")'


# Each switch removes one defence, as text substitutions in the temporary copy.
SWITCHES = {
    "entity_allowed": [("src/engine.rs",
                        "if !intent.entities.ids.contains(id) {",
                        f"if !intent.entities.ids.contains(id) && !{off('entity_allowed')} {{")],
    "entity_uses": [("src/engine.rs",
                     ".filter(|uses| *uses <= intent.entities.per_entity_max_uses)",
                     f".filter(|uses| *uses <= intent.entities.per_entity_max_uses || {off('entity_uses')})")],
    "witness_needed": [
        ("src/engine.rs",
         "    let witness = latest_witness(state, tool, entity).ok_or(missing)?;\n",
         f"    let Some(witness) = latest_witness(state, tool, entity) else {{\n"
         f"        return if {off('witness_needed')} {{ Ok(None) }} else {{ Err(missing) }};\n"
         f"    }};\n"),
        ("src/engine.rs",
         "    let witness = witness.ok_or_else(|| deny(GuardId::Prov, PolicyError::ProvenanceMissing))?;\n",
         f"    if witness.is_none() && {off('witness_needed')} {{\n"
         f"        return Ok(Some(amount));\n"
         f"    }}\n"
         f"    let witness = witness.ok_or_else(|| deny(GuardId::Prov, PolicyError::ProvenanceMissing))?;\n"),
        ("src/engine.rs",
         "        _ => Err(deny(GuardId::Prov, PolicyError::ProvenanceMissing)),\n    }\n}\n\n/// Whether the recorded results",
         f"        (Some(amount), Some((entity, new_entity_uses)), None) if {off('witness_needed')} => {{\n"
         f"            Ok(Some(PaymentInputs {{ amount, entity, new_entity_uses, witness_seq: u64::MAX }}))\n"
         f"        }}\n"
         f"        _ => Err(deny(GuardId::Prov, PolicyError::ProvenanceMissing)),\n    }}\n}}\n\n/// Whether the recorded results"),
        ("src/engine.rs",
         "        if let Some(reservation) = reservation {\n            // A reservation always has its witness",
         f"        if let Some(reservation) = reservation.filter(|_| !{off('witness_needed')}) {{\n"
         f"            // A reservation always has its witness"),
    ],
    "witness_once": [("src/engine.rs", "    if consumed {\n", f"    if consumed && !{off('witness_once')} {{\n")],
    "amount_bound": [("src/engine.rs", "    if !bound {\n", f"    if !bound && !{off('amount_bound')} {{\n")],
    "per_call": [("src/engine.rs",
                  "if amount > limits.per_call_max_minor {",
                  f"if amount > limits.per_call_max_minor && !{off('per_call')} {{")],
    "cumulative": [("src/engine.rs",
                    "if total > limits.cumulative_max_minor {",
                    f"if total > limits.cumulative_max_minor && !{off('cumulative')} {{")],
    "pending": [
        ("src/engine.rs",
         "    if claimed\n        || unresolved.contains(&entity)\n",
         f"    if !{off('pending')} && (claimed\n        || unresolved.contains(&entity)\n"),
        ("src/engine.rs",
         "            .any(|reservation| blocks_payment(reservation, tool, &entity))\n    {\n",
         "            .any(|reservation| blocks_payment(reservation, tool, &entity)))\n    {\n"),
        ("src/engine.rs", "        if *count >= max {\n", f"        if *count >= max && !{off('pending')} {{\n"),
    ],
    "confidentiality": [("src/engine.rs",
                         "if input.conf > destination_clearance(tool, &canon.roles) {",
                         f"if input.conf > destination_clearance(tool, &canon.roles) && !{off('confidentiality')} {{")],
    "integrity": [("src/engine.rs",
                   "if !(amount_trusted && currency_trusted) {",
                   f"if !(amount_trusted && currency_trusted) && !{off('integrity')} {{")],
    "taint_recorded": [("src/engine.rs",
                        "if let Err(error) = self.labels.record_all(&taint_writes, entry) {",
                        f"if let Err(error) = (if {off('taint_recorded')} {{ Ok(()) }} else {{ self.labels.record_all(&taint_writes, entry) }}) {{")],
    "undeclared": [("src/engine.rs",
                    "if strict_arguments(tool) && !only_declared(",
                    f"if !{off('undeclared')} && strict_arguments(tool) && !only_declared(")],
    "reserved_meta": [("src/engine.rs",
                       ".any(|(key, _)| is_reserved_meta(key.as_str()))",
                       f".any(|(key, _)| is_reserved_meta(key.as_str()) && !{off('reserved_meta')})")],
    "pinned": [
        ("src/engine.rs",
         "let tool = self.pins.tools.get(name).ok_or(not_pinned)?;",
         f"let tool = self.pins.tools.get(name).or_else(|| if {off('pinned')} "
         f"{{ self.pins.tools.get(\"search_notes\") }} else {{ None }}).ok_or(not_pinned)?;"),
        ("src/engine.rs",
         "            .get(&in_flight.tool)\n            .ok_or(PepError::UnknownCall)?;\n        self.pin_checks(tool)?;\n",
         f"            .get(&in_flight.tool)\n            .or_else(|| if {off('pinned')} "
         f"{{ self.pins.tools.get(\"search_notes\") }} else {{ None }})\n"
         f"            .ok_or(PepError::UnknownCall)?;\n        self.pin_checks(tool)?;\n"),
    ],
    "quarantine": [("src/engine.rs",
                    "if self.servers.state(&tool.server_id) != ServerState::Serving {",
                    f"if self.servers.state(&tool.server_id) != ServerState::Serving && !{off('quarantine')} {{")],
    "ratchet_kept": [("src/engine.rs",
                      "state: EpisodeState::new(intent, budget, context_conf),",
                      f"state: EpisodeState::new(intent, budget, if {off('ratchet_kept')} "
                      f"{{ Confidentiality::Public }} else {{ context_conf }}),")],
    "release_forwarded": [
        ("src/engine.rs",
         "        if !matches!(state, ResState::Held | ResState::AwaitingStepUp) {\n            return Err(PepError::InvalidTransition);\n        }\n        self.release(reservation_id)",
         f"        if !matches!(state, ResState::Held | ResState::AwaitingStepUp) && !{off('release_forwarded')} {{\n"
         f"            return Err(PepError::InvalidTransition);\n        }}\n        self.release(reservation_id)"),
        ("src/actor.rs",
         "                if let Some((call, _)) = self.waiting.remove(&pep_id) {\n                    self.unforward(&call);\n                }\n",
         f"                if let Some((call, _)) = self.waiting.remove(&pep_id) {{\n                    self.unforward(&call);\n"
         f"                }} else if {off('release_forwarded')} && let Some(call) = self.legs.remove(&pep_id) {{\n"
         f"                    self.unforward(&call);\n                }}\n"),
    ],
    "cancel_releases": [
        ("src/serve.rs",
         "        Ok(Inbound::Ignored) => mcp::accepted().to_http(),\n",
         f"        Ok(Inbound::Ignored) => {{\n"
         f"            if {off('cancel_releases')} {{\n"
         f"                let parsed = crate::jcs::parse_with(&request.body, &crate::jcs::ParseOptions::definition());\n"
         f"                if let Some(id) = parsed.ok().and_then(|parsed| {{\n"
         f"                    parsed.value.pointer(\"/params/requestId\").and_then(|id| id.as_str().map(str::to_owned))\n"
         f"                }}) {{\n"
         f"                    context.registry.sabotage_cancel(&id);\n"
         f"                }}\n"
         f"            }}\n"
         f"            mcp::accepted().to_http()\n"
         f"        }}\n"),
        ("src/registry.rs",
         "impl Registry {\n",
         "impl Registry {\n"
         "    /// Sabotage only: treats `pep_id` as a disconnect, in every live episode.\n"
         "    pub fn sabotage_cancel(&self, pep_id: &str) {\n"
         "        if let Ok(inner) = self.inner.lock() {\n"
         "            for live in inner.live.values() {\n"
         "                let _ = live.agent.send(crate::actor::AgentMessage::Disconnected { pep_id: pep_id.to_owned() });\n"
         "            }\n"
         "        }\n"
         "    }\n\n"),
    ],
    "unknown_kept": [("src/actor.rs",
                      ".settle(host, rid, Settlement::Aborted(AbortOutcome::Unknown));",
                      f".settle(host, rid, Settlement::Aborted(if {off('unknown_kept')} "
                      f"{{ AbortOutcome::DefinitelyNotExecuted }} else {{ AbortOutcome::Unknown }}));")],
    "replay_unresolved": [("src/journal.rs",
                           "            Some(OutcomeKind::Unknown) => true,\n            None if payment.forwarded => true,\n",
                           f"            Some(OutcomeKind::Unknown) | None if {off('replay_unresolved')} => continue,\n"
                           f"            Some(OutcomeKind::Unknown) => true,\n            None if payment.forwarded => true,\n")],
    "taint_replayed": [("src/main.rs",
                        "        &replayed.taint,\n",
                        "        &(if pep_sidecar::sabotage::off(\"taint_replayed\") { Vec::new() } else { replayed.taint.clone() }),\n")],
    "rate_limit": [("src/registry.rs",
                    "        if !take(\n            &mut live.bucket,\n",
                    f"        if !{off('rate_limit')} && !take(\n            &mut live.bucket,\n")],
    "control_routed": [("src/mcp.rs",
                        '            "subscriptions/listen" => Some(Self::Listen),\n            _ => None,\n',
                        f'            "subscriptions/listen" => Some(Self::Listen),\n'
                        f'            _ if {off("control_routed")} => Some(Self::Discover),\n            _ => None,\n')],
}

# In the kit, not the PEP: a /tmp the agents share, which C-OUT's fresh-container attack must see.
KIT_SWITCHES = {
    "shared_tmp": [("compose/kit.py",
                    '"--tmpfs", "/tmp:size=64m,mode=1777,nosuid,nodev,noexec", *mount,',
                    '*(("-v", os.environ["PEP_SHARED_TMP"] + ":/tmp") if "shared_tmp" in os.environ.get("PEP_SABOTAGE", "") '
                    'else ("--tmpfs", "/tmp:size=64m,mode=1777,nosuid,nodev,noexec")), *mount,')],
}

ENG = "C-ENG "
OUT = "C-OUT "
HOMOGLYPH = ENG + "an entity id that looks like an allowed one"
OUTSIDE = ENG + "an entity outside the intent"
UNBOUND = ENG + "an amount taken from an unbound result field"
LAUNDERED = ENG + "a funding lookup laundered through a store write"
NEXT_EPISODE = ENG + "a value the agent wrote in one episode, as a witness in the next"
PUBLIC_SINK = ENG + "Secret data sent to a Public sink"
FREE_ARGUMENT = ENG + "Secret data through a free data argument"
CHUNKS = ENG + "a secret in chunks under 16 bytes, through a reader with no location"
SPLIT = ENG + "a payment split to dodge step-up"
CONCURRENT = ENG + "two concurrent payments funded by one lookup"
UPSTREAM = ENG + "lookup, pay, lookup, pay while the first is still upstream"
SECOND_INTENT = ENG + "the same invoice from a second intent while the first is NeedsReconcile"
CAPS = ENG + "over per_call_max_minor, and past the cumulative cap"
UNDECLARED = ENG + "an undeclared nested argument"
RESERVED = ENG + "a tool name under the reserved pep/ prefix"
UNPINNED = ENG + "a call to an unpinned tool"
CONTROL = ENG + "a control method sent on the agent socket"
FORGED = ENG + "a forged call-proof or outcome member in the agent's _meta"
QUARANTINED = ENG + "a call to a tool of a quarantined server"
DISCONNECT = OUT + "an agent disconnect after forwarding never releases the reservation"
CANCELLED = OUT + "notifications/cancelled naming a forwarded payment never releases it"
MEMO = OUT + "a retry after Unknown with a changed memo is refused"
RESTART = OUT + "a PEP restart mid-payment leaves it NeedsReconcile"
OTHER_ENTITY = OUT + "with X unresolved, a payment to Y and then a retry of X is refused"
TAINT = OUT + "an agent write before a restart is still tainted after it"
RATCHET = OUT + "Secret data, a new episode of the intent, then a Public sink"
BURST = OUT + "a burst over the bucket is refused and issues no Call Proof"
CONTAINERS = OUT + "another intent's episode, in a fresh container, holds neither data nor helper"

# Label, the switches on together, and the attacks that should now fail.
RUNS = [
    ("G_entity's allowlist gone", ["entity_allowed"], [OUTSIDE]),
    ("Provenance and the allowlist gone", ["entity_allowed", "witness_needed"], [HOMOGLYPH]),
    ("F-14's amount binding gone", ["amount_bound"], [UNBOUND, SPLIT]),
    ("F-08's taint never recorded", ["taint_recorded"], [LAUNDERED, NEXT_EPISODE, TAINT]),
    ("G_label's integrity check gone", ["integrity"], [LAUNDERED, NEXT_EPISODE, TAINT]),
    ("G_label's confidentiality check gone", ["confidentiality"], [PUBLIC_SINK, FREE_ARGUMENT, CHUNKS, RATCHET]),
    ("The per-episode ratchet not carried over", ["ratchet_kept"], [RATCHET]),
    ("Every once-only check on an invoice gone", ["witness_once", "pending", "entity_uses"],
     [CONCURRENT, UPSTREAM, MEMO, OTHER_ENTITY]),
    ("PaymentPending gone", ["pending"], [SECOND_INTENT]),
    ("per_call_max_minor gone", ["per_call"], [CAPS]),
    ("cumulative_max_minor gone", ["cumulative"], [CAPS]),
    ("F-13's undeclared argument check gone", ["undeclared"], [UNDECLARED]),
    ("G_pin's lookup falls back to a pinned tool", ["pinned"], [RESERVED, UNPINNED]),
    ("The router takes any method", ["control_routed"], [CONTROL]),
    ("Reserved _meta members allowed", ["reserved_meta"], [FORGED]),
    ("Quarantine ignored", ["quarantine"], [QUARANTINED]),
    ("A disconnect releases a forwarded payment", ["release_forwarded"], [DISCONNECT]),
    ("A cancel releases a forwarded payment", ["release_forwarded", "cancel_releases"], [CANCELLED]),
    ("Unknown is taken for not executed", ["unknown_kept", "entity_uses"], [MEMO]),
    ("Replay forgets unresolved payments", ["replay_unresolved"], [RESTART]),
    ("Replay forgets taint", ["taint_replayed"], [TAINT]),
    ("No rate limit", ["rate_limit"], [BURST]),
    ("Agents share /tmp", ["shared_tmp"], [CONTAINERS]),
]

SABOTAGE_MODULE = """//! Sabotage only: this file exists in a temporary copy of the tree, never in the repository.

/// Whether the defence `name` is switched off in this run.
#[must_use]
pub fn off(name: &str) -> bool {
    std::env::var("PEP_SABOTAGE").is_ok_and(|set| set.split(',').any(|item| item == name))
}
"""


def substitute(copy, path, old, new):
    full = os.path.join(copy, path)
    with open(full, encoding="utf-8", newline="") as f:
        text = f.read()
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected this exactly once, found {text.count(old)}: {old[:80]!r}")
    with open(full, "w", encoding="utf-8", newline="") as f:
        f.write(text.replace(old, new))


def prepare(copy):
    """The tree, with its switches, under its own tag and project."""
    def skip(directory, names):
        return {name for name in names if name in (".git", "target", "node_modules")}
    shutil.copytree(ROOT, copy, ignore=skip, dirs_exist_ok=True)
    with open(os.path.join(copy, "src/sabotage.rs"), "w") as f:
        f.write(SABOTAGE_MODULE)
    substitute(copy, "src/lib.rs", "pub mod serve;\n", "pub mod sabotage;\npub mod serve;\n")
    for switches in (SWITCHES, KIT_SWITCHES):
        for edits in switches.values():
            for path, old, new in edits:
                substitute(copy, path, old, new)
    substitute(copy, "compose/gate1.yaml",
               "  pep:                         # 12 episodes at 72 MiB, and 48 connections (compose.yaml's formulas)\n",
               "  pep:                         # 12 episodes at 72 MiB, and 48 connections (compose.yaml's formulas)\n"
               "    environment: { PEP_SABOTAGE: \"${PEP_SABOTAGE:-}\" }\n")
    substitute(copy, "compose/kit.py", 'check.PROJECT = "pep-kit"', f'check.PROJECT = "{PROJECT}"')
    for path in ("compose.yaml", "compose/gate1.yaml", "compose/load.yaml", "compose/kit.py"):
        full = os.path.join(copy, path)
        with open(full, encoding="utf-8", newline="") as f:
            text = f.read()
        with open(full, "w", encoding="utf-8", newline="") as f:
            f.write(text.replace(":dev", TAG))


def run_kit(copy, shared, switches, attacks):
    """Each attack's result: (held, detail), or None if the kit stopped before it."""
    arguments = [item for attack in attacks for item in ("--only", attack)]
    env = dict(os.environ, PEP_SABOTAGE=",".join(switches), PEP_SHARED_TMP=shared)
    out = subprocess.run(["python3", "compose/kit.py", *arguments], cwd=copy, env=env, capture_output=True,
                         text=True, timeout=1800, check=False)
    results = {}
    for line in out.stdout.splitlines():
        match = RESULT.match(line)
        if match:
            results[match[2]] = (match[1] == "ok  ", match[4] or "")
    if not results:
        print(out.stdout[-1500:], out.stderr[-800:], flush=True)
    return results


def verdict(held, detail):
    if held:
        return "survived"
    parts = detail.split("; ")
    return "refused elsewhere" if all(part.startswith("not refused for") for part in parts) else "caught"


def write_report(baseline, findings):
    attacks = sorted(baseline)
    caught = {attack: [row for row in findings if row["attack"] == attack and row["verdict"] == "caught"]
              for attack in attacks}
    proven = sum(1 for rows in caught.values() if rows)
    held = sum(1 for result in baseline.values() if result[0])
    unmoved = [row for row in findings if row["verdict"] != "caught"]
    lines = [
        "# Gate 1 sabotage report", "",
        f"Generated by `compose/sabotage.py` on {datetime.date.today()}.", "",
        f"**{proven} of {len(attacks)} C-ENG and C-OUT attacks were seen to fail with a defence removed.** "
        f"The baseline, on the same build with every switch off, held {held} of {len(attacks)}. "
        f"{len(findings) - len(unmoved)} of the {len(findings)} sabotage results were caught.", "",
        "The sabotage is in a temporary copy of the tree, under its own image tag. An attack is **caught** if the oracle "
        "saw a bypass or the attempt succeeded. **Refused elsewhere** means another guard stopped the call, so the attack "
        "never got past, and it does not count. **Survived** means it held with the defence gone.", "",
        "## By attack", "",
        "| Attack | Seen to fail under |", "|---|---|",
    ]
    for attack in attacks:
        names = "; ".join(sorted({row["label"] for row in caught[attack]})) or "**nothing yet**"
        lines.append(f"| {attack} | {names} |")
    lines += ["", "## Every run", "", "| Sabotage | Switches | Attack | Result | Detail |", "|---|---|---|---|---|"]
    for row in findings:
        detail = row["detail"].replace("|", "\\|")[:180]
        lines.append(f"| {row['label']} | `{','.join(row['switches'])}` | {row['attack']} | {row['verdict']} | {detail} |")
    with open(os.path.join(ROOT, REPORT), "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {REPORT}: {proven} of {len(attacks)} attacks caught, {len(unmoved)} results unmoved", flush=True)
    return proven == ALL_ATTACKS and not unmoved


def main():
    arguments = sys.argv[1:]
    only = arguments[arguments.index("--run") + 1] if "--run" in arguments else None
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    with tempfile.TemporaryDirectory(prefix="pep-sabotage-") as work:
        copy = os.path.join(work, "tree")
        shared = os.path.join(work, "shared-tmp")
        os.mkdir(shared)
        os.chmod(shared, 0o1777)
        prepare(copy)
        baseline = run_kit(copy, shared, [], list(GROUPS))
        held = sum(1 for result in baseline.values() if result[0])
        print(f"baseline: {held} of {len(baseline)} held, every switch off", flush=True)
        if len(baseline) != ALL_ATTACKS or held != ALL_ATTACKS:
            print(sorted(name for name, result in baseline.items() if not result[0]))
            raise SystemExit("the baseline did not hold, so nothing below would mean anything")
        findings = []
        for label, switches, attacks in RUNS:
            if only and only not in label:
                continue
            results = run_kit(copy, shared, switches, attacks)
            for attack in attacks:
                if attack not in results:
                    row = dict(label=label, switches=switches, attack=attack, verdict="did not run", detail="")
                else:
                    row = dict(label=label, switches=switches, attack=attack, verdict=verdict(*results[attack]),
                               detail=results[attack][1])
                findings.append(row)
                print(f"{row['verdict']:18} {label}: {attack}: {row['detail'][:140]}", flush=True)
    images = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, check=False)
    tagged = [image for image in images.stdout.split() if image.endswith(TAG)]
    subprocess.run(["docker", "image", "rm", "-f", *tagged], capture_output=True, check=False)   # so none can be run by mistake
    if only:
        return 0 if all(row["verdict"] == "caught" for row in findings) else 1   # a part proves nothing about the whole
    return 0 if write_report(baseline, findings) else 1


if __name__ == "__main__":
    sys.exit(main())
