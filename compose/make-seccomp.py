"""Writes seccomp-unix-only.json (WEEK2_PLAN §4, N1, RV4 #6) from Docker's default profile.

Usage: python3 compose/make-seccomp.py   (from the repository root)

The input is Docker Engine 29.9.2's default profile, the copy the engine vendors
(moby/moby, tag docker-v29.9.2, vendor/github.com/moby/profiles/seccomp/default.json), kept
in compose/ and checked by its SHA-256. The output is that profile with three changes:
- `socketcall` is removed, so the multiplexed socket entry point is gone (RV4 #6);
- `socket` is allowed for AF_UNIX (1) only; every other family gets EAFNOSUPPORT (97), so
  SDKs fail cleanly instead of being killed;
- x86_64 has no sub-architectures, so x86 (`int 0x80`) and x32 system calls are refused
  (RV4 #6).
Everything else, `io_uring_setup` refused included, is Docker's default.
"""
import hashlib, json, sys

SOURCE = "compose/seccomp-docker-default-v29.9.2.json"
SOURCE_SHA256 = "785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334"
OUTPUT = "seccomp-unix-only.json"
AF_UNIX = 1
EAFNOSUPPORT = 97

raw = open(SOURCE, "rb").read()
if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
    sys.exit(f"{SOURCE}: unexpected SHA-256")
profile = json.loads(raw)

for arch in profile["archMap"]:
    if arch["architecture"] == "SCMP_ARCH_X86_64":
        arch["subArchitectures"] = []

rules = []
for rule in profile["syscalls"]:
    names = [name for name in rule["names"] if name not in ("socketcall", "socket")]
    if not names:
        continue  # Docker's per-family `socket` rules
    rules.append(dict(rule, names=names))
rules.insert(1, {"names": ["socket"], "action": "SCMP_ACT_ALLOW",
                 "args": [{"index": 0, "value": AF_UNIX, "op": "SCMP_CMP_EQ"}]})
rules.insert(2, {"names": ["socket"], "action": "SCMP_ACT_ERRNO", "errnoRet": EAFNOSUPPORT,
                 "args": [{"index": 0, "value": AF_UNIX, "op": "SCMP_CMP_NE"}]})
profile["syscalls"] = rules

with open(OUTPUT, "w", newline="\n") as f:
    json.dump(profile, f, indent="\t")
    f.write("\n")
print(f"wrote {OUTPUT}: {len(rules)} rules")
