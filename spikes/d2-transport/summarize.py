import json, sys
for l in open(sys.argv[1]):
    e = json.loads(l)
    k = e["kind"]
    if k == "request":
        tag = "notification" if e["id"] is None else f"id={e['id']}"
        extra = f" params={json.dumps({x: y for x, y in (e['params'] or {}).items() if x != '_meta'})}" if e["id"] is None else ""
        print(f"   {e['method']} {tag}{extra}")
    elif k == "m1-check": print(f"      M1 check on {e['method']}: {e['problems']}")
    elif k == "http": print(f"   {e['verb']} (legacy) -> 405")
    else: print(f"   [{k}] {e.get('method', '')} {e.get('id', '')} {e.get('variant', '')}")
