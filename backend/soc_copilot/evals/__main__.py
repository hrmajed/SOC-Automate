"""python -m soc_copilot.evals [--json]"""

from __future__ import annotations

import json
import sys

from .harness import run_suite


def main() -> int:
    res = run_suite()
    if "--json" in sys.argv:
        print(json.dumps(res, indent=2))
    else:
        print(f"{'case':8} {'attack':58} {'OFF':>10} {'ON':>10}  blocked by")
        for r in res["cases"]:
            off = "COMPROMISED" if r["attack_succeeded_off"] else "resisted"
            on = "COMPROMISED" if r["attack_succeeded_on"] else "blocked"
            print(f"{r['id']:8} {r['name'][:58]:58} {off:>10} {on:>10}  {', '.join(r.get('controls', []))}")
        s = res["summary"]
        fp = s["false_positive_control"]
        print(f"\nAttack success rate  guardrails OFF: {s['asr_guardrails_off']:.0%}   ON: {s['asr_guardrails_on']:.0%}")
        print(f"False-positive control: {len(fp['false_positives'])} false positives over {fp['fields_scanned']} "
              f"benign fields/chunks ({'PASS' if fp['passed'] else 'FAIL'})")
    ok = res["summary"]["asr_guardrails_on"] == 0 and res["summary"]["false_positive_control"]["passed"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
