"""Minimal deployment gate built on ``modelguard.admission.admit``.

Run it from a deploy job or wrapper script; it exits 0 only if the
artifact is admitted. It does not deploy anything itself -- your
deployment tooling must refuse to proceed on a non-zero exit.

    python deploy_gate.py MODEL_DIR MBOM SIGNATURE POLICY \\
        --trusted-fingerprint <sha256> --actor deploy-bot \\
        --audit-log /var/lib/modelguard/admission.jsonl

Prefer supplying the fingerprint and policy from deployment
configuration your artifact supplier cannot modify.
"""

from __future__ import annotations

import argparse
import sys

from modelguard import ModelGuard
from modelguard.admission import admit


def main() -> int:
    parser = argparse.ArgumentParser(description="ModelGuard deployment admission gate")
    parser.add_argument("artifact")
    parser.add_argument("mbom")
    parser.add_argument("signature")
    parser.add_argument("policy")
    parser.add_argument("--trusted-fingerprint", action="append", default=[])
    parser.add_argument("--actor", required=True)
    parser.add_argument("--audit-log")
    parser.add_argument("--cache-dir")
    args = parser.parse_args()

    guard = ModelGuard(
        cache_dir=args.cache_dir,
        trusted_key_fingerprints=args.trusted_fingerprint or None,
    )
    decision = admit(
        guard,
        args.artifact,
        args.mbom,
        args.signature,
        args.policy,
        actor=args.actor,
        audit_log_path=args.audit_log,
    )

    if decision.admitted:
        print(f"ADMITTED {decision.subject} {decision.artifact_digest}")
        if not decision.revocation_checked:
            print("note: revocation was NOT checked (no registry configured)", file=sys.stderr)
        return 0

    print("BLOCKED", file=sys.stderr)
    for reason in decision.reasons:
        print(f"  - {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
