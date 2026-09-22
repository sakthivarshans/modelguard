"""ModelGuard: an open-source framework for AI/ML model supply-chain security.

Phase 1 scope: local artifact inspection, deterministic hashing,
canonical manifests, ML-BOM generation, and local Ed25519 signing and
verification. See docs/limitations.md for what is explicitly not yet
implemented.
"""

from modelguard.exceptions import ModelGuardError, VerificationDenied
from modelguard.sdk import ModelGuard, VerificationResult

__version__ = "0.7.0"

__all__ = [
    "ModelGuard",
    "ModelGuardError",
    "VerificationDenied",
    "VerificationResult",
    "__version__",
]
