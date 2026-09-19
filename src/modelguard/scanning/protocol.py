"""Scanner plugin interface.

Every scanner ModelGuard runs -- built-in or third-party -- implements
this ``Protocol``, per the architecture document's plugin-based
scanner architecture. Defined as a ``Protocol`` rather than an ABC so
a third-party scanner needs no ModelGuard base class or import-time
dependency to be usable; it only has to match this shape.

The single hard rule, restated here because it is the most important
security property of the whole scanning subsystem: a scanner inspects
bytes and already-parsed metadata only. It must never execute, import,
or deserialize anything from the artifact it is scanning. A scanner
that needs to know "is this a pickle file" sniffs magic bytes; it does
not call ``pickle.load`` to find out.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.scanning.models import Finding


class Scanner(Protocol):
    """A pluggable artifact scanner.

    Implementations MUST NOT execute, import, unpickle, or otherwise
    deserialize any content read from ``artifact_path``. Scanning is
    limited to reading raw bytes, checking file extensions and magic
    numbers, and inspecting already-parsed ``Manifest``/``MLBOM``
    metadata that was validated upstream by Pydantic, never by
    re-running the artifact's own code.
    """

    @property
    def name(self) -> str:
        """A short, stable identifier used in ``ScanReport.scanner_statuses``
        and in each ``Finding.scanner`` this scanner produces.
        """
        ...

    def scan(
        self,
        artifact_path: Path,
        manifest: Manifest | None,
        mbom: MLBOM | None,
    ) -> list[Finding]:
        """Scan ``artifact_path`` and return zero or more findings.

        ``manifest``/``mbom`` are the already-built, already-validated
        documents for this artifact, if the caller has them -- pass
        ``None`` when unavailable rather than a placeholder object.
        Raising is allowed and expected for genuinely unexpected
        failures (e.g. the filesystem disappearing mid-scan);
        ``modelguard.scanning.run_scanners`` isolates each scanner so
        one raising scanner does not abort the others.
        """
        ...
