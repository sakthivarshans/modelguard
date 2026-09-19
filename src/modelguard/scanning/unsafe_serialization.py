"""Unsafe-serialization scanner.

Flags files that use pickle-based serialization formats, which can
execute arbitrary code during deserialization (``pickle.load``,
``torch.load`` with the default pickle-based loader, ``joblib.load``,
``dill.load``). This scanner NEVER unpickles anything: it only checks
file extensions and the first few bytes of each file. Detecting
"this file's opcodes construct a dangerous object" would require
actually parsing (and is not far from executing) the pickle stream --
that is out of scope here. See ``docs/limitations.md``.
"""

from __future__ import annotations

from pathlib import Path

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.scanning._walk import ScannableFile, iter_scannable_files
from modelguard.scanning.models import Confidence, Finding, Severity

# Extensions used by common pickle-based ML serialization formats.
# torch.save()'s default format (.pt/.pth/.ckpt) is a zip container
# whose payload is pickle, even though the outer container is not.
_PICKLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib", ".dill"})

# The first two bytes of a pickle stream using protocol 2+: the PROTO
# opcode (0x80) followed by a protocol-version byte in 0..5. Pickle
# protocol 0/1 has no such marker and is not detected by this sniff --
# documented explicitly rather than silently missed.
_PICKLE_PROTO_OPCODE = 0x80
_MAX_KNOWN_PICKLE_PROTOCOL = 5
_SNIFF_BYTES = 8


def _looks_like_pickle_header(prefix: bytes) -> bool:
    return (
        len(prefix) >= 2
        and prefix[0] == _PICKLE_PROTO_OPCODE
        and prefix[1] <= _MAX_KNOWN_PICKLE_PROTOCOL
    )


class UnsafeSerializationScanner:
    """Flags pickle-based (or pickle-like) files as unsafe to deserialize."""

    name = "unsafe_serialization"

    def scan(
        self, artifact_path: Path, manifest: Manifest | None, mbom: MLBOM | None
    ) -> list[Finding]:
        findings: list[Finding] = []
        for item in iter_scannable_files(artifact_path, self.name):
            if isinstance(item, Finding):
                findings.append(item)
                continue
            findings.extend(self._scan_file(item))
        return findings

    def _scan_file(self, file: ScannableFile) -> list[Finding]:
        extension = Path(file.relative_path).suffix.lower()
        if extension in _PICKLE_EXTENSIONS:
            return [
                Finding(
                    scanner=self.name,
                    category="unsafe_deserialization",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    component=file.relative_path,
                    message=(
                        f"File extension {extension!r} is associated with pickle-based "
                        "serialization, which can execute arbitrary code during loading."
                    ),
                    remediation=(
                        "Prefer a safe format such as SafeTensors. If this file must "
                        "remain pickle-based, only ever load it in an isolated, "
                        "untrusted-input-aware environment."
                    ),
                    evidence=f"extension={extension}",
                )
            ]

        try:
            with file.absolute_path.open("rb") as fh:
                prefix = fh.read(_SNIFF_BYTES)
        except OSError:
            # Unreadable file: report nothing rather than guessing. A
            # scanner reporting a false "clean" here would be worse
            # than silence, but so would inventing a finding about
            # content it never actually read.
            return []

        if _looks_like_pickle_header(prefix):
            return [
                Finding(
                    scanner=self.name,
                    category="unsafe_deserialization",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    component=file.relative_path,
                    message=(
                        "File begins with a pickle protocol header (opcode 0x80) despite "
                        "an extension not normally associated with pickle; it may be "
                        "pickle-based serialization under a misleading name."
                    ),
                    remediation=(
                        "Confirm the actual format of this file before loading it. If it "
                        "is pickle-based, treat it with the same caution as a .pkl file."
                    ),
                    evidence=f"header_bytes={prefix[:2].hex()}",
                )
            ]

        return []
