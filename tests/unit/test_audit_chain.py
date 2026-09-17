from __future__ import annotations

import json
from pathlib import Path

import pytest

from modelguard.audit.chain import ChainIntegrityError, append_entry, read_all_entries, verify_chain


def test_append_and_read_round_trips(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    append_entry(log, {"msg": "first"})
    append_entry(log, {"msg": "second"})

    entries = read_all_entries(log)
    assert [e.record["msg"] for e in entries] == ["first", "second"]
    assert entries[0].index == 0
    assert entries[1].index == 1


def test_chain_links_consecutive_entries(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    append_entry(log, {"msg": "first"})
    append_entry(log, {"msg": "second"})

    entries = read_all_entries(log)
    assert entries[1].prev_hash == entries[0].record_hash


def test_verify_chain_passes_for_untampered_log(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    for i in range(5):
        append_entry(log, {"msg": f"entry-{i}"})

    verify_chain(log)  # must not raise


def test_verify_chain_empty_log_passes(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    verify_chain(log)  # no file at all -- trivially valid


def test_editing_a_record_in_place_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    append_entry(log, {"msg": "first"})
    append_entry(log, {"msg": "second"})

    lines = log.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["record"]["msg"] = "TAMPERED"
    lines[0] = json.dumps(tampered)
    log.write_text("\n".join(lines) + "\n")

    with pytest.raises(ChainIntegrityError):
        verify_chain(log)


def test_deleting_a_middle_record_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    for i in range(4):
        append_entry(log, {"msg": f"entry-{i}"})

    lines = log.read_text().splitlines()
    del lines[1]  # remove the second entry, breaking the chain
    log.write_text("\n".join(lines) + "\n")

    with pytest.raises(ChainIntegrityError):
        verify_chain(log)


def test_reordering_records_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    for i in range(3):
        append_entry(log, {"msg": f"entry-{i}"})

    lines = log.read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    log.write_text("\n".join(lines) + "\n")

    with pytest.raises(ChainIntegrityError):
        verify_chain(log)
