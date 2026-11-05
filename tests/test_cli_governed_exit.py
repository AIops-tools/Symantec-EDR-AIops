"""Governed CLI exits preserve error and unknown states."""

import pytest
import typer

from symantec_edr_aiops.cli import governed


def test_error_exits_one():
    with pytest.raises(typer.Exit) as exc:
        governed({"error": "permission denied"})
    assert exc.value.exit_code == 1


def test_unknown_exits_two_before_error():
    with pytest.raises(typer.Exit) as exc:
        governed({"outcomeUnknown": True, "error": "lost response"})
    assert exc.value.exit_code == 2
