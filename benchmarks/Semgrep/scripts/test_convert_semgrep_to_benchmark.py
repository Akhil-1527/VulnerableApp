"""
test_convert_semgrep_to_benchmark.py
====================================
Unit tests for the Semgrep to benchmark conversion script.

Run:
    python3 -m pytest benchmarks/Semgrep/scripts/test_convert_semgrep_to_benchmark.py -v
    # or from repo root:
    python3 -m pytest benchmarks/Semgrep/scripts/ -v
"""

import sys
import os
import json
import subprocess
from pathlib import Path

import pytest
sys.path.insert(0, os.path.dirname(__file__))

from convert_semgrep_to_benchmark import convert, _cwe_tag

SQLI_CWE = "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
PATH = "src/main/java/org/sasanlabs/service/vulnerability/sqlInjection/ErrorBasedSQLInjectionVulnerability.java"


def _result(path=PATH, line=143, cwe=None, vulnerability_class=None) -> dict:
    metadata = {}
    if cwe is not None:
        metadata["cwe"] = cwe
    if vulnerability_class is not None:
        metadata["vulnerability_class"] = vulnerability_class
    return {
        "check_id": "java.lang.security.audit.tainted-sql-string.tainted-sql-string",
        "path": path,
        "start": {"line": line, "col": 21},
        "end": {"line": line, "col": 60},
        "extra": {"metadata": metadata},
    }


def test_cwe_tag_strips_the_description():
    assert _cwe_tag([SQLI_CWE]) == "CWE-89"


def test_cwe_tag_accepts_a_plain_string():
    assert _cwe_tag(SQLI_CWE) == "CWE-89"


def test_cwe_tag_returns_none_without_a_cwe():
    assert _cwe_tag(None) is None
    assert _cwe_tag([]) is None
    assert _cwe_tag("no id here") is None


def test_convert_maps_a_result_to_a_sast_finding():
    report = {"results": [_result(cwe=[SQLI_CWE], vulnerability_class=["SQL Injection"])]}
    assert convert(report) == {
        "tool": "Semgrep",
        "scanType": "SAST",
        "findings": [
            {"filePath": PATH, "line": 143, "cwe": "CWE-89", "type": "SQL Injection"}
        ],
    }


def test_convert_rejects_findings_without_a_matching_taxonomy():
    with pytest.raises(ValueError, match="custom.rule.*no CWE or vulnerability_class"):
        result = _result()
        result["check_id"] = "custom.rule"
        convert({"results": [result]})


def test_convert_accepts_type_only_findings():
    assert convert({"results": [_result(vulnerability_class="SQL Injection")]})["findings"] == [
        {"filePath": PATH, "line": 143, "type": "SQL Injection"}
    ]


def test_cli_rejects_unscorable_findings_without_overwriting_output(tmp_path):
    report = tmp_path / "report.json"
    output = tmp_path / "findings.json"
    report.write_text(json.dumps({"results": [_result()]}))
    output.write_text("previous findings")
    process = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("convert_semgrep_to_benchmark.py")),
         "--input", str(report), "--output", str(output)],
        capture_output=True, text=True,
    )
    assert process.returncode != 0
    assert "no CWE or vulnerability_class" in process.stderr
    assert output.read_text() == "previous findings"


def test_convert_deduplicates_identical_findings():
    result = _result(cwe=[SQLI_CWE])
    assert len(convert({"results": [result, result]})["findings"]) == 1


def test_convert_keeps_findings_on_different_lines():
    report = {"results": [_result(line=83, cwe=[SQLI_CWE]), _result(line=143, cwe=[SQLI_CWE])]}
    assert [f["line"] for f in convert(report)["findings"]] == [83, 143]


def test_convert_skips_results_without_a_location():
    assert convert({"results": [{"extra": {}}]})["findings"] == []


def test_convert_handles_an_empty_report():
    assert convert({})["findings"] == []
