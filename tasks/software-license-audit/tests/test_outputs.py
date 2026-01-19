import json
import os
import pytest
from openpyxl import load_workbook


class TestLicenseAuditReport:
    """Test suite for software license audit task."""

    def test_json_report_exists(self):
        """Verify that the JSON license report file exists."""
        assert os.path.exists("/root/license_audit_report.json"), \
            "License audit report JSON file not found at /root/license_audit_report.json"

    def test_excel_report_exists(self):
        """Verify that the Excel license report file exists."""
        assert os.path.exists("/root/license_audit_report.xlsx"), \
            "License audit report Excel file not found at /root/license_audit_report.xlsx"

    def test_json_report_structure(self):
        """Verify that the JSON report has the correct structure."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        # Check required top-level keys
        required_keys = ["summary", "violations", "dependencies", "timestamp", "policy_version"]
        for key in required_keys:
            assert key in report, f"Missing required key '{key}' in JSON report"

        # Check summary structure
        assert "total_dependencies" in report["summary"], \
            "Missing 'total_dependencies' in summary"
        assert "total_violations" in report["summary"], \
            "Missing 'total_violations' in summary"
        assert "violation_categories" in report["summary"], \
            "Missing 'violation_categories' in summary"

    def test_all_dependencies_analyzed(self):
        """Verify that all 109 dependencies from input have been analyzed."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        assert report["summary"]["total_dependencies"] == 109, \
            f"Expected 109 dependencies, found {report['summary']['total_dependencies']}"
        assert len(report["dependencies"]) == 109, \
            f"Expected 109 dependency entries, found {len(report['dependencies'])}"

    def test_runtime_violations_detected(self):
        """Verify that runtime license violations are correctly identified."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        runtime_violations = [v for v in report["violations"] if v["dependency_type"] == "runtime"]

        # Expected runtime violations based on policy
        # Note: elasticsearch has an exception so it won't be in violations
        expected_runtime_violations = [
            "tqdm",  # MPL-2.0 is restricted for runtime
            "phonemizer",  # GPL-3.0 is restricted for runtime
            "kenlm"  # LGPL-2.1 is restricted for runtime
        ]

        violation_names = [v["name"] for v in runtime_violations]
        for expected in expected_runtime_violations:
            assert expected in violation_names, \
                f"Expected runtime violation for '{expected}' not found"

    def test_development_violations_detected(self):
        """Verify that development license violations are correctly identified."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        dev_violations = [v for v in report["violations"] if v["dependency_type"] == "development"]

        # Elastic-2.0 is restricted for development
        expected_dev_violations = []  # Based on our policy, no dev violations expected

        assert len(dev_violations) == len(expected_dev_violations), \
            f"Expected {len(expected_dev_violations)} development violations, found {len(dev_violations)}"

    def test_violation_details(self):
        """Verify that each violation contains required details."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        for violation in report["violations"]:
            assert "name" in violation, "Violation missing 'name'"
            assert "version" in violation, "Violation missing 'version'"
            assert "license" in violation, "Violation missing 'license'"
            assert "dependency_type" in violation, "Violation missing 'dependency_type'"
            assert "violation_type" in violation, "Violation missing 'violation_type'"
            assert violation["violation_type"] in ["restricted", "prohibited"], \
                f"Invalid violation_type: {violation['violation_type']}"

    def test_exception_handling(self):
        """Verify that elasticsearch exception is properly noted."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        elasticsearch_entry = next(
            (d for d in report["dependencies"] if d["name"] == "elasticsearch"),
            None
        )

        assert elasticsearch_entry is not None, "Elasticsearch not found in dependencies"
        assert "exception" in elasticsearch_entry or \
               any(v["name"] == "elasticsearch" and "exception_note" in v
                   for v in report["violations"]), \
            "Elasticsearch exception not properly documented"

    def test_excel_report_sheets(self):
        """Verify that the Excel report contains required sheets."""
        wb = load_workbook("/root/license_audit_report.xlsx")

        required_sheets = ["Summary", "Violations"]
        for sheet in required_sheets:
            assert sheet in wb.sheetnames, f"Missing required sheet '{sheet}' in Excel report"

    def test_excel_summary_sheet(self):
        """Verify the content of the Excel summary sheet."""
        wb = load_workbook("/root/license_audit_report.xlsx")
        summary_sheet = wb["Summary"]

        # Check that summary statistics are present
        cells = [[cell.value for cell in row] for row in summary_sheet.iter_rows()]
        flat_values = [val for row in cells for val in row if val is not None]

        # Should contain total dependencies count (109)
        assert 109 in flat_values or "109" in [str(v) for v in flat_values], \
            "Total dependencies count (109) not found in Summary sheet"

    def test_excel_violations_sheet(self):
        """Verify the Violations sheet contains the correct violations."""
        wb = load_workbook("/root/license_audit_report.xlsx")
        violations_sheet = wb["Violations"]

        # Check headers
        headers = [cell.value for cell in violations_sheet[1]]
        expected_headers = ["Package", "Version", "License", "Type", "Violation", "Notes"]

        for header in expected_headers:
            assert header in headers or any(h and header.lower() in h.lower() for h in headers if h), \
                f"Expected header '{header}' not found in Violations sheet"


    def test_violation_count_accuracy(self):
        """Verify that the violation count matches the actual violations."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        actual_violations = len(report["violations"])
        reported_violations = report["summary"]["total_violations"]

        assert actual_violations == reported_violations, \
            f"Violation count mismatch: summary reports {reported_violations}, but found {actual_violations} violations"

    def test_license_categorization(self):
        """Verify that licenses are correctly categorized."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        categories = report["summary"]["violation_categories"]

        assert "restricted" in categories, "Missing 'restricted' category in summary"
        assert "prohibited" in categories, "Missing 'prohibited' category in summary"

        # Count actual violations by type
        restricted_count = len([v for v in report["violations"] if v["violation_type"] == "restricted"])
        prohibited_count = len([v for v in report["violations"] if v["violation_type"] == "prohibited"])

        assert categories["restricted"] == restricted_count, \
            f"Restricted count mismatch: reported {categories['restricted']}, actual {restricted_count}"
        assert categories["prohibited"] == prohibited_count, \
            f"Prohibited count mismatch: reported {categories['prohibited']}, actual {prohibited_count}"

    def test_timestamp_present(self):
        """Verify that the report includes a timestamp."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        assert "timestamp" in report, "Missing timestamp in report"
        assert report["timestamp"] != "", "Timestamp is empty"

    def test_policy_version_tracked(self):
        """Verify that the policy version is included in the report."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        assert "policy_version" in report, "Missing policy_version in report"
        assert report["policy_version"] == "2.0", \
            f"Expected policy version 2.0, found {report['policy_version']}"