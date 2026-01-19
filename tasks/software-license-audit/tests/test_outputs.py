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
        """Verify that all dependencies from input have been analyzed."""
        # Load input to get expected count
        with open("/root/project_dependencies.json", "r") as f:
            input_data = json.load(f)
        expected_count = len(input_data["dependencies"])

        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        assert report["summary"]["total_dependencies"] == expected_count, \
            f"Expected {expected_count} dependencies, found {report['summary']['total_dependencies']}"
        assert len(report["dependencies"]) == expected_count, \
            f"Expected {expected_count} dependency entries, found {len(report['dependencies'])}"

    def test_runtime_violations_detected(self):
        """Verify that runtime license violations are correctly identified."""
        # Load input and policy to determine expected violations
        with open("/root/project_dependencies.json", "r") as f:
            input_data = json.load(f)
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)

        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        runtime_violations = [v for v in report["violations"] if v["dependency_type"] == "runtime"]

        # Verify each violation is actually a policy violation
        for violation in runtime_violations:
            dep = next((d for d in input_data["dependencies"]
                       if d["name"] == violation["name"]), None)
            assert dep is not None, f"Violation {violation['name']} not found in input"

            # Check if it's in restricted or prohibited lists
            is_violation = (violation["license"] in policy.get("restricted_licenses", {}).get("runtime", []) or
                          violation["license"] in policy.get("prohibited_licenses", {}).get("runtime", []))
            assert is_violation, f"{violation['name']} with {violation['license']} is not actually a violation"

    def test_development_violations_detected(self):
        """Verify that development license violations are correctly identified."""
        with open("/root/project_dependencies.json", "r") as f:
            input_data = json.load(f)
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        dev_violations = [v for v in report["violations"] if v["dependency_type"] == "development"]

        # Verify each dev violation is actually a policy violation
        for violation in dev_violations:
            dep = next((d for d in input_data["dependencies"]
                       if d["name"] == violation["name"] and d["type"] == "development"), None)
            assert dep is not None, f"Development violation {violation['name']} not found in input"

            # Check if it's in restricted or prohibited lists for development
            is_violation = (violation["license"] in policy.get("restricted_licenses", {}).get("development", []) or
                          violation["license"] in policy.get("prohibited_licenses", {}).get("development", []))

            # Also check if it has an exception
            has_exception = any(e["package"] == violation["name"] for e in policy.get("exceptions", []))

            assert is_violation or has_exception, \
                f"{violation['name']} with {violation['license']} is not actually a development violation"

    def test_violation_details(self):
        """Verify that each violation contains required details."""
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)
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

            # Check exception_note is only present when exception was applied
            has_exception = any(e["package"] == violation["name"] for e in policy.get("exceptions", []))
            if has_exception:
                # If there's an exception, exception_note is optional but allowed
                if "exception_note" in violation:
                    assert isinstance(violation["exception_note"], str), \
                        f"exception_note must be string for {violation['name']}"

    def test_exception_handling(self):
        """Verify that exceptions from policy are properly applied."""
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        # Check if policy has exceptions
        if "exceptions" in policy and len(policy["exceptions"]) > 0:
            # For each exception in policy, verify it's handled correctly
            for exception in policy["exceptions"]:
                pkg_name = exception["package"]
                dep_entry = next(
                    (d for d in report["dependencies"] if d["name"] == pkg_name),
                    None
                )

                if dep_entry:  # Only check if the package exists in dependencies
                    assert dep_entry["exception"] == True, \
                        f"Package {pkg_name} should have exception=True"
                    assert "exception_reason" in dep_entry, \
                        f"Package {pkg_name} with exception should have exception_reason"

    def test_excel_report_sheets(self):
        """Verify that the Excel report contains required sheets."""
        wb = load_workbook("/root/license_audit_report.xlsx")

        required_sheets = ["Summary", "Violations"]
        for sheet in required_sheets:
            assert sheet in wb.sheetnames, f"Missing required sheet '{sheet}' in Excel report"

    def test_excel_summary_sheet(self):
        """Verify the content and layout of the Excel summary sheet."""
        wb = load_workbook("/root/license_audit_report.xlsx")
        summary_sheet = wb["Summary"]

        # Check the two-column layout as specified in instruction.md
        # First column should contain labels, second column should contain values
        expected_labels = [
            "License Audit Report",
            "Report Generated",
            "Policy Version",
            "Summary Statistics",
            "Total Dependencies",
            "Total Violations",
            "Restricted License Violations",
            "Prohibited License Violations"
        ]

        # Get all cells as a 2D array
        cells = [[cell.value for cell in row] for row in summary_sheet.iter_rows()]

        # Check that expected labels are in the first column
        first_col_values = [row[0] if row else None for row in cells if row]
        for label in expected_labels:
            assert label in first_col_values, \
                f"Expected label '{label}' not found in first column of Summary sheet"

        # Verify two-column layout structure: labels in col A, values in col B
        # Find the key metric rows and verify they have corresponding values
        value_labels = ["Total Dependencies", "Total Violations",
                       "Restricted License Violations", "Prohibited License Violations",
                       "Report Generated", "Policy Version"]

        for i, row in enumerate(cells):
            if row and len(row) > 0 and row[0] in value_labels:
                assert len(row) > 1, f"Row {i+1} with label '{row[0]}' missing value in column B"
                assert row[1] is not None, f"Row {i+1} with label '{row[0]}' has None value in column B"

                # Verify type constraints for numeric fields
                if row[0] in ["Total Dependencies", "Total Violations",
                             "Restricted License Violations", "Prohibited License Violations"]:
                    assert isinstance(row[1], (int, float)), \
                        f"Row {i+1} with label '{row[0]}' should have numeric value, got {type(row[1])}"

        # Verify that data is consistent with JSON report
        with open("/root/license_audit_report.json", "r") as f:
            json_report = json.load(f)

        # Check total dependencies count matches
        flat_values = [val for row in cells for val in row if val is not None]
        expected_count = json_report["summary"]["total_dependencies"]
        assert expected_count in flat_values or str(expected_count) in [str(v) for v in flat_values], \
            f"Total dependencies count ({expected_count}) not found in Summary sheet"

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

        # Validate type constraints: counts should be integers
        assert isinstance(categories["restricted"], int), \
            f"Restricted count should be integer, got {type(categories['restricted'])}"
        assert isinstance(categories["prohibited"], int), \
            f"Prohibited count should be integer, got {type(categories['prohibited'])}"

        # Count actual violations by type
        restricted_count = len([v for v in report["violations"] if v["violation_type"] == "restricted"])
        prohibited_count = len([v for v in report["violations"] if v["violation_type"] == "prohibited"])

        assert categories["restricted"] == restricted_count, \
            f"Restricted count mismatch: reported {categories['restricted']}, actual {restricted_count}"
        assert categories["prohibited"] == prohibited_count, \
            f"Prohibited count mismatch: reported {categories['prohibited']}, actual {prohibited_count}"

    def test_dependency_schema_validation(self):
        """Verify that each dependency in the report follows the required schema."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        for dep in report["dependencies"]:
            # Check required fields
            assert "name" in dep, f"Missing 'name' in dependency: {dep}"
            assert "version" in dep, f"Missing 'version' in dependency: {dep}"
            assert "license" in dep, f"Missing 'license' in dependency: {dep}"
            assert "type" in dep, f"Missing 'type' in dependency: {dep}"
            assert "compliant" in dep, f"Missing 'compliant' in dependency: {dep}"
            assert "exception" in dep, f"Missing 'exception' in dependency: {dep}"

            # Check field types
            assert isinstance(dep["name"], str), f"'name' must be string in {dep['name']}"
            assert isinstance(dep["version"], str), f"'version' must be string in {dep['name']}"
            assert isinstance(dep["license"], str), f"'license' must be string in {dep['name']}"
            assert dep["type"] in ["runtime", "development"], f"Invalid type '{dep['type']}' in {dep['name']}"
            assert isinstance(dep["compliant"], bool), f"'compliant' must be bool in {dep['name']}"
            assert isinstance(dep["exception"], bool), f"'exception' must be bool in {dep['name']}"

            # Check exception_reason only exists when exception is True
            if dep["exception"]:
                assert "exception_reason" in dep, f"Missing 'exception_reason' when exception=True in {dep['name']}"
                assert isinstance(dep["exception_reason"], str), f"'exception_reason' must be string in {dep['name']}"
            else:
                assert "exception_reason" not in dep, \
                    f"'exception_reason' must NOT exist when exception=False in {dep['name']}"

    def test_timestamp_present(self):
        """Verify that the report includes a valid ISO8601 timestamp."""
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        assert "timestamp" in report, "Missing timestamp in report"
        assert report["timestamp"] != "", "Timestamp is empty"

        # Validate ISO8601 format
        import re
        iso8601_pattern = r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)?$'
        assert re.match(iso8601_pattern, report["timestamp"]), \
            f"Timestamp '{report['timestamp']}' is not in valid ISO8601 format"

    def test_dual_license_handling(self):
        """Verify that dual licenses are handled according to policy."""
        with open("/root/project_dependencies.json", "r") as f:
            input_data = json.load(f)
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        # Verify dual license handling policy exists
        assert "dual_license_handling" in policy, "Policy must specify dual_license_handling"

        # Check for any dual licenses in input
        dual_license_deps = [dep for dep in input_data["dependencies"] if " OR " in dep.get("license", "")]

        if dual_license_deps:
            # If dual licenses exist, verify they follow the policy handling
            handling_policy = policy.get("dual_license_handling", "most_permissive")

            for input_dep in dual_license_deps:
                report_dep = next(
                    (d for d in report["dependencies"] if d["name"] == input_dep["name"]),
                    None
                )
                assert report_dep is not None, f"Dual license dependency {input_dep['name']} not found in report"

                # For "most_permissive" policy, verify that the most permissive license is used
                if handling_policy == "most_permissive":
                    licenses = [lic.strip() for lic in input_dep["license"].split(" OR ")]
                    dep_type = input_dep["type"]

                    # Find the most permissive license (first one that's allowed, if any)
                    allowed_licenses = policy["allowed_licenses"].get(dep_type, [])
                    most_permissive = None
                    for lic in licenses:
                        if lic in allowed_licenses:
                            most_permissive = lic
                            break

                    # If no allowed license found, use first license for evaluation
                    effective_license = most_permissive if most_permissive else licenses[0]

                    # The compliant status should reflect the effective license evaluation
                    has_exception = report_dep.get("exception", False)
                    is_violation = (
                        effective_license in policy.get("restricted_licenses", {}).get(dep_type, []) or
                        effective_license in policy.get("prohibited_licenses", {}).get(dep_type, [])
                    )
                    expected_compliant = has_exception or not is_violation

                    assert report_dep["compliant"] == expected_compliant, \
                        f"Dual license {input_dep['name']} compliant status incorrect. " \
                        f"License: {input_dep['license']}, Effective: {effective_license}, " \
                        f"Expected compliant: {expected_compliant}, Got: {report_dep['compliant']}"
        else:
            # If no dual licenses exist in data, verify policy is ready to handle them
            assert policy.get("dual_license_handling") == "most_permissive", \
                "Policy should specify dual_license_handling='most_permissive' for future dual license support"

    def test_compliant_flag_consistency(self):
        """Verify that compliant flags are consistent with policy and exceptions."""
        with open("/root/project_dependencies.json", "r") as f:
            input_data = json.load(f)
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        for dep in report["dependencies"]:
            # Find original input dependency
            input_dep = next(
                (d for d in input_data["dependencies"] if d["name"] == dep["name"]),
                None
            )
            assert input_dep is not None, f"Dependency {dep['name']} not found in input"

            dep_type = dep["type"]
            license_name = dep["license"]
            has_exception = dep.get("exception", False)

            # Handle dual licenses if present
            effective_license = license_name
            if " OR " in license_name and policy.get("dual_license_handling") == "most_permissive":
                licenses = license_name.split(" OR ")
                allowed_licenses = policy["allowed_licenses"].get(dep_type, [])
                for lic in licenses:
                    if lic.strip() in allowed_licenses:
                        effective_license = lic.strip()
                        break

            # Check if license violates policy
            is_violation = (
                effective_license in policy.get("restricted_licenses", {}).get(dep_type, []) or
                effective_license in policy.get("prohibited_licenses", {}).get(dep_type, [])
            )

            # If there's an exception, dependency should be compliant regardless of violation
            # If no exception and no violation, should be compliant
            # If no exception but has violation, should NOT be compliant
            expected_compliant = has_exception or not is_violation

            assert dep["compliant"] == expected_compliant, \
                f"Dependency {dep['name']}: compliant={dep['compliant']}, expected={expected_compliant} " \
                f"(exception={has_exception}, violation={is_violation}, license={effective_license})"

    def test_exception_note_in_violations(self):
        """Verify that violations with exceptions have exception_note."""
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        # Get packages with exceptions
        exception_packages = {e["package"] for e in policy.get("exceptions", [])}

        for violation in report["violations"]:
            # If this violation is for a package with an exception, it should have exception_note
            if violation["name"] in exception_packages:
                assert "exception_note" in violation, \
                    f"Violation for {violation['name']} should have exception_note since it has an exception"
                assert isinstance(violation["exception_note"], str), \
                    f"exception_note for {violation['name']} should be a string"
                assert violation["exception_note"].strip() != "", \
                    f"exception_note for {violation['name']} should not be empty"

    def test_violation_type_accuracy(self):
        """Verify that violation_type correctly reflects license category."""
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)
        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        for violation in report["violations"]:
            license_name = violation["license"]
            dep_type = violation["dependency_type"]
            violation_type = violation["violation_type"]

            # Check if the license is in restricted or prohibited lists
            restricted_licenses = policy.get("restricted_licenses", {}).get(dep_type, [])
            prohibited_licenses = policy.get("prohibited_licenses", {}).get(dep_type, [])

            if license_name in restricted_licenses:
                assert violation_type == "restricted", \
                    f"License {license_name} is in restricted list but violation_type is {violation_type}"
            elif license_name in prohibited_licenses:
                assert violation_type == "prohibited", \
                    f"License {license_name} is in prohibited list but violation_type is {violation_type}"
            else:
                # This shouldn't happen - every violation should match a policy list
                assert False, f"Violation {violation['name']} has license {license_name} not found in policy lists"

    def test_policy_version_tracked(self):
        """Verify that the policy version is included in the report."""
        with open("/root/license_policy.json", "r") as f:
            policy = json.load(f)
        expected_version = policy["policy_version"]

        with open("/root/license_audit_report.json", "r") as f:
            report = json.load(f)

        assert "policy_version" in report, "Missing policy_version in report"
        assert report["policy_version"] == expected_version, \
            f"Expected policy version {expected_version}, found {report['policy_version']}"