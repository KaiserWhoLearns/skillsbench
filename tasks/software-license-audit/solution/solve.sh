#!/bin/bash
set -e

python3 << 'EOF'
import json
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment

# Load input files
with open("/root/project_dependencies.json", "r") as f:
    dependencies_data = json.load(f)

with open("/root/license_policy.json", "r") as f:
    policy = json.load(f)

# Initialize report structure
report = {
    "timestamp": datetime.now().isoformat(),
    "policy_version": policy["policy_version"],
    "summary": {
        "total_dependencies": 0,
        "total_violations": 0,
        "violation_categories": {
            "restricted": 0,
            "prohibited": 0
        }
    },
    "violations": [],
    "dependencies": []
}

# Process each dependency
for dep in dependencies_data["dependencies"]:
    dep_type = dep["type"]
    license_name = dep["license"]

    # Check for violations
    violation_type = None

    if license_name in policy["prohibited_licenses"][dep_type]:
        violation_type = "prohibited"
    elif license_name in policy["restricted_licenses"][dep_type]:
        violation_type = "restricted"

    # Add to dependencies list
    dep_entry = {
        "name": dep["name"],
        "version": dep["version"],
        "license": dep["license"],
        "type": dep_type,
        "compliant": violation_type is None
    }

    report["dependencies"].append(dep_entry)

    # Add to violations if needed
    if violation_type:
        violation = {
            "name": dep["name"],
            "version": dep["version"],
            "license": dep["license"],
            "dependency_type": dep_type,
            "violation_type": violation_type
        }

        report["violations"].append(violation)
        report["summary"]["violation_categories"][violation_type] += 1

# Update summary
report["summary"]["total_dependencies"] = len(dependencies_data["dependencies"])
report["summary"]["total_violations"] = len(report["violations"])

# Save JSON report
with open("/root/license_audit_report.json", "w") as f:
    json.dump(report, f, indent=2)

# Create Excel report
wb = Workbook()

# Summary Sheet
summary_sheet = wb.active
summary_sheet.title = "Summary"

# Add headers with formatting
header_font = Font(bold=True, size=14)
subheader_font = Font(bold=True, size=12)
header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
header_align = Alignment(horizontal="center", vertical="center")

summary_sheet["A1"] = "License Audit Report"
summary_sheet["A1"].font = Font(bold=True, size=16)
summary_sheet.merge_cells("A1:B1")

summary_sheet["A3"] = "Report Generated"
summary_sheet["B3"] = report["timestamp"]

summary_sheet["A4"] = "Policy Version"
summary_sheet["B4"] = report["policy_version"]

summary_sheet["A6"] = "Summary Statistics"
summary_sheet["A6"].font = subheader_font
summary_sheet.merge_cells("A6:B6")

summary_sheet["A7"] = "Total Dependencies"
summary_sheet["B7"] = report["summary"]["total_dependencies"]

summary_sheet["A8"] = "Total Violations"
summary_sheet["B8"] = report["summary"]["total_violations"]

summary_sheet["A9"] = "Restricted License Violations"
summary_sheet["B9"] = report["summary"]["violation_categories"]["restricted"]

summary_sheet["A10"] = "Prohibited License Violations"
summary_sheet["B10"] = report["summary"]["violation_categories"]["prohibited"]

# Adjust column widths
summary_sheet.column_dimensions["A"].width = 30
summary_sheet.column_dimensions["B"].width = 40

# Violations Sheet
violations_sheet = wb.create_sheet("Violations")

# Add headers (exactly as specified in instruction.md)
headers = ["Package", "Version", "License", "Type", "Violation"]
for col, header in enumerate(headers, 1):
    cell = violations_sheet.cell(row=1, column=col, value=header)
    cell.font = Font(bold=True)
    cell.fill = PatternFill(start_color="D3D3D3", end_color="D3D3D3", fill_type="solid")

# Add violation data
for row, violation in enumerate(report["violations"], 2):
    violations_sheet.cell(row=row, column=1, value=violation["name"])
    violations_sheet.cell(row=row, column=2, value=violation["version"])
    violations_sheet.cell(row=row, column=3, value=violation["license"])
    violations_sheet.cell(row=row, column=4, value=violation["dependency_type"])
    violations_sheet.cell(row=row, column=5, value=violation["violation_type"])

# Adjust column widths
for col in range(1, 6):
    violations_sheet.column_dimensions[chr(64 + col)].width = 20

# Note: Removed "All Dependencies" sheet as per requirements

# Save Excel file
wb.save("/root/license_audit_report.xlsx")

print("License audit complete. Reports generated:")
print("- /root/license_audit_report.json")
print("- /root/license_audit_report.xlsx")
print(f"\nSummary: {report['summary']['total_violations']} violations found out of {report['summary']['total_dependencies']} dependencies")
EOF