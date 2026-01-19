---
name: license-audit
description: "Perform software license audits by analyzing dependencies and checking them against organizational policies. Covers license types, compatibility, compliance checking, and report generation in JSON and Excel formats."
---

# License Audit Skill

This skill helps you perform software license audits by analyzing dependencies and checking them against organizational policies.

## Key Concepts

### License Types
Common open-source licenses and their characteristics:

- **MIT**: Very permissive, allows commercial use, modification, distribution
- **Apache-2.0**: Permissive with patent grant, requires attribution
- **BSD-3-Clause**: Permissive, requires attribution, no endorsement
- **BSD-2-Clause**: Similar to BSD-3 but without non-endorsement clause
- **GPL-3.0**: Copyleft, requires source disclosure for distributed software
- **AGPL-3.0**: Like GPL but includes network use as distribution
- **MPL-2.0**: Weak copyleft, file-level, allows proprietary combinations
- **Elastic-2.0**: Restricts certain commercial uses
- **ISC**: Simple permissive license similar to MIT
- **PSF**: Python Software Foundation license, permissive
- **HPND**: Historical Permission Notice and Disclaimer

### License Compatibility

When checking license compliance, consider:

1. **Dependency Type**:
   - Runtime dependencies: Part of distributed software
   - Development dependencies: Used only during development/testing

2. **License Restrictions**:
   - Copyleft licenses (GPL, AGPL) may require source code disclosure
   - Some licenses restrict commercial use
   - Patent clauses can affect usage


## Working with JSON Files

### Reading JSON data:
```python
import json

with open("file.json", "r") as f:
    data = json.load(f)
```

### Writing JSON reports:
```python
with open("report.json", "w") as f:
    json.dump(report_data, f, indent=2)
```

## Working with Excel Reports

### Creating Excel files with openpyxl:
```python
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill

wb = Workbook()
sheet = wb.active
sheet.title = "Report"

# Add headers
sheet["A1"] = "Package"
sheet["A1"].font = Font(bold=True)

# Save workbook
wb.save("report.xlsx")
```

### Multiple sheets:
```python
# Create additional sheets
violations_sheet = wb.create_sheet("Violations")
summary_sheet = wb.create_sheet("Summary")
```

## Audit Process

1. **Load Dependencies**: Parse dependency files (package.json, requirements.txt, etc.)
2. **Load Policy**: Read organizational license policy
3. **Analyze Each Dependency**:
   - Check license against allowed/restricted/prohibited lists
   - Consider dependency type (runtime vs development)
4. **Generate Report**:
   - Create structured JSON report
   - Generate Excel workbook with multiple sheets
   - Include summary statistics

## Report Structure

A good license audit report should include:

- **Summary**: Total dependencies, violations count, categories
- **Violations List**: Details of non-compliant dependencies
- **Full Dependency List**: All dependencies with compliance status
- **Metadata**: Timestamp, policy version used

## Python Implementation Pattern

```python
# Basic structure for license audit
report = {
    "timestamp": datetime.now().isoformat(),
    "policy_version": policy["policy_version"],
    "summary": {
        "total_dependencies": 0,
        "total_violations": 0,
        "violation_categories": {}
    },
    "violations": [],
    "dependencies": []
}

# Process dependencies
for dep in dependencies:
    # Check compliance
    if is_violation(dep, policy):
        report["violations"].append(dep)
    report["dependencies"].append(dep)

# Update summary
report["summary"]["total_dependencies"] = len(dependencies)
report["summary"]["total_violations"] = len(report["violations"])
```