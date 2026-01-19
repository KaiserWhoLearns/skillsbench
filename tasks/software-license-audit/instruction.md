I am going to release a new software. All dependencies of my software lies in `project_dependencies.json`. My software has to following the license policy in `license_policy.json`.
You should help me find the dependencies that are in violations of my policies. Please look through all my dependencies and give me two output report: `license_audit_report.json` and `license_audit_report.xlsx`.


You should write `license_audit_report.json` in the following format:

```
{
    "timestamp": "string in ISO8601 format",
    "policy_version": "string",
    "summary": {
      "total_dependencies": "integer",
      "total_violations": "integer",
      "violation_categories": {
        "restricted": "integer (count of 'restricted')",
        "prohibited": "integer (count of 'prohibited')"
      }
    },
    "violations": [
      {
        "name": "string (package name)",
        "version": "string",
        "license": "string",
        "dependency_type": "string ('runtime' or 'development')",
        "violation_type": "string ('restricted' or 'prohibited')",
        "exception_note": "string (optional)"
      }
    ],
    "dependencies": [
      {
        "name": "string",
        "version": "string",
        "license": "string",
        "type": "string ('runtime'or'development')",
        "compliant": "bool",
        "exception": "bool, True if it is an execption",
        "exception_reason": "string (optional, exist only when exception is True)"
      }
    ]
  }
```


For `license_audit_report.xlsx`, please construct it with the following: You should have three sheets, with the first sheet named as "Summary", being a summary of the situation and the second sheet named as "Violations" to be the license violations.

For the first sheet, you need a single column that contains [License Audit Report, Report Generated, Policy Version, Summary Statistics, Total Dependencies, Total Violations, Restricted License Violations, Prohibited License Violations]. From the second to last row, you should have their corresponding value in the second column.
  
For the second sheet, you should have headers to be [Package, Version, License, Type, Violation, Notes], and each row to be the violation entry.