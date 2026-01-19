I am going to release a new software. All dependencies of my software lie in `project_dependencies.json`. My software has to follow the license policy in `license_policy.json`.
You should help me find the dependencies that are in violations of my policies. Please look through all my dependencies and give me two output reports: `license_audit_report.json` and `license_audit_report.xlsx`.

Note: The policy file may contain an exceptions list that allows certain packages to be exempt from policy violations. Check for and apply any exceptions defined in the policy.

Additional requirements:
- The timestamp must be in valid ISO8601 format (e.g., "2024-01-15T10:30:45.123456")
- Violations are determined by checking if a license appears in the restricted_licenses or prohibited_licenses lists for the dependency type
- Dependencies with exceptions are considered compliant (compliant=true) but may still appear in violations list with exception_note to track the violation would have occurred
- For dual licenses (e.g., "MIT OR Apache-2.0"), apply the dual_license_handling policy to select the effective license for evaluation


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
        "exception_note": "string (optional, only if exception was applied)"
      }
    ],
    "dependencies": [
      {
        "name": "string",
        "version": "string",
        "license": "string",
        "type": "string ('runtime' or 'development')",
        "compliant": "bool",
        "exception": "bool (REQUIRED for all dependencies - True if package has exception, False otherwise)",
        "exception_reason": "string (REQUIRED when exception is True, must NOT exist when exception is False)"
      }
    ]
  }
```

For `license_audit_report.xlsx`, please construct it with the following: You should have two sheets, with the first sheet named as "Summary", being a summary of the situation and the second sheet named as "Violations" to be the license violations.

For the first sheet, you should use a two-column layout where the first column contains the labels [License Audit Report, Report Generated, Policy Version, Summary Statistics, Total Dependencies, Total Violations, Restricted License Violations, Prohibited License Violations] and the second column contains their corresponding values.
  
For the second sheet, you should have headers to be [Package, Version, License, Type, Violation, Notes], and each row to be the violation entry.