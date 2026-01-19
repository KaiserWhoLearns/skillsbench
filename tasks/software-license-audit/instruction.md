I am going to release a new software. All dependencies of my software lie in `project_dependencies.json`. My software has to follow the license policy in `license_policy.json`.
You should help me find the dependencies that are in violations of my policies. Please look through all my dependencies and give me two output reports: `license_audit_report.json` and `license_audit_report.xlsx`. The json file's values should correctly correspond with the .xlsx file's values.

You should determine violations by checking if a license appears in the restricted_licenses or prohibited_licenses fields for the appropriate dependency type (runtime or development).

You should write license_audit_report.json in the following format:
{
    "timestamp": "string in a valid ISO8601 format",
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
        "violation_type": "string ('restricted' or 'prohibited')"
      }
    ],
    "dependencies": [
      {
        "name": "string",
        "version": "string",
        "license": "string",
        "type": "string ('runtime' or 'development')",
        "compliant": "bool"
      }
    ]
  }


For `license_audit_report.xlsx`, you should have two sheets, with the first sheet named as "Summary", being a summary of the situation and the second sheet named as "Violations" to be the license violations.

For the first sheet, you should have two columns where the first column contains the labels (headers) in the following order: [License Audit Report, Report Generated, Policy Version, Summary Statistics, Total Dependencies, Total Violations, Restricted License Violations, Prohibited License Violations] and the second column contains their corresponding values.

For the second sheet, you should have headers to be [Package, Version, License, Type, Violation], and each row to be a violation entry corresponding exactly to the violations in the JSON report.