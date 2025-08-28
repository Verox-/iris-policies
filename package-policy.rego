package security.evaluation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Default deny
default allow = false

# Parse the vulnerability report
vulnerabilities = input.vulnerability_report.matches

# Parse the SBOM
components = input.sbom.components

# Count vulnerabilities by severity
critical_vulns := count([v | v := vulnerabilities[_]; v.vulnerability.severity == "Critical"])
high_vulns := count([v | v := vulnerabilities[_]; v.vulnerability.severity == "High"])
medium_vulns := count([v | v := vulnerabilities[_]; v.vulnerability.severity == "Medium"])
low_vulns := count([v | v := vulnerabilities[_]; v.vulnerability.severity == "Low"])

# Policy: Deny if any critical vulnerabilities
deny[msg] {
    critical_vulns > 0
    msg := sprintf("Found %d critical vulnerabilities", [critical_vulns])
}

# Policy: Deny if more than 5 high vulnerabilities
deny[msg] {
    high_vulns > 5
    msg := sprintf("Found %d high vulnerabilities (max allowed: 5)", [high_vulns])
}

# Policy: Check for specific vulnerable packages
deny[msg] {
    some i
    comp := components[i]
    comp.name == "log4j"
    comp.version < "2.17.0"
    msg := sprintf("Vulnerable log4j version detected: %s", [comp.version])
}

# Policy: Check for packages without versions
deny[msg] {
    some i
    comp := components[i]
    not comp.version
    msg := sprintf("Component without version: %s", [comp.name])
}

# Policy: Check for GPL licensed components (example)
deny[msg] {
    some i
    comp := components[i]
    some j
    license := comp.licenses[j]
    contains(lower(license.license.id), "gpl")
    msg := sprintf("GPL licensed component found: %s", [comp.name])
}

# Allow if no deny rules triggered
allow {
    count(deny) == 0
}

# Summary report
summary := {
    "allow": allow,
    "critical_vulnerabilities": critical_vulns,
    "high_vulnerabilities": high_vulns,
    "medium_vulnerabilities": medium_vulns,
    "low_vulnerabilities": low_vulns,
    "total_components": count(components),
    "denial_reasons": deny
}
