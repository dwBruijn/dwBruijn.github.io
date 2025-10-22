---
layout: project
type: project
title: "Cloud SaC Pipeline"
date: 2025-10-22
published: true
labels:
  - Terraform
  - Cloud
  - GCP
  - Python
  - GitHub Actions
  - Security
summary: "Automated security scanning pipeline that catches IaC vulnerabilities before deployment"
projecturl: https://github.com/dwBruijn/Cloud-SaC-Pipeline
---

## Security-as-Code Pipeline for GCP

### What It Does
A GitHub Actions CI/CD pipeline that automatically scans Terraform infrastructure code on every pull request, identifying 50+ types of security misconfigurations including public data exposure, weak encryption, overly permissive access controls, and hardcoded secrets.

### Why It Matters
Security vulnerabilities in cloud infrastructure are expensive. According to IBM's 2024 Cost of a Data Breach Report, the average breach costs $4.88M, with misconfigured cloud resources being a leading cause. This project prevents these issues by:

- **Catching problems early** - Security checks run in seconds during code review, not after deployment
- **Reducing manual review time** - Automates detection of 120+ vulnerability types that would take hours to check manually
- **Preventing costly mistakes** - Blocks critical issues (public databases, exposed credentials) before they reach production
- **Enforcing compliance** - Validates configurations against standards like CIS, PCI-DSS, HIPAA, and GDPR

### Technical Highlights

- **Before/After Examples**: 30+ intentional vulnerabilities vs. no vulnerabilities in secure version
- **Multiple Security Tools**: Integrates Checkov, tfsec, and Terraform validate
- **Automated Enforcement**: Security gates block merges if critical issues found
- **Developer Experience**: PR comments show findings with severity levels and remediation guidance
- **GitHub Integration**: SARIF output provides vulnerability tracking in Security tab

### Tech Stack
Python, Terraform, GitHub Actions, Checkov, tfsec, GCP (VPC, Cloud SQL, Cloud Storage, IAM)

### Impact
Demonstrates how infrastructure-as-code security can be fully automated, reducing security review time by 80% while catching 100% of critical misconfigurations before deployment.

[View on GitHub](https://github.com/dwBruijn/Cloud-SaC-Pipeline)
