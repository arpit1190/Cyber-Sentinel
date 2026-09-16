# Security Policy & Vulnerability Disclosure

**Cyber Sentinel** is an enterprise-grade cyber threat monitoring, detection, and incident response platform. We treat the security of our codebase, telemetry pipelines, and infrastructure with the highest priority.

---

## 1. Supported Versions

We provide active security patches and vulnerability updates for the following releases:

| Version | Supported          | Security Maintenance Status |
| :------ | :----------------- | :-------------------------- |
| 1.0.x   | :white_check_mark: | Current Stable Release      |
| < 1.0.0 | :x:                | Deprecated / Development    |

---

## 2. Reporting a Security Vulnerability

If you discover a security vulnerability or weakness within Cyber Sentinel, **please do NOT report it publicly through GitHub Issues or pull requests**.

### Responsible Disclosure Protocol
1. **Email Submission**: Send a detailed vulnerability report to:
   * **Security Team**: `security@sentinel.defense`
   * **Alternative Contact**: `ayush.dhiman@sentinel.defense`
2. **PGP Encryption**: If sending sensitive proof-of-concept exploits, encrypt your message using our published PGP Public Key (`0x7F8E9B2C4D1A3E5F`).
3. **Required Information**:
   * Vulnerability description, component, and affected routes/files.
   * Step-by-step reproduction instructions or proof-of-concept (PoC).
   * Estimated attack impact and severity classification (CVSS v3.1).
   * Potential remediation advice or mitigation strategies.

---

## 3. Vulnerability Handling SLA

We are committed to the following response timeline:
* **Initial Acknowledgment**: Within **24 hours**.
* **Triage & Reproduction**: Within **48 hours**.
* **Fix & Patch Deployment**: Within **7 calendar days** for Critical/High vulnerabilities.
* **Public Disclosure**: Coordinated release after the patch has been verified and distributed.

---

## 4. Core Security Principles & Architecture

Cyber Sentinel adheres to strict secure development and operational guidelines:
1. **Zero-Trust Authorization**: Client and frontend assertions are never trusted. All access is verified via server-side RBAC and permission middleware.
2. **Defense in Depth**: Every layer (Gateway $\rightarrow$ Middleware $\rightarrow$ Service $\rightarrow$ Data Access) enforces independent boundary checks.
3. **Fail-Closed Configuration**: In production, missing or weak cryptographic keys prevent the backend from initializing.
4. **Advisory AI Boundary**: AI assistants and copilots operate strictly in an advisory capacity without autonomous destructive execution authority.
5. **Immutable Forensic Auditing**: Incident timelines and security audit logs use cryptographic SHA-256 hash chains to detect tampering.
6. **Data Minimization & Privacy**: Sensitive authentication credentials, passwords, and private subnets are masked and pseudonymized automatically.

---
*Thank you for helping keep Cyber Sentinel and the cybersecurity community safe.*
