# Contributing to Cyber Sentinel

Thank you for your interest in contributing to **Cyber Sentinel**! We welcome contributions from cybersecurity engineers, researchers, and developers.

To ensure high reliability, forensic integrity, and airtight security across the platform, all contributions must adhere to the standards outlined in this guide.

---

## 1. Code of Conduct

We are committed to providing a welcoming, collaborative, and inclusive environment. Please treat all contributors with respect and professionalism.

---

## 2. Getting Started

### Prerequisites
* **Node.js**: `v20.x` or `v22.x` (LTS recommended)
* **npm**: `v10.x`+
* **Docker & Docker Compose** (optional for containerized setup)
* **PostgreSQL** (optional; local in-memory/JSON repository fallback is active by default)

### Local Development Setup
1. Fork and clone the repository:
   ```bash
   git clone https://github.com/yushdhiman/Cyber-Sentinel-.git
   cd Cyber-Sentinel-
   ```
2. Install dependencies:
   ```bash
   npm install
   cd backend && npm install
   cd ../frontend && npm install
   cd ..
   ```
3. Copy environment configurations:
   ```bash
   cp backend/.env.example backend/.env
   ```
4. Start development servers:
   ```bash
   npm run dev
   ```

---

## 3. Development & Security Guidelines

### 3.1 Security Directives (Mandatory)
* **Parameterized Queries Only**: Never concatenate SQL queries or user input directly. Always use parameterized `$1, $2, ...` placeholders via `query(sql, params)`.
* **Zero Trust on Client Inputs**: Validate every inbound parameter using dedicated validators under `backend/src/validators/`.
* **No Plaintext Secrets**: Never commit API keys, private certificates, or production credentials to source code.
* **Audit Logging**: Every security-sensitive action (status changes, containment actions, profile updates, credential modifications) must emit a structured audit log using `logSecurityEvent()`.
* **Human-in-the-Loop for Actions**: Destructive actions (e.g. `ISOLATE_ENDPOINT`, `TERMINATE_PROCESS`) must always require human operator confirmation.

### 3.2 Code Formatting & Style
* Use clear, semantic variable and function names.
* Keep controllers thin; place business logic and security policies inside `services/`.
* Preserve existing comments and docstrings.

---

## 4. Testing Requirements

Every pull request must maintain **100% test pass rate** and include tests covering newly added features or bug fixes.

Before submitting a PR, run the comprehensive test suite:
```bash
# Run complete test suite (126+ unit, integration, and security tests)
npm test

# Run adversarial worst-case stress suite
npm run test:worst-case

# Run frontend production build validation
cd frontend && npm run build
```

---

## 5. Pull Request Workflow

1. Create a feature branch with a descriptive name:
   ```bash
   git checkout -b feat/threat-intel-enrichment
   # or
   git checkout -b fix/hmac-timestamp-validation
   ```
2. Commit your changes following [Conventional Commits](https://www.conventionalcommits.org/):
   * `feat:` for new capabilities
   * `fix:` for bug and security fixes
   * `docs:` for documentation updates
   * `test:` for adding or updating test suites
   * `refactor:` for code improvements without functional change
3. Push to your fork and submit a Pull Request against `main`.
4. Ensure all CI automated validation checks pass.

---
*Thank you for helping build a safer digital defense infrastructure.*
