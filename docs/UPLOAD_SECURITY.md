# Cyber Sentinel — File Upload Security & Quarantine Architecture

## 1. Overview & Threat Model

Cyber Sentinel ingests binary files for malware static analysis and protection scanning. All uploaded payloads are treated as hostile. The platform enforces defense-in-depth against:
- **Disguised Executables**: Windows PE/ELF binaries masquerading with image or document extensions (`.jpg`, `.png`, `.pdf`).
- **Double Extension Attacks**: Deceptive multi-extension filenames (`invoice.pdf.exe`, `scan.doc.vbs`).
- **Path Traversal & Null Bytes**: Attacks attempting to write outside storage boundaries (`../../../../etc/passwd`, `sample.pdf\0.exe`).
- **Archive Bombs & Zip Slips**: ZIP files with extreme decompression ratios ($> 100:1$) or path traversal sequences in central directories.
- **Unauthorized Host Execution**: Malicious payloads executing on the host platform.

---

## 2. Multi-Layered Defense Architecture

```
Client Upload Payload
  │
  ├──► [1] Auth & RBAC Check (JWT Verification + SOC Analyst Role)
  ├──► [2] Pre-Decode String Bounds Guard (Max 14MB encoded string length)
  ├──► [3] Filename Sanitizer (Strips null bytes, path traversal, control chars)
  ├──► [4] Double Extension Detector (Identifies and flags trailing execution extensions)
  ├──► [5] Magic-Byte & Header Validator (Inspects true binary signatures vs declared MIME)
  ├──► [6] Archive Bomb & Zip Slip Guard (Checks expansion ratio <= 100:1 & entry safety)
  ├──► [7] Safe Isolated Storage Vault:
  │       ├─ Cryptographically random UUID naming (SAMPLE-<uuid>.quarantine)
  │       ├─ Non-executable file permissions (chmod 0o600)
  │       └─ Stored in isolated folder outside public web roots
  └──► [8] Sample Lifecycle & Retention Policy (Automatic pruning of files older than TTL)
```

---

## 3. Magic-Byte Validation Matrix

| File Type | Magic Bytes / Signature | Detection Category |
| :--- | :--- | :--- |
| **Windows PE (EXE/DLL)** | `4D 5A` (`MZ`) at offset 0 | `EXECUTABLE_PE` |
| **Linux ELF** | `7F 45 4C 46` (`\x7fELF`) | `EXECUTABLE_ELF` |
| **macOS Mach-O** | `FE ED FA CE` / `FE ED FA CF` / `CA FE BA BE` | `EXECUTABLE_MACHO` |
| **PDF Document** | `25 50 44 46` (`%PDF`) | `DOCUMENT_PDF` |
| **ZIP / Office OpenXML** | `50 4B 03 04` (`PK..`) | `ARCHIVE_ZIP` |
| **GZIP Archive** | `1F 8B 08` | `ARCHIVE_GZIP` |
| **TAR Archive** | `ustar` at offset 257 | `ARCHIVE_TAR` |
| **7-Zip Archive** | `37 7A BC AF 27 1C` | `ARCHIVE_7Z` |
| **RAR Archive** | `52 61 72 21 1A 07` | `ARCHIVE_RAR` |
| **PowerShell Script** | `param(`, `Write-Host`, `New-Object`, `pwsh` | `SCRIPT_POWERSHELL` |
| **Windows Batch** | `@echo off`, `setlocal`, `goto :` | `SCRIPT_BATCH` |
| **Unix Shell** | `#!/bin/sh`, `#!/bin/bash` | `SCRIPT_SHELL` |

---

## 4. Quarantine Storage Directives

1. **Storage Isolation**: Samples are stored in `src/data/quarantine/` with `0o700` directory permissions, outside any static asset routes.
2. **Naming Scheme**: Client filenames are never used on disk. Storage filenames follow `SAMPLE-<crypto_random_hex>.quarantine`.
3. **Execution Prevention**: Files are written with `0o600` permissions (read/write by owner only, zero execute flags).
4. **Lifecycle & Pruning**: Automated background retention prunes samples older than 24 hours (`POST /api/malware/quarantine/prune`).
