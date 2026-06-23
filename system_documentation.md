# Dragon Security Assessment Platform — System Documentation

This document provides a comprehensive technical overview of the Dragon Security Assessment Platform, detailing its architecture, scanning engines, user interface modules, database design, and security control mechanisms.

---

## 🏗️ Architectural Overview

Dragon is built using a modern **Electron + React + TypeScript** stack, styled with Vanilla CSS and TailwindCSS, and structured with an **offline-first** design. The codebase coordinates across three primary contexts:

```mermaid
graph TD
    subgraph Frontend [Renderer Process (React)]
        UI[Dashboard / Wizard / Explorer]
        State[React Hooks & Global State]
    end

    subgraph Bridge [IPC Preload Script]
        API[contextBridge.exposeInMainWorld]
    end

    subgraph Backend [Main Process (Electron)]
        IPC[ipcMain Event Listeners]
        DB[JSON Database Service]
        ScanEng[Scanner Engine]
        Rep[Report Compiler]
        AI[AI Remediation Assistant]
    end

    UI -->|Triggers UI Events| State
    State -->|Calls API| API
    API -->|invokes IPC| IPC
    IPC -->|Queries / Writes| DB
    IPC -->|Executes scan| ScanEng
    IPC -->|Compiles exports| Rep
    IPC -->|Consults chat| AI
    ScanEng -->|Updates scan state| DB
    ScanEng -.->|Sends real-time progress & logs| API
```

### 1. Main Process (`src/main.ts`)
Acts as the secure backend shell. It manages native operating system integrations (windows, dialogs, local file system access), registers all Inter-Process Communication (IPC) handlers, and coordinates database operations, report compilation, and scanning engine scheduling.

### 2. Preload Script (`src/preload.ts`)
Acts as a secure, isolated bridge between the backend main process and the frontend renderer. It uses Electron's `contextBridge` to expose a curated subset of APIs (`window.electronAPI`), preventing raw Node.js access in the browser context for security.

### 3. Renderer Process (`src/renderer/` & `src/renderer/App.tsx`)
Acts as the single-page React frontend. It handles user state, triggers audit modules, displays real-time scan logs, and displays findings inside an interactive dashboard and vulnerability explorer.

### 4. Database Service (`src/main/db.ts`)
An offline-first JSON-based database (`dragon_db.json` stored in the user's local AppData directory). It stores **Assets**, **Scan Records**, and **Vulnerability Findings** with schema validation.

---

## 🔍 Core Security Auditing & Scanner Engines

All scans in Dragon operate in a **controlled, non-destructive validation mode**. They identify vulnerabilities, outdated packages, configurations, and specs without exploiting systems.

### 1. Website Security Crawler & Header Auditor
Audits public or local web application instances via HTTP/HTTPS connections.
* **Security Header Audit:** Checks for the presence and configuration of `Content-Security-Policy` (CSP), `Strict-Transport-Security` (HSTS), `X-Frame-Options` (XFO), and `X-Content-Type-Options` (XCTO).
* **Cookie Flags Audit:** Inspects `Set-Cookie` directives for crucial security flags: `Secure` (restricting cookies to HTTPS) and `HttpOnly` (preventing client-side script access to session identifiers).
* **Server Info Disclosure:** Warns if the HTTP `Server` header exposes detailed software versions.
* **Technology Stack Profiler:** Examines response headers and HTML markup structures against signatures (e.g. Express, React, Next.js, Nginx) to map application footprint.

### 2. Static Application Security Testing (SAST) Engine
Recursively analyzes codebase files (`.ts`, `.js`, `.py`, `.go`, `.java`, `.cs`, `.php`), ignoring build directories (`node_modules`, `.git`, `dist`).
* **SQL Injection (SQLi) Detector:** Matches dynamic string interpolations inside SQL statements.
* **Command Injection Detector:** Identifies shell invocations (e.g., `subprocess.Popen` with `shell=True` or Node `exec`) containing dynamic parameters.
* **Dangerous Functions Audit:** Flags usage of `eval()`, React's `dangerouslySetInnerHTML`, and unsafe deserialization functions.
* **Weak Cryptography Audit:** Flags usage of deprecated ciphers/hash algorithms (`MD5`, `SHA-1`, `DES`, `RC4`).

### 3. API Security spec Auditor
Discovers and parses local or remote OpenAPI/Swagger specs (`.json`, `.yaml`, `.yml`).
* **Auth Schema Validator:** Flags any endpoints defined without global or local `security` schemas.
* **Parameter Constraint Auditor:** Inspects parameter schemas. Flags string parameters missing regex `pattern` or length limits, and numeric parameters lacking `minimum`/`maximum` bounds.
* **Sensitive Route exposure:** Warns if internal debug or administrative paths (e.g. `/debug`, `/env`, `/actuator`) are exposed.

### 4. Container & Docker Security Auditor
Audits `Dockerfile`, `docker-compose.yml`, and Kubernetes manifest configurations.
* **Privileged Execution Check:** Audits Dockerfiles for a `USER` instruction. Flags containers running as `root` by default.
* **Mutable Tags Check:** Flags base images referencing mutable tags (e.g., `node:latest`) instead of pinned stable versions or digest hashes.
* **Database & Admin Exposure:** Warns if administrative ports (e.g. `3306`, `5432`, `6379`, `27017`) are exposed publicly.
* **Hardcoded Credentials:** Audits compose configuration files for plaintext passwords or API keys stored in environment blocks.

### 5. Dependency Vulnerability Scanner
Inspects manifest files (`package.json` for Node, `requirements.txt` for Python).
* Compares dependencies and versions against an offline vulnerability database (`LOCAL_CVE_DATABASE`).
* Identifies vulnerable third-party modules (e.g., prototype pollution in `lodash`, SSRF in `axios`) and details CVE numbers, severity scores, and required update ranges.

---

## 📊 Compliance Evaluation Engine

Dragon maps scan findings against standard compliance frameworks to score assets and generate audit checklists.

* **OWASP ASVS (Application Security Verification Standard):** Scores the asset's security stance across Session Management (V3), Access Control (V4), Input Validation (V5), and Cryptography (V6).
* **CIS Benchmarks:** Scores container configurations across Image Tags, Runtime Privileges, Configuration Secrets, and Host Network Exposure.
* **Scoring Logic:** Calculates percentage scores based on control verification checks. Individual checklists (Pass/Fail) are preserved with each completed scan run in the database.

---

## 💻 Frontend Interface Features

```
+------------------------------------------------------------------------+
|  DRAGON Security Platform                                   [ Dark ]   |
+------------------------------------------------------------------------+
|  [Dashboard]  [Asset Manager]  [Scan Wizard]  [Findings]  [Reports]    |
+------------------------------------------------------------------------+
|                                                                        |
|  * Scan Wizard: Select Target -> Consent -> Run Modules                |
|  * Findings: Interactive table with custom location paths & severity   |
|  * Report Center: Export Compliance Assessment / Vuln Audit Reports     |
|                                                                        |
+------------------------------------------------------------------------+
```

### 1. Interactive Dashboard
* Displays total vulnerability counters (Critical, High, Medium, Low, Info).
* Renders radial progress dials showing compliance score percentages (OWASP ASVS and CIS Benchmarks).
* Displays vulnerabilities grouped by severity.

### 2. Asset Manager
* Handles target assets (Websites, Folders, API specs, Container configs).
* Includes target metadata (Environment, Owners, Criticality).

### 3. Scan Wizard (Security Validation & Attack Simulation)
* **Target Scope Configuration:** Dynamically adjusts module options depending on the selected asset type.
* **Explicit Authorization Consent:** Features a simulation consent checkbox. The execute button remains locked until the operator explicitly confirms authorization.
* **Real-time Terminal Output:** Renders live, scrolling audit logs and a progress indicator.

### 4. Vulnerability Explorer
* **Findings Grid:** Renders an interactive table displaying the vulnerability title, location path, severity, and detection date/time.
* **Metadata Detail Drawer:** Slidout drawer containing finding details, risk scores, impact summaries, code evidence, reference links, and assigned remediators.
* **Cascading Deletion Controls:** Support for deleting individual findings, checking multiple checkboxes for bulk deletion, or clicking a "Clear All" header button.

### 5. Report Center
* Generates **Vulnerability Audits** or **Compliance Assessments**.
* Compiles comprehensive reports in **PDF, HTML, JSON, and CSV** formats.
* **Clean-up Controls:** Features a red "Clear History" button to wipe scan runs and associated findings, and individual delete buttons on each row.

---

## 🔒 Safe Design & Operational Guidelines

Dragon enforces safety requirements to ensure it is strictly used as a defensive utility:

1. **Authorization Gate:** Scan starts require manual checkbox verification, logging operator authorization before executing scanning modules.
2. **Non-Destructive Checks:** Passive scanners analyze codebase structures, HTTP headers, open ports, and configurations. It does not execute live exploit scripts, simulate DoS attacks, attempt credential brute-forcing, or alter remote data.
3. **Non-blocking UI Dialogs:** Inter-Process Communication utilizes native Electron OS message sheets (`dialog.showMessageBox`) for alert and confirm events. This keeps the renderer process responsive and prevents unclickable/jammed buttons.
4. **Platform Path Resolution:** Normalizes system-specific file paths. Drive-letter casing (e.g., `c:\` vs `C:\`) and directory slashes are normalized case-insensitively, ensuring complete relative locations (e.g. `src/main/ai.ts:102`) are stored in database records instead of ambiguous basenames.
