# 🛡️ Threat Hunt Report: Operation QUARTZFANG

![KQL](https://img.shields.io/badge/KQL-Kusto%20Query%20Language-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![MDE](https://img.shields.io/badge/Microsoft-Defender%20for%20Endpoint-00A4EF?style=for-the-badge&logo=microsoft&logoColor=white)
![Threat Hunting](https://img.shields.io/badge/Threat-Hunting-red?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange?style=for-the-badge)
![AI Threats](https://img.shields.io/badge/AI--Directed-Intrusion-purple?style=for-the-badge)

| | |
|---|---|
| **Organisation** | SemiCrest Technologies (fictional) |
| **Platform** | Microsoft Sentinel (KQL), workspace `LAW-HuntPractice` |
| **Hunt window** | 20 September 2026, 06:30–08:30 UTC |
| **Hosts** | `sc-portal01`, `sc-db01`, `sc-registry01`, `sc-admin01` |
| **Tables** | `DeviceProcessEvents_CL`, `DeviceNetworkEvents_CL`, `DeviceFileEvents_CL`, `Syslog`, `PortalAccessLog_CL`, `ContainerRegistryLog_CL`, `LLMAgentLogs_CL` |
| **Profile** | AI-directed espionage: SSRF → lateral movement → exfiltration |
| **Reference** | Anthropic threat intelligence, Campaign C0062 (November 2025) |

📄 **Full report:** [QUARTZFANG_Report.pdf](QUARTZFANG_Report.pdf)

---

## 📌 Scenario

At **06:52 UTC**, an analytics rule fired on `sc-portal01`: two requests to the document preview API in quick succession, one rejected and one accepted. Minutes later, a process the web application never spawns appeared on the server. Database activity on `sc-db01` spiked, an outbound HTTPS transfer was observed, and a new account appeared that nobody created.

The scenario reproduces **Campaign C0062**, the first documented cyberattack largely executed by an AI agent, with a human operator stepping in only at strategic decision points. A recovered attacker agent log (`LLMAgentLogs_CL`) was available, but its narration mixes accurate findings with **fabricated claims**. Every claim had to be checked against host telemetry.

**Objective:** Reconstruct the full attack chain, separate real attacker activity from legitimate noise, and determine how much of the operation was run by the AI versus the human.

---

## 🔍 High-Level Hunt Plan

1. **Web logs** (`PortalAccessLog_CL`): find the exploit requests against `/api/v1/preview`.
2. **Process events** (`DeviceProcessEvents_CL`): find what the exploit spawned and what the attacker ran.
3. **Database, registry and admin API logs** (`Syslog`, `ContainerRegistryLog_CL`): trace lateral movement with harvested credentials.
4. **Network events** (`DeviceNetworkEvents_CL`): find the exfiltration destination.
5. **AI agent log** (`LLMAgentLogs_CL`): find the human decision points, and verify every claim against steps 1–4.

---

## 📝 Steps Taken & Findings

### 1. Initial Access: SSRF in the Preview API

External IPs `198.51.100.31`, `.45` and `.62` probed `/api/v1/preview` at 06:30. From **06:44**, `203.0.113.87` tested URL schemes one by one (`http`, `https`, `ftp`, `file`, `dict`). At **06:52:30**, `file:///etc/passwd` was rejected (**400**). **18 seconds later**, the attacker switched to `gopher://127.0.0.1:6379/`, which was accepted (**200**). The payload sent Redis commands (`FLUSHALL` and `SET`) that planted a cron job running every minute.

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30) .. datetime(2026-09-20 07:00))
| where UrlOriginal has "preview"
| sort by TimeGenerated asc
```

![Preview API requests](images/01-preview-api-requests.png)

---

### 2. Remote Code Execution: cron Spawns a Reverse Shell

At **06:52:52**, four seconds after the gopher request, `cron` spawned a `python3` reverse shell as **root**. The full chain: **SSRF → gopher:// → Redis → cron job → python3 reverse shell**.

```kql
DeviceProcessEvents_CL
| where DeviceName has "sc-portal01"
| where TimeGenerated between (datetime(2026-09-20 06:52) .. datetime(2026-09-20 07:10))
| project Timestamp, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp asc
```

![cron spawning python3](images/02-rce-cron-python3.png)

---

### 3. Credential Harvest

In a 12-second burst (07:05:15–27), the shell ran `cat /etc/semicrest/portal.conf`, `env`, and `find` for `.conf` and `.env` files. The config file held two credential pairs:

- **PostgreSQL:** `portal_svc` → `10.5.0.20` (`sc-db01`)
- **Harbor registry:** `ci-builder` → `10.5.0.30` (`sc-registry01`)

**Visibility gap:** process telemetry records that `env` ran, but not its output. Whether environment variables held more credentials **cannot be determined** from the available data.

```kql
DeviceFileEvents_CL
| where TimeGenerated between (datetime(2026-09-20 07:00) .. datetime(2026-09-20 07:10))
| search "portal.conf"
```

![Config file read](images/03-config-file-read.png)

---

### 4. Lateral Movement: Database

At **07:16:14**, `portal_svc` connected to `sc-db01` from `10.5.0.10` **without** the `application_name=portal_svc` that the real application always sets. Within 11 seconds it ran unbounded `SELECT *` queries on `users`, `projects`, `customers`, `information_schema.tables` and `pg_catalog.pg_shadow`. The legitimate app only runs parameterised queries (`$1`) with `WHERE` and `LIMIT`.

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 07:00) .. datetime(2026-09-20 08:30))
| where Computer has "sc-db01"
| where ProcessName has "postgres"
| where SyslogMessage !has "$1"
| summarize Count = count(), FirstSeen = min(TimeGenerated) by SyslogMessage
| sort by FirstSeen asc
```

![Database enumeration](images/04-database-enumeration.png)

---

### 5. Lateral Movement: Container Registry

The `ci-builder` account normally only runs `pull_artifact` and `push_artifact` from the CI server (`10.5.0.100`). At **07:33**, it appeared from `sc-portal01` (`10.5.0.10`) running `login`, `list_repository`, `pull_manifest` and `inspect_layer` against `semicrest/portal-build:latest`.

```kql
ContainerRegistryLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30) .. datetime(2026-09-20 08:30))
| search "10.5.0.10"
```

![Registry access](images/05-registry-access.png)

---

### 6. Lateral Movement: Admin API

At **07:45**, `portal_svc` queried the admin API on `sc-admin01`. `/services` and `/topology` returned **200**, but `/secrets` returned **403 Forbidden**.

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 06:30) .. datetime(2026-09-20 08:30))
| where Computer has "sc-admin01"
| where SyslogMessage has "src=10.5.0.10 "
| project TimeGenerated, ProcessName, SyslogMessage
| sort by TimeGenerated asc
```

![Admin API 403](images/06-admin-api-403.png)

---

### 7. Staging, Exfiltration and Persistence

- **08:02:** `tar` → `gzip` → `openssl enc -aes-256-cbc` packed the data into `/tmp/.portal-cache/report.tar.gz.enc`.
- **08:15:** `curl` POSTed the archive to **`198.51.100.210:443`** as **root**. All legitimate HTTPS from this server runs as `www-data`.
- **08:29:** `useradd svc_monitor`, `usermod -aG sudo`, and `ssh-keygen` created a backdoor admin account with an SSH key.

```kql
DeviceProcessEvents_CL
| where TimeGenerated between (datetime(2026-09-20 07:50) .. datetime(2026-09-20 08:30))
| where DeviceName has "sc-portal01"
| where AccountName == "root"
| project TimeGenerated, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

![Staging, exfil, persistence](images/07-staging-exfil-persistence.png)

---

### 8. AI Agent Log: Human Gates and Hallucinations

The attacker's session (`qf-c062-9e4a`, which also appears in the curl header) shows **one initial tasking and four human approval gates**. Everything else was executed by the agent.

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2020-01-01) .. datetime(2030-01-01))
| where session_id == "qf-c062-9e4a"
| project TimeGenerated, actor, via, user_input, tool_name, tool_result, gate_decision
| sort by TimeGenerated asc
```

![Agent log](images/08-agent-log.png)

Cross-referencing the agent's claims against host telemetry:

| Agent claim | What the telemetry shows | Verdict |
|---|---|---|
| Extracted TLS certs and API tokens from the admin secrets store | `/api/v1/secrets` returned **403** | ❌ Hallucinated |
| Found `db_admin` credentials in an image layer | `inspect_layer` only fetched the **vulnerability scan report**, and `db_admin` was never used | ❌ Hallucinated |
| gopher payload used Redis `SLAVEOF` | The payload used `FLUSHALL` + `SET` (cron) | ⚠️ Inaccurate |
| Data exfiltrated | `curl` to `198.51.100.210:443` confirmed | ✅ True |
| Persistence installed | `svc_monitor`, sudo and SSH key confirmed | ✅ True |

---

## 📅 Chronological Events Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| 06:30–06:31 | sc-portal01 | External scanners probe `/api/v1/preview` |
| 06:31:55 | — | 🧑 Operator tasks the AI agent |
| 06:44:05–15 | sc-portal01 | `203.0.113.87` fuzzes URL schemes |
| 06:52:30 | sc-portal01 | `file://` rejected (400) |
| 06:52:48 | sc-portal01 | `gopher://` to Redis accepted (200) |
| 06:52:52 | sc-portal01 | `cron` spawns `python3` reverse shell as root |
| 06:53:03 | — | 🧑 Gate 1: approve credential harvesting |
| 07:05:15–27 | sc-portal01 | `cat portal.conf`, `env`, `find` |
| 07:16:14–25 | sc-db01 | `SELECT *` on users, projects, customers, pg_shadow |
| 07:31:09 | — | 🧑 Gate 2: authorise data collection |
| 07:33:01–05 | sc-registry01 | `ci-builder` registry enumeration |
| 07:45:27–32 | sc-admin01 | Admin API: services, topology, secrets (403) |
| 07:48:31 | — | 🧑 Gates 3 & 4: verify intel, authorise exfiltration |
| 08:02:05–13 | sc-portal01 | `tar` → `gzip` → `openssl` staging |
| 08:15:00 | sc-portal01 | `curl` exfil to `198.51.100.210:443` |
| 08:29:35–55 | sc-portal01 | `svc_monitor` sudo account and SSH key created |

---

## ⏱️ Timing Analysis: Human or Machine?

A human operator works at a steady, irregular pace, with commands seconds to minutes apart. This chain shows the opposite: **machine-speed bursts of 4–22 seconds**, separated by **11–17 minute idle gaps** that line up with the human approval gates in the agent log.

**Classification:** semi-autonomous. A person set a machine going and approved each phase.

---

## 🧹 Real or Noise

| Pattern | Verdict | Why |
|---|---|---|
| `portal_svc` used across 3 hosts | Attack (shared credential) | Attacker sessions lack the app's client identity and run at agent cadence. Revoking the credential would break production, so it must be rotated with the app owners. |
| Nightly `pg_dump` as `portal_svc` | Noise | Runs locally (`-h localhost`) and appears uniformly in the lead-in data before the intrusion |
| DB connection spike at 07:30 | Noise | Connection pool exhaustion ("too many clients") with no queries executed |
| Internal scan from `10.5.0.250` | Noise | Scheduled Nessus/10.6.2 scan |

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Reconnaissance | T1595 Active Scanning |
| Resource Development | **T1588.007 Obtain Capabilities: Artificial Intelligence** |
| Initial Access | T1190 Exploit Public-Facing Application |
| Execution / Persistence | T1053.003 Scheduled Task/Job: Cron |
| Credential Access | T1552.001 Unsecured Credentials: Credentials in Files |
| Discovery | T1083 File and Directory Discovery; T1613 Container and Resource Discovery |
| Lateral Movement | T1078 Valid Accounts |
| Collection | T1213 Data from Information Repositories; T1074.001 Local Data Staging; T1560.001 Archive via Utility |
| Exfiltration | T1048 Exfiltration Over Alternative Protocol |
| Persistence | T1136.001 Create Local Account; T1098.004 SSH Authorized Keys |

---

## 🚩 Indicators of Compromise

| Type | Value |
|---|---|
| Exploit IP | `203.0.113.87` |
| Recon IPs | `198.51.100.31`, `198.51.100.45`, `198.51.100.62` |
| Exfil IP | `198.51.100.210` |
| Staged file | `/tmp/.portal-cache/report.tar.gz.enc` |
| Backdoor account | `svc_monitor` (sudo) |
| SSH key | `/home/svc_monitor/.ssh/id_ed25519` |
| HTTP header | `X-Session: qf-c062-9e4a` |
| User agent | `python-requests/2.31.0` |

---

## ✅ Summary

An AI agent, directed by a human operator, exploited an SSRF flaw in SemiCrest's document preview API to reach Redis, plant a cron job, and gain root on `sc-portal01`. It harvested credentials from a config file, moved to the database, container registry and admin API, then encrypted and exfiltrated data to `198.51.100.210` and left a backdoor sudo account. The agent's own log overstated its success: two of its claimed extractions never happened, which shows why AI-driven attacks still need a human to verify results.

---

## 🚨 Response Recommendations

- Isolate `sc-portal01`, remove `svc_monitor` and its SSH key, and clear the malicious cron entry
- Rotate the `portal_svc` and `ci-builder` credentials in coordination with app and CI owners
- Fix the SSRF by allow-listing URL schemes and hosts, and block `gopher://`, `file://` and `dict://`
- Require Redis authentication and stop running it as root
- Move secrets from config files into a secrets manager
- Block `198.51.100.210` and `203.0.113.87`

---

## 📖 Key Takeaways & Lessons Learned

- **Never trust attacker logs blindly.** AI agents hallucinate, so every claim must be checked against host telemetry.
- **Timing is a fingerprint.** Machine-speed bursts with long pauses point to an AI agent with a human approver.
- **Baselines matter.** Knowing what normal looks like (the app's `application_name`, the CI server's IP, `www-data` HTTPS) is what exposed the attacker.
- **Same account ≠ same actor.** Shared service credentials need behaviour-based detection, not just account-based alerts.
- **Know your visibility gaps.** Process logs show that a command ran, not what it printed.

---

*All data comes from a simulated training lab. Organisations, IP addresses and credentials are fictional.*
