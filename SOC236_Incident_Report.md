# SOC Incident Response & DFIR Report
## Defense Evasion & Credential Access via Mimikatz (Diversionary Brute-Force to Shell)

**Prepared by:** Ediz YURDAGÜL — `edizyurdagul@hotmail.com`
**Report Type:** Incident Response & Digital Forensics
**Classification:** TLP:AMBER (Portfolio / Educational Redaction Applied)

---

## 1. Executive Summary

On November 7, 2023, a coordinated, two-track intrusion was identified against host **EC2AMAZ-ILGVOIN\LetsDefend** (`172.16.17.168`). The attacker used a classic **adversary diversion (false-flag) tactic**: a loud, high-volume brute-force campaign was launched against the host from an external IP (`37.19.205.153`), generating a large volume of failed-authentication noise clearly intended to consume Tier-1 (L1) analyst attention and alert triage capacity.

While that noisy, low-value brute-force vector was being actively investigated, the real compromise occurred through a separate, quieter path directly on the host: a User Account Control (UAC) prompt was approved, granting an elevated PowerShell session. From that elevated session, the attacker systematically disabled Windows Defender Firewall across all profiles (Defense Evasion) and, roughly 90 seconds later, executed **Mimikatz** against `lsass.exe` in an attempt to harvest cached credentials (NTLM hashes, Kerberos tickets, and plaintext secrets).

The incident was contained before evidence of credential exfiltration or lateral movement was confirmed. This report documents the full technical timeline, distinguishes the diversionary noise from the actual intrusion path, validates one initially-suspicious system process as legitimate baseline behavior, and provides concrete containment and hardening recommendations.

**Key finding:** The brute-force alert was the distraction, not the attack. The actual initial-access vector was a locally-approved UAC elevation — a reminder that the loudest alert in the queue is not always the one that matters most.

---

## 2. Incident Overview & Metadata

| Field | Details |
|---|---|
| **Incident Title** | Defense Evasion & Credential Access via Mimikatz (Diversionary Brute-Force to Shell) |
| **Classification** | True Positive — Compromised (Credential Access Phase) |
| **Severity** | High (P2) |
| **Status** | Contained |
| **Analyst** | Ediz YURDAGÜL (Tier-1 / Tier-2 SOC Analyst) |
| **Incident Date** | November 7, 2023 |
| **Target Host** | EC2AMAZ-ILGVOIN\LetsDefend |
| **Target Host IP** | `172.16.17.168` |
| **Diversionary / Noise IP** | `37.19.205.153` (external brute-force source) |
| **Actual Access Vector** | Local session, UAC-elevated PowerShell (`172.16.17.168`) |
| **Credential Access Tool** | Mimikatz (`mimikatz.exe`) |
| **Elevated Process PID** | 4104 (`powershell.exe`) |

---

## 3. Threat Actor TTPs — MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Evidence |
|---|---|---|---|
| Initial Access | T1110 | Brute Force *(diversionary)* | High-volume failed-authentication attempts from `37.19.205.153`, used as a noise/distraction vector rather than the actual entry point |
| Privilege Escalation | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | `consent.exe` invoked under `explorer.exe` at 12:46:36, immediately followed by an elevated `powershell.exe` session at 12:46:40 |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Elevated `powershell.exe` (PID 4104) used as the operator console for all subsequent attacker actions |
| Defense Evasion | T1562.004 | Impair Defenses: Disable or Modify System Firewall | `netsh.exe` invoked from the elevated PowerShell session to disable the host firewall at 12:46:47 |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | `mimikatz.exe` executed from `Downloads\test\mimikatz-master\x64\` at 12:48:29, targeting `lsass.exe` memory for NTLM/Kerberos/plaintext credential extraction |

---

## 4. Step-by-Step Technical Analysis & Attack Timeline

### Track A — Diversionary Brute-Force (Concurrent Noise)

Throughout the incident window, host `172.16.17.168` was subjected to a sustained, high-volume brute-force authentication campaign originating from `37.19.205.153`. The volume and repetitiveness of these failed attempts were disproportionate to a typical opportunistic scan — consistent with a deliberate attempt to flood the SOC queue and anchor L1 triage attention on a vector that was never going to succeed. **This track produced no successful authentication and is assessed as a decoy, not the actual intrusion path.**

### Track B — Actual Intrusion (Local Privilege Escalation → Shell)

**12:46:36.571 — UAC Elevation Prompt Triggered (T1548.002)**

```
Source Process : explorer.exe (PID 6600)
Parent Process : C:\Windows\System32\userinit.exe
Process User   : EC2AMAZ-ILGVOIN\LetsDefend
Target Process : consent.exe 3896 468 000001E187DCE810
```

`explorer.exe` invoked `consent.exe` — the native Windows UAC consent dialog. This is the elevation checkpoint: for the attacker's next step to succeed, this prompt had to be approved, either by the logged-in user or by an attacker already in possession of an interactive session.

`[Screenshot: Sysmon/EDR process log — explorer.exe spawning consent.exe with UAC elevation parameters, 12:46:36.571]`

**12:46:40.394 — Elevated PowerShell Session Established**

```
Source Process : explorer.exe (PID 6600)
Parent Process : C:\Windows\System32\userinit.exe
Process User   : EC2AMAZ-ILGVOIN\LetsDefend
Target Process : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

Roughly four seconds after the UAC prompt appeared, an elevated PowerShell session was spawned from `explorer.exe`. This session — later observed running as **PID 4104** — became the attacker's operating console for the remainder of the intrusion.

`[Screenshot: Sysmon/EDR process log — explorer.exe spawning elevated powershell.exe, 12:46:40.394]`

**12:46:47.910 — Defense Evasion: Firewall Disabled (T1562.004)**

```
Source Process : powershell.exe (PID 4104)
Parent Path    : C:\Windows\explorer.exe
Process User   : EC2AMAZ-ILGVOIN\LetsDefend
Target Process : "C:\Windows\System32\netsh.exe" firewall set opmode disable
```

From the newly-elevated PowerShell session, the attacker immediately reached for `netsh.exe` to disable the Windows Firewall. This is a deliberate defense-evasion step: with the host firewall down, subsequent tooling (including Mimikatz, discussed next) faces one less layer of local network-based inspection and blocking, and any outbound connection attempts are less likely to be interrupted.

`[Screenshot: Sysmon/EDR process log — powershell.exe (PID 4104) executing netsh.exe firewall set opmode disable, 12:46:47.910]`

**12:48:29 — Credential Access: Mimikatz Execution (T1003.001)**

```
Executed From  : C:\Users\LetsDefend\Downloads\test\mimikatz-master\x64\mimikatz.exe
Parent Session : powershell.exe (PID 4104)
```

Approximately **90 seconds** after the firewall was disabled, the same elevated PowerShell session launched `mimikatz.exe` directly from a subdirectory under the user's Downloads folder. Mimikatz is a well-known, publicly available credential-dumping utility capable of extracting plaintext passwords, NTLM hashes, and Kerberos tickets directly from the `lsass.exe` process memory space. Its presence and execution here indicate a clear intent to harvest credentials for follow-on lateral movement or privilege consolidation across the domain.

`[Screenshot: Process log / command-line evidence — mimikatz.exe execution from Downloads\test\mimikatz-master\x64\, 12:48:29]`

### Timeline Summary

| Time (UTC/local) | Event | Technique |
|---|---|---|
| Ongoing (concurrent) | High-volume brute-force noise from `37.19.205.153` | T1110 (diversion) |
| 12:46:36.571 | `consent.exe` invoked — UAC elevation prompt | T1548.002 |
| 12:46:40.394 | Elevated `powershell.exe` (PID 4104) spawned | T1059.001 |
| 12:46:47.910 | `netsh.exe firewall set opmode disable` executed | T1562.004 |
| 12:48:29 | `mimikatz.exe` executed against `lsass.exe` | T1003.001 |

---

## 5. Forensic Baseline Note — Legitimate Process Validation

During triage, the following process parameter string was flagged for review due to the presence of a `ProfileControl` flag, which can superficially resemble a security-relevant setting:

```
csrss.exe
ObjectDirectory=\Windows
SharedSection=1024,20480,768
Windows=On
SubSystemType=Windows
ServerDll=basesrv,1
ServerDll=winsrv:UserServerDllInitialization,3
ServerDll=sxssrv,4
ProfileControl=Off
MaxRequestThreads=16
```

**Analyst determination:** `ProfileControl=Off` is a **standard, default Windows kernel subsystem parameter** for the Client/Server Runtime Subsystem (`csrss.exe`), governing whether the OS extracts performance-counter profiling data for the subsystem — it is unrelated to user profile security, access control, or defense mechanisms of any kind. This parameter is present by default on stock Windows installations and does **not** indicate defense tampering, kernel-level manipulation, or any adversary interaction with core system processes.

**Disposition:** Confirmed benign. Logged here as a documented baseline reference so this exact string is not re-flagged as suspicious in future triage passes on this host or its peers — a small but meaningful step toward reducing repeat false-positive investigation time.

---

## 6. Privilege Escalation & Diversion Tactic Analysis

Unlike incidents where a web shell or remote exploit grants an attacker code execution without ever touching the interactive desktop, this case shows a **genuine, successful privilege escalation** via UAC approval — a materially different and more serious finding than "discovery only" cases.

**Why this matters:** the four-second gap between the `consent.exe` prompt (12:46:36.571) and the elevated PowerShell spawn (12:46:40.394) is consistent with a human — either the legitimate user under social-engineering pressure, or an attacker with an already-established interactive session — actively clicking "Yes" on the UAC dialog. This is a **deliberate escalation event**, not a passive privilege check like a `whoami /priv` discovery command would be.

**The diversion tactic deserves particular attention for lessons-learned purposes.** The brute-force noise from `37.19.205.153` was almost certainly not intended to succeed — its purpose was to occupy the SOC's attention budget. This is a well-documented adversary pattern: generate a loud, easy-to-triage-but-time-consuming signal on one vector while the real access is established quietly on another. Analysts should treat **simultaneous, unrelated alerts on the same asset** as a specific reason to broaden investigation scope, not narrow it — the presence of an obvious, noisy threat does not rule out a second, quieter one running in parallel.

---

## 7. Containment, Eradication & Remediation

### Containment (Completed)

- [x] **Host isolation:** `EC2AMAZ-ILGVOIN\LetsDefend` (`172.16.17.168`) immediately isolated from the network to prevent lateral movement or credential exfiltration.
- [x] **Process termination:** Elevated `powershell.exe` (PID 4104) and the running `mimikatz.exe` process were terminated.
- [x] **Artifact removal:** The `C:\Users\LetsDefend\Downloads\test\` directory (containing the Mimikatz toolkit) was deleted.
- [x] **Firewall restoration:** Host firewall re-enabled across all profiles via `netsh advfirewall set allprofiles state on`.

### Eradication

- [ ] Full memory and disk forensic review of the host to confirm whether `lsass.exe` dumping succeeded and whether any credential material left the host.
- [ ] Review of authentication logs domain-wide for any successful logons using accounts whose credentials may have resided in `lsass.exe` memory at time of compromise.
- [ ] Search environment-wide for additional instances of Mimikatz or similar credential-dumping tooling using the recovered file hash / known Mimikatz signatures.

### Remediation / Hardening Recommendations

| Action | Rationale |
|---|---|
| **Enforce domain-wide forced password reset** | Assume credential exposure until proven otherwise; a full reset closes the window regardless of confirmed exfiltration. |
| **Enable LSA Protection (RunAsPPL)** | Prevents unsigned/untrusted processes — including Mimikatz — from reading `lsass.exe` memory outright, neutralizing this exact technique at the OS level. |
| **Audit Kerberos ticket issuance (Event ID 4768 / 4769)** | Detects Golden Ticket / Pass-the-Ticket follow-on activity that commonly follows successful LSASS credential theft. |
| **Restrict local UAC auto-approval / require admin PIN or secondary approval for elevation** | Reduces the chance that a single locally-approved prompt is sufficient for full elevation. |
| **Correlate concurrent alerts on the same asset** | Build a detection rule that flags when two or more distinct alert categories fire on the same host within a short window — this exact diversion pattern should trigger automatic priority escalation, not require manual analyst intuition to catch. |
| **Restrict/alert on execution from user Downloads folders** | Disallow or heavily scrutinize `.exe` execution directly from `Downloads\`, a common staging location for attacker tooling as seen here. |

---

## 8. Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Diversionary Source IP | `37.19.205.153` | External brute-force noise vector (false-flag) |
| Compromised Host IP | `172.16.17.168` | Actual point of local privilege escalation and shell access |
| Compromised Host | `EC2AMAZ-ILGVOIN\LetsDefend` | Affected asset |
| Elevated Process | `powershell.exe` (PID 4104) | Attacker's operator console post-UAC-elevation |
| Defense Evasion Command | `"C:\Windows\System32\netsh.exe" firewall set opmode disable` | Host firewall disabled across all profiles |
| Credential Access Tool | `mimikatz.exe` | Executed from `C:\Users\LetsDefend\Downloads\test\mimikatz-master\x64\mimikatz.exe` |
| Staging Directory | `C:\Users\LetsDefend\Downloads\test\mimikatz-master\` | Location of the attacker's toolkit on disk |
| UAC Elevation Artifact | `consent.exe 3896 468 000001E187DCE810` | Marks the exact elevation checkpoint in the attack chain |

---

## 9. Lessons Learned & Recommendations

1. **A loud alert is not always the important one.** The brute-force campaign was, by volume, the most visually alarming signal in this incident — and it was the least relevant. SOC workflows should include an explicit check for "what else is happening on this asset right now" whenever a noisy alert consumes significant triage time.

2. **UAC approval is a security boundary, not a formality.** The four-second gap between prompt and elevated shell shows how quickly a single approved dialog converts into full attacker tooling access. User training and technical controls (secondary approval, admin-PIN elevation) both have a role here.

3. **The firewall-disable-then-credential-dump pattern is a strong, chainable detection signature.** A `netsh firewall` / `netsh advfirewall` disable command followed within minutes by execution of a binary from a user-writable directory is a high-confidence indicator worth a dedicated correlation rule, independent of whether the specific tool is recognized by signature.

4. **Baseline documentation reduces future noise.** Formally recording the `csrss.exe` / `ProfileControl=Off` finding as a validated benign baseline prevents repeat investigation cycles on the same non-issue, freeing analyst time for genuine anomalies.

5. **LSASS protection is a high-leverage, low-friction control.** Enabling RunAsPPL would have prevented the credential-dumping stage of this incident outright, regardless of how the attacker obtained their elevated shell.

---

*— End of Report —*
