# Wazuh SOC Home Lab

A hands-on Security Operations Center (SOC) home lab focused on endpoint telemetry collection, log analysis, event correlation, authentication investigation, and dashboard development with Wazuh.

> **Scope:** This documents controlled activity performed on my own virtual machines. It is a learning lab, not a production SOC deployment. The exact Wazuh and operating-system versions were not recorded in the supplied notes, so they are not guessed.

## Project overview

I configured Windows and Linux monitoring, enabled Wazuh archives, deployed Sysmon on Windows, generated controlled account and authentication activity, investigated the resulting telemetry, and built a basic SOC activity dashboard.

**Skills demonstrated**
- Deploying and enrolling Windows and Linux Wazuh agents.
- Configuring archive logging and Filebeat forwarding.
- Collecting Windows Security events, Sysmon telemetry, and Linux authentication/syslog events.
- Searching and filtering events in Wazuh Discover.
- Interpreting Windows Event IDs, SIDs/RIDs, logon types, and authentication fields.
- Correlating SSH authentication, session lifecycle, process identifiers, and command activity.
- Building metric, line-chart, and data-table visualizations.
- Mapping simulated behaviours to MITRE ATT&CK.

## Lab architecture

The environment uses VMware virtual machines on a private lab network. IP addresses below are transcribed from the lab notes. The exact host running the Wazuh manager/indexer/dashboard is not unambiguously identified and should be confirmed.

~~~text
                 VMware private virtual network
                         192.168.149.0/24

   Windows endpoint                         Ubuntu endpoint
   192.168.149.134                          192.168.149.132
   - Windows Security logs                  - SSH/authentication logs
   - Sysmon telemetry                       - Syslog
   - Local account activity                 - User/session activity
              \                                  /
               \                                /
                +------ Wazuh agent telemetry --+
                               |
                               v
                  Wazuh manager / indexer /
                       dashboard stack
                   (host/IP to confirm)

   SSH pbareki host noted: 192.168.149.133
   Windows RDP account noted: Peter
~~~

**Address clarification:** Notes label 192.168.149.133 as the “SSH pbareki server”, 192.168.149.132 as the Ubuntu server, and 192.168.149.134 as Windows. Confirm which host runs the Wazuh manager before treating the diagram as definitive.

[Browse the existing lab screenshots](images/)

## Tools and technologies

| Component | Role |
|---|---|
| Wazuh manager, indexer, dashboard | Central collection, analysis, indexing, search, and visualization |
| Wazuh Windows agent | Windows endpoint telemetry collection |
| Wazuh Linux agent | Ubuntu endpoint telemetry collection |
| Ubuntu Server | Linux endpoint for SSH and user/session activity |
| Windows | Endpoint for local account, group, and logon activity |
| Sysmon | Additional Windows system telemetry |
| Sysmon Modular (Olaf Hartong) | Sysmon configuration used in the lab |
| Filebeat | Forwards archive events for indexing |
| VMware | Hosts the virtual machines |
| Windows CMD / PowerShell | Generates controlled local-account and authentication activity |
| SSH client | Generates failed and successful SSH authentication and session activity |

**Versions:** Exact Wazuh, Windows, Ubuntu, Sysmon, and Filebeat versions were not captured. Add versions from the installed systems rather than estimating them.

## Telemetry collection and archive configuration

Wazuh alerts and archives serve different purposes. Alerts contain events that match rules at the configured threshold. Archives can retain events that do not generate an alert, which is useful for reconstructing activity and building visualizations from raw telemetry.

The configuration work included:
1. Enabling archive logging in the Wazuh manager's ossec.conf.
2. Enabling the archives input in filebeat.yml.
3. Troubleshooting the absence of the wazuh-archives index and configuring the archive pipeline.
4. Deploying Windows and Linux agents.
5. Installing Sysmon with the Sysmon Modular configuration.
6. Confirming Sysmon and Linux syslog events were arriving in Wazuh.

References:
- [Wazuh event logging and archive configuration](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [Wazuh indexer indices and enabling archives](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Wazuh global configuration: logall and logall_json](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html)

**Operational consideration:** Archive collection increases storage consumption because it retains events that may not trigger alerts. Monitor disk usage and define an appropriate retention or cleanup policy.

## Attack simulations and detection scenarios

These were controlled simulations against the lab's own virtual machines. ATT&CK mappings describe the behaviour being emulated; they do not imply that an actual adversary compromised the environment.

| Scenario | Activity generated | Evidence examined | MITRE ATT&CK |
|---|---|---|---|
| Local account creation | Created a temporary Windows user with net user. | Security Event ID 4720; account name and SID. | [T1136.001 – Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| Add user to local Administrators | Added the temporary account to the local Administrators group. | Event ID 4732; target member SID and group SID/name. | [T1098.007 – Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/) |
| Account deletion | Deleted the temporary Windows user. | Event ID 4726; subject (actor) and target account. | Account-management behaviour; no narrower mapping asserted. |
| Guest account enablement | Enabled the Guest account during the test. | Event ID 4722. | Account-management behaviour; no narrower mapping asserted. |
| Windows failed logons | Entered incorrect passwords to generate failed logons. | Event ID 4625. | [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| Linux SSH failed authentication | Attempted SSH with an invalid username and incorrect passwords. | “Failed password” / “invalid user” messages, source IP, attempted username. | [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| Successful SSH login and session | Authenticated with the lab user, ran commands, and exited. | Accepted-password message, session-open/close messages, session ID, SSHD PID, command telemetry. | [T1078.003 – Local Accounts](https://attack.mitre.org/techniques/T1078/003/) |
| Linux account and network discovery | Ran whoami, ip a, and read /etc/passwd. | Command/session telemetry and Linux logs. | [T1087.001 – Local Account](https://attack.mitre.org/techniques/T1087/001/); [T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/) |

### Windows Security Event IDs examined

| Event ID | Meaning |
|---:|---|
| 4624 | An account was successfully logged on. |
| 4625 | An account failed to log on. |
| 4634 | An account was logged off. |
| 4720 | A user account was created. |
| 4722 | A user account was enabled. |
| 4726 | A user account was deleted. |
| 4732 | A member was added to a security-enabled local group. |
| 4738 | A user account was changed. |

Interpret an Event ID together with its **provider and event log/channel**. The same numeric ID can mean different things in different providers or channels. Prefer the event's message and official documentation over a number-only search.

- [Microsoft Learn: Windows Security event reference](https://learn.microsoft.com/azure/sentinel/windows-security-event-id-reference)

**Screenshot discrepancy to resolve:** The existing filename “23 Event ID 420 User account creation.png” says Event ID 420, while the written walkthrough identifies account creation as Event ID 4720. Verify the number visible in the screenshot and rename the file if it shows 4720. Do not claim the screenshot proves 4720 until checked.

**Event ID 4738 clarification:** 4738 means a user account was changed. It is not specifically a password-change event. Password-change and password-reset events have separate identifiers (4723 and 4724).

## Investigation notes and correlation fields

A useful investigation establishes **who performed an action, what was affected, where it happened, and how it relates to surrounding activity**.

### Windows: subject, target, SID and RID

- **Subject** identifies the account/security context that performed the action.
- **Target account/member** identifies the account affected.
- **SID (Security Identifier)** identifies a Windows security principal.
- **RID (Relative Identifier)** is the final component of a SID. Common built-in examples include 500 (Administrator) and 501 (Guest).
- **Group SID/name** identifies the group involved. The local Administrators group commonly uses SID S-1-5-32-544.

A target account name may be missing from an event. In that case, use the target SID and correlate it with other events to resolve the account. Do not assume the subject and target are the same account.

### Windows: logon type and identifiers

For Event ID 4624, inspect the logon type to understand the kind of logon. Type 2 is interactive; type 10 is commonly associated with Remote Desktop interactive logons. Interpret the value in context and consult the event details.

The **Logon ID** (and linked Logon ID, where present) can help correlate Security events belonging to the same logon session. Process ID, process name, workstation name, source address, and authentication package add context.

### Linux: SSH session identifiers and process IDs

The SSH login generated a session identifier. Session-open and session-close records, together with the SSHD process ID and timestamps, help establish the session lifecycle. Where telemetry exposes a terminal session ID, it can associate command activity with that session.

A practical investigation sequence:
1. Identify the failed or successful authentication event.
2. Record username, source IP, timestamp, and SSHD process ID.
3. Find the session-open record and note its session identifier.
4. Search for related events during the session, including command telemetry.
5. Locate the session-close record and establish the end of the activity window.
6. Correlate by timestamp and identifiers; do not rely on username alone.

Session IDs and process IDs are useful pivots but are not globally unique forever. Scope searches by host/agent and time range, and validate that events belong to the same session.

## SOC activity dashboard

The walkthrough describes three panels built using Wazuh archive data:

1. **Failed Windows Logon** – metric counting Windows failed logons using data.win.system.eventID and Event ID 4625.
2. **Windows Account Changes Over Time** – line chart using a timestamp histogram and splitting by data.win.system.eventID for events 4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733, and 4738.
3. **Linux Failed SSH Authentication Activity** – data table filtered to the Linux agent and “failed password” events, including timestamp, data.src.user, and data.src.ip. The destination-user field was absent in the observed events, so missing values were retained rather than inventing a value.

Example query patterns:

~~~text
data.win.system.eventID: 4625
~~~

For the Linux failed-SSH table, filter to the Linux agent and search for:

~~~text
"failed password"
~~~

If a field is unavailable to the visualization builder, refresh the field list for the relevant index pattern in Dashboard Management. The walkthrough records that this resolved missing field options during chart construction.

## Screenshots

The images below are the existing files in the repository's images/ directory. Captions describe the activities recorded in the supplied notes and filenames. The screenshots have not been independently inspected at pixel level in this update. Before public release, review them for exposed passwords, usernames, hostnames, IP addresses, and other sensitive information.

### Archive setup and endpoint telemetry

![ Archive logging enabled in the Wazuh manager configuration. ](<images/1. Enabling archives-logging in the ossec.cong.png>)

*Archive logging enabled in the Wazuh manager configuration.*

![ Filebeat archives input enabled to forward archived events for indexing. ](<images/2. Enable filebeat.yml.png>)

*Filebeat archives input enabled to forward archived events for indexing.*

![ Archive index unavailable before the archive pipeline was configured. ](<images/3. No wazuh_archives.png>)

*Archive index unavailable before the archive pipeline was configured.*

![ Initial archive index configuration. ](<images/4. Create wazuh archives.png>)

*Initial archive index configuration.*

![ Continued archive index configuration. ](<images/4. Create wazuh archives 2.png>)

*Continued archive index configuration.*

![ Further archive index setup evidence. ](<images/4. Create wazuh archives 3.png>)

*Further archive index setup evidence.*

![ Windows agent configuration. ](<images/5. Making the Windows Agent.png>)

*Windows agent configuration.*

![ Additional Windows agent configuration. ](<images/5. Making the Windows Agent 2.png>)

*Additional Windows agent configuration.*

![ Windows agent deployed on the Windows endpoint. ](<images/6. Deployed Windows Agent.png>)

*Windows agent deployed on the Windows endpoint.*

![ Linux agent deployed on the Ubuntu endpoint. ](<images/7. Deployed Linux Agent 1.png>)

*Linux agent deployed on the Ubuntu endpoint.*

![ Both Windows and Linux agents shown in the Wazuh environment. ](<images/8. Deployed Linux & Windows Agent.png>)

*Both Windows and Linux agents shown in the Wazuh environment.*

![ Sysmon and Olaf Hartong's Sysmon Modular configuration downloaded. ](<images/9. Download Sysmon & SysmonConfig-Sysmon-modula-olafhartong.png>)

*Sysmon and Olaf Hartong's Sysmon Modular configuration downloaded.*

![ Sysmon installed or started with the selected configuration. ](<images/10. Starting Sysmon to install using said config.png>)

*Sysmon installed or started with the selected configuration.*

![ Initial Sysmon state after installation. ](<images/11. Initial SysMon.png>)

*Initial Sysmon state after installation.*

![ Sysmon service or event-source name. ](<images/12. Sysmon Name.png>)

*Sysmon service or event-source name.*

![ Sysmon added to the monitored Windows event sources. ](<images/13. Added SysMon.png>)

*Sysmon added to the monitored Windows event sources.*

![ Sysmon telemetry arriving through the monitoring pipeline. ](<images/14. Sysmon Logs going through.png>)

*Sysmon telemetry arriving through the monitoring pipeline.*

![ Linux syslog collection and event forwarding evidence. ](<images/15. Syslog installed and Logs Going through.png>)

*Linux syslog collection and event forwarding evidence.*

### Windows account activity and event investigation

![ Windows local users, administrators, and network configuration inspected. ](<images/16. Checking Local Users, Admins and IP Config.png>)

*Windows local users, administrators, and network configuration inspected.*

![ Guest account shown disabled before the controlled test. ](<images/17. Guest account disabled by default.png>)

*Guest account shown disabled before the controlled test.*

![ Guest account enabled and password changed during the test. ](<images/18. Enable guest user and set password.png>)

*Guest account enabled and password changed during the test.*

![ Temporary user created and added to local Administrators. ](<images/19. Creating User 1, set password, add to admin group.png>)

*Temporary user created and added to local Administrators.*

![ Temporary account creation verified. ](<images/20. verify user1 exists.png>)

*Temporary account creation verified.*

![ Temporary account deleted and removal verified. ](<images/21. delete user1 and verify.png>)

*Temporary account deleted and removal verified.*

![ Wazuh Discover filtered to Windows endpoint events. ](<images/22. Event in Wazuh dashboard logs filtered by windows agent.png>)

*Wazuh Discover filtered to Windows endpoint events.*

![ Account-creation event evidence. The filename says 420, but the walkthrough notes identify Event ID 4720. Verify the number shown in the screenshot and rename if necessary. ](<images/23 Event ID 420 User account creation.png>)

*Account-creation event evidence. The filename says 420, but the walkthrough notes identify Event ID 4720. Verify the number shown in the screenshot and rename if necessary.*

![ Event ID 4738 account-change event. This ID means a user account was changed, not specifically that its password was changed. ](<images/24. Event ID 4738 User account password change 1.png>)

*Event ID 4738 account-change event. This ID means a user account was changed, not specifically that its password was changed.*

![ Additional details for the Event ID 4738 account-change record. ](<images/24. Event ID 4738 User account password change 2.png>)

*Additional details for the Event ID 4738 account-change record.*

![ Test account added to the local Administrators group; notes associate this with Event ID 4732. ](<images/25. User added to admins.png>)

*Test account added to the local Administrators group; notes associate this with Event ID 4732.*

![ Event ID 4726 account-deletion event. ](<images/26. Event code 4726 User account deleted.png>)

*Event ID 4726 account-deletion event.*

![ Event ID 4722 account-enabled event for Guest. ](<images/27. Event code 4722 Guest Account enabled.png>)

*Event ID 4722 account-enabled event for Guest.*

![ Event ID 4634 logoff event. ](<images/28. Event ID 4634 logging off windows acc.png>)

*Event ID 4634 logoff event.*

![ Event ID 4624 successful logon event. ](<images/29. Event ID 4624 logging in windows account.png>)

*Event ID 4624 successful logon event.*

![ Event ID 4625 failed Windows logon evidence. ](<images/30. Event ID 4625 failled password login attempts 1.png>)

*Event ID 4625 failed Windows logon evidence.*

![ Additional failed Windows logon evidence. ](<images/30. Event ID 4625 failled password login attempts 2.png>)

*Additional failed Windows logon evidence.*

### Linux SSH investigation and dashboards

![ Ubuntu user and authentication logs arriving in Wazuh. ](<images/31. Ubuntu user logs showing up.png>)

*Ubuntu user and authentication logs arriving in Wazuh.*

![ Failed SSH authentication attempts using an invalid username. ](<images/32. fake user trying to login.png>)

*Failed SSH authentication attempts using an invalid username.*

![ Successful SSH authentication for the configured lab user. ](<images/33. pbareki successful login.png>)

*Successful SSH authentication for the configured lab user.*

![ SSH session creation and session identifier evidence. ](<images/34. pbareki session created.png>)

*SSH session creation and session identifier evidence.*

![ Commands executed during the SSH session. ](<images/35 ssh session ran these commands.png>)

*Commands executed during the SSH session.*

![ whoami output confirming the effective user in the session. ](<images/36 proof of command line whoami.png>)

*whoami output confirming the effective user in the session.*

![ SSH login event for the lab user. ](<images/37 pbareki logging in event.png>)

*SSH login event for the lab user.*

![ SSH logout or session-closure event. ](<images/38. pbareki logged out event.png>)

*SSH logout or session-closure event.*

![ Wazuh dashboard creation workflow. ](<images/39. creating dashboards.png>)

*Wazuh dashboard creation workflow.*

![ Dashboard navigation menu. ](<images/40. dashboard menu.png>)

*Dashboard navigation menu.*

![ Additional dashboard navigation evidence. ](<images/40. dashboard menu 2.png>)

*Additional dashboard navigation evidence.*

![ Field-specific query used to count failed login attempts. ](<images/41. Use the right query to see how many failed login attempts.png>)

*Field-specific query used to count failed login attempts.*

![ Saved dashboard after creating the initial visualization. ](<images/42. Saved dashboard.png>)

*Saved dashboard after creating the initial visualization.*

![ Index-pattern field list refresh used when fields were missing from visualizations. ](<images/43. In case fields don't show up refresh.png>)

*Index-pattern field list refresh used when fields were missing from visualizations.*

![ Time-series visualization of activity over time. ](<images/44. line chart showing query attempts.png>)

*Time-series visualization of activity over time.*

![ Linux failed-authentication activity visualization. ](<images/45. failed linux auth activivty.png>)

*Linux failed-authentication activity visualization.*

![ Wazuh interface showing the available dashboards. ](<images/46. all dashboards.png>)

*Wazuh interface showing the available dashboards.*

## Key takeaways

- **Collection is not the same as alerting.** Archives provide visibility into events that may not generate an alert. This supports investigation and dashboard development, but increases storage requirements.
- **Use structured fields, not broad numeric searches.** Filtering data.win.system.eventID is more reliable than searching for a number such as 4625 across every field.
- **Know the event source and channel.** Interpret an Event ID with its provider/channel and event details.
- **Understand the event schema.** Subject, target, SID, RID, group, logon type, Logon ID, process ID, and source IP answer different questions.
- **Correlate across time and identifiers.** A username alone is not enough to link a login, command execution, and logout. Use session identifiers, process IDs, timestamps, agent identity, and host context.
- **Validate missing fields.** The Linux failed-authentication records did not contain a destination username in the observed data. Keep missing values visible rather than making assumptions.
- **Dashboards depend on correct field mappings.** Refreshing the index-pattern field list resolved missing field options during chart construction.
- **Document only what was tested.** These simulations demonstrate telemetry and investigation skills; they do not prove every event automatically triggers a Wazuh alert rule.

## Recommended next steps

- Record exact Wazuh, Windows, Ubuntu, Sysmon, and Filebeat versions.
- Confirm the Wazuh manager host/IP and update the architecture diagram.
- Add an investigation write-up for each scenario: objective, steps, query, evidence, interpretation, and limitations.
- Add a custom Wazuh detection rule and test positive and negative cases.
- Document archive retention settings and monitor disk usage.
- Redact credentials and sensitive host details from screenshots. Never store passwords in README files, screenshots, shell history, or Git history.

## References

- [Wazuh: Event logging and archives](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [Wazuh: Wazuh indexer indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Wazuh: Global configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html)
- [Microsoft Learn: Windows Security event reference](https://learn.microsoft.com/azure/sentinel/windows-security-event-id-reference)
- [MITRE ATT&CK: Create Account – Local Account (T1136.001)](https://attack.mitre.org/techniques/T1136/001/)
- [MITRE ATT&CK: Additional Local or Domain Groups (T1098.007)](https://attack.mitre.org/techniques/T1098/007/)
- [MITRE ATT&CK: Password Guessing (T1110.001)](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK: Local Accounts (T1078.003)](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK: Local Account Discovery (T1087.001)](https://attack.mitre.org/techniques/T1087/001/)
- [MITRE ATT&CK: System Network Configuration Discovery (T1016)](https://attack.mitre.org/techniques/T1016/)
