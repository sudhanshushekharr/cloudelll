# Active Directory Security Lab - Infrastructure as Code

Complete Ansible automation for AD security hardening, attack simulation, detection, and automated response.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Deployment Modes](#deployment-modes)
- [Components](#components)
- [Usage Guide](#usage-guide)
- [Attack Simulation Workflow](#attack-simulation-workflow)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

This project implements a complete Infrastructure as Code (IaC) solution for:

- **Baseline Security Hardening**: Password policies, service configurations, protocol security
- **Advanced Monitoring**: Sysmon deployment, audit policies, PowerShell logging
- **AD-Specific Security**: Kerberos hardening, honeypot accounts, delegation controls
- **Threat Detection**: Custom Wazuh rules for common AD attacks
- **Automated Response**: Intelligent active response to detected threats

### Key Features

✅ **Two Operating Modes**: Switch between vulnerable and protected states  
✅ **Complete Automation**: One command deployment  
✅ **Real Detection**: Custom rules for Mimikatz, Kerberoasting, BloodHound, etc.  
✅ **Active Response**: Automated threat remediation when in protected mode  
✅ **Compliance Checking**: Automated security posture validation

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Ubuntu (Wazuh Manager)                │
│  - Wazuh Manager                                        │
│  - Custom Detection Rules                               │
│  - Active Response Engine                               │
└───────────────────┬─────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
┌───────▼──────┐       ┌───────▼──────┐
│  Windows     │       │  Windows     │
│  Server 2022 │       │  Server 2025 │
│  (DC22)      │       │  (DC25)      │
│              │       │              │
│  - Sysmon    │       │  - Sysmon    │
│  - Wazuh     │       │  - Wazuh     │
│    Agent     │       │    Agent     │
│  - Hardening │       │  - Hardening │
└──────────────┘       └──────────────┘
```

## 📦 Prerequisites

### On Your Control Machine (where you run Ansible)

```bash
# Install Ansible
sudo apt update
sudo apt install ansible python3-pip

# Install required collections
ansible-galaxy collection install ansible.windows
ansible-galaxy collection install community.windows

# Install Python WinRM
pip3 install pywinrm
```

### On Windows Machines (Already Done)

✅ WinRM configured  
✅ ansible_automation user created  
✅ Basic authentication enabled

### On Ubuntu (Wazuh Manager)

Wazuh should already be installed with agents connected from Windows machines.

## 🚀 Quick Start

### 1. Configure Your Environment

Edit `group_vars/all.yml`:

```yaml
wazuh_manager_ip: "YOUR_UBUNTU_IP" # Replace with actual IP
```

Verify `inventory.ini` has correct IPs for your Windows machines.

### 2. Test Connectivity

```bash
ansible windows -m win_ping
```

You should see SUCCESS for both hosts.

### 3. Deploy in Vulnerable Mode (for demonstration)

```bash
ansible-playbook deploy_all.yml -e "deployment_mode=vulnerable"
```

This will:

- Deploy baseline configurations (weak in vulnerable mode)
- Install and configure Sysmon
- Setup audit policies
- Configure AD security settings
- Deploy Wazuh rules (detection only, no active response)

### 4. Run Your Attacks

Now you can run Mimikatz, BloodHound, etc. The attacks will succeed, but Wazuh will detect and alert.

### 5. Switch to Protected Mode

```bash
./switch-mode.sh protected
```

Or manually:

```bash
ansible-playbook deploy_all.yml -e "deployment_mode=protected"
```

This will:

- Strengthen all security controls
- Enable active responses in Wazuh
- Deploy honeypots
- Implement credential protections

### 6. Test Active Response

Run the same attacks again. Now they should be automatically blocked/remediated.

## 🔄 Deployment Modes

### Vulnerable Mode

**Purpose**: Demonstrate attacks and detections

**Characteristics**:

- Weak password policies (min length: 6, no lockout)
- LLMNR/NetBIOS enabled
- WDigest enabled (allows plaintext credential capture)
- Windows Defender disabled
- Wazuh detects attacks but **does not block**
- No honeypots deployed

**Use Case**:

1. Run attack simulations
2. Show detections in Wazuh
3. Demonstrate what happens without security controls

### Protected Mode

**Purpose**: Demonstrate automated defense

**Characteristics**:

- Strong password policies (min length: 14, lockout after 5 attempts)
- LLMNR/NetBIOS disabled
- WDigest disabled
- Credential Guard enabled
- Wazuh **actively responds** to threats
- Honeypot accounts and files deployed

**Use Case**:

1. Run same attacks
2. Show automated blocking/remediation
3. Demonstrate security controls in action

## 🧩 Components

### 1. Baseline Hardening (`01_baseline_hardening.yml`)

Configures fundamental security settings:

- Password complexity and age requirements
- Account lockout policies
- PowerShell logging (module, script block, transcription)
- Disables vulnerable protocols (SMBv1, LLMNR, NetBIOS)
- Stops unnecessary services
- Credential protection (WDigest, Credential Guard)

### 2. Sysmon Deployment (`02_deploy_sysmon.yml`)

Deploys Microsoft Sysmon with custom configuration:

- Process creation monitoring with command line
- Network connections
- LSASS memory access detection
- File creation tracking
- Registry modifications
- Named pipe monitoring
- WMI event tracking

### 3. Audit Configuration (`03_configure_auditing.yml`)

Enables comprehensive Windows audit policies:

- Account logon events
- Account management
- Logon/logoff events
- Object access (files, registry)
- Policy changes
- Privilege use
- Kerberos authentication

Configures:

- Command line auditing in process events
- Increased event log sizes (2GB for Security log)
- Log retention policies

### 4. AD Security (`04_ad_security.yml`)

Active Directory-specific hardening:

- NTLM restriction (deny all in protected mode)
- Kerberos encryption hardening (disable RC4)
- Honeypot accounts with Domain Admin privileges
- Honeypot files with fake credentials
- Protected Users group configuration
- Stale account detection
- Service account (SPN) auditing
- Unconstrained delegation checks

### 5. Wazuh Integration (`05_wazuh_integration.yml`)

Deploys detection and response capabilities:

- Custom detection rules for:

  - Mimikatz
  - LSASS memory access
  - Kerberoasting (Rubeus)
  - BloodHound enumeration
  - Responder
  - Pass-the-Hash
  - Honeypot triggers
  - Persistence mechanisms
  - PowerShell obfuscation

- Active response actions:
  - Kill malicious processes
  - Disable compromised accounts
  - Force user logoff
  - Delete attack artifacts
  - Optional network isolation

### 6. Compliance Checking (`07_compliance_check.yml`)

Automated security posture validation:

- Password policy verification
- Service configuration checks
- Protocol security status
- Audit policy compliance
- Sysmon operational status
- PowerShell logging verification
- Overall security score calculation

## 📖 Usage Guide

### Deploy Everything

```bash
# Vulnerable mode
ansible-playbook deploy_all.yml -e "deployment_mode=vulnerable"

# Protected mode
ansible-playbook deploy_all.yml -e "deployment_mode=protected"
```

### Deploy Individual Components

```bash
# Just hardening
ansible-playbook playbooks/01_baseline_hardening.yml

# Just Sysmon
ansible-playbook playbooks/02_deploy_sysmon.yml

# Just Wazuh integration
ansible-playbook playbooks/05_wazuh_integration.yml
```

### Switch Modes Quickly

```bash
chmod +x switch-mode.sh
./switch-mode.sh vulnerable
./switch-mode.sh protected
```

### Run Compliance Check

```bash
ansible-playbook playbooks/07_compliance_check.yml
```

Creates reports in `./compliance_reports/`

### Check Active Response Logs (on Ubuntu)

```bash
tail -f /var/ossec/logs/active-responses.log
```

### View Wazuh Alerts (on Ubuntu)

```bash
tail -f /var/ossec/logs/alerts/alerts.log
```

## 🎭 Attack Simulation Workflow

### Phase 1: Vulnerable Mode Demo

```bash
# 1. Deploy vulnerable configuration
./switch-mode.sh vulnerable

# 2. On Windows machine, run Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# 3. Check Wazuh dashboard - you'll see:
#    - Rule 100010/100011: Mimikatz detected
#    - Alert level 15
#    - But NO active response (because we're in vulnerable mode)

# 4. Run BloodHound
.\SharpHound.exe -c All

# 5. Check Wazuh again:
#    - Rule 100050: BloodHound detected
#    - Data collection completed (no blocking)
```

### Phase 2: Protected Mode Demo

```bash
# 1. Switch to protected mode
./switch-mode.sh protected

# 2. Wait for deployment to complete (2-3 minutes)

# 3. Try Mimikatz again
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# 4. Check what happened:
#    - Wazuh detected the attack
#    - Active response killed the process
#    - Your account may be disabled
#    - Check: tail -f /var/ossec/logs/active-responses.log

# 5. Try accessing honeypot file
type C:\Users\Public\Documents\passwords.txt

# 6. Check response:
#    - Rule 100081: Honeypot file accessed
#    - Account immediately disabled
#    - All processes killed
#    - Forced logoff
```

### Phase 3: Demonstrate Detection Without Blocking

If you want detections but no blocking during a specific demo:

```bash
# On Ubuntu, edit Wazuh config
sudo nano /var/ossec/etc/ossec.conf

# Find your active-response blocks and change:
<disabled>no</disabled>
# to:
<disabled>yes</disabled>

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

## 🔍 Monitoring and Verification

### Check Deployment Status

```bash
# View last deployment summary
ls -lt deployment_summary_*.txt | head -1 | xargs cat
```

### Verify Sysmon

```powershell
# On Windows
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

### Verify Audit Policies

```cmd
# On Windows
auditpol /get /category:*
```

### Verify Active Responses

```bash
# On Ubuntu
grep "Active Response" /var/ossec/logs/active-responses.log | tail -20
```

### Check Honeypot Status

```powershell
# On Windows (DC only)
Get-ADUser admin_backup
Get-ADUser svc_test
Test-Path "C:\Users\Public\Documents\passwords.txt"
```

## 🐛 Troubleshooting

### WinRM Connection Issues

```bash
# Test WinRM manually
telnet 10.51.202.134 5985

# Verify authentication
ansible windows -m ansible.windows.win_whoami
```

### Wazuh Rules Not Loading

```bash
# On Ubuntu, validate rules
/var/ossec/bin/wazuh-logtest -t < /dev/null

# Check for syntax errors
grep -i error /var/ossec/logs/ossec.log
```

### Active Response Not Triggering

```bash
# Check if responses are enabled
grep "disabled" /var/ossec/etc/ossec.conf | grep -A2 "active-response"

# Verify script has execute permissions
ls -l /var/ossec/active-response/bin/remediate-threat.sh

# Check script logs
tail -100 /var/ossec/logs/active-responses.log
```

### Sysmon Not Capturing Events

```powershell
# On Windows, check service
Get-Service Sysmon64

# Verify config
Get-Content "C:\Program Files\Sysmon\sysmonconfig.xml"

# Check event log
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### Compliance Check Failures

```bash
# Run with verbose output
ansible-playbook playbooks/07_compliance_check.yml -vvv

# Check individual host
ansible dc25 -m ansible.windows.win_shell -a "net accounts"
```

## 📊 Reports and Outputs

### Generated on Windows Machines

- `C:\hardening_report_{mode}.json` - Security configuration summary
- `C:\audit_policy_{mode}.txt` - Current audit policies
- `C:\ad_security_report.json` - AD-specific security status
- `C:\compliance_report.json` - Latest compliance check results

### Generated on Control Machine

- `deployment_summary_{mode}_{timestamp}.txt` - Deployment summary
- `compliance_reports/` - Individual host compliance reports

### Generated on Wazuh Manager

- `/var/ossec/logs/alerts/alerts.log` - All security alerts
- `/var/ossec/logs/active-responses.log` - Active response actions
- `/var/ossec/etc/rules/local_rules.xml` - Custom detection rules

## 🎓 Demo Script for Presentation

### Introduction (2 minutes)

"I've built an automated security infrastructure for Active Directory that can operate in two modes: vulnerable for demonstrations, and protected with automated threat response."

### Part 1: Vulnerable Mode (5 minutes)

```bash
# Show current state
./switch-mode.sh vulnerable
cat group_vars/all.yml | grep deployment_mode

# Show what gets deployed
cat deployment_summary_vulnerable_*.txt

# Run attacks (have these prepared)
# - Mimikatz (show it works)
# - BloodHound (show enumeration succeeds)
# - Show Wazuh detecting but not blocking
```

### Part 2: The Switch (1 minute)

```bash
# Show the automation
./switch-mode.sh protected

# Explain what changed:
# - Strong password policies
# - Disabled vulnerable protocols
# - Active responses enabled
# - Honeypots deployed
```

### Part 3: Protected Mode (5 minutes)

```bash
# Run same attacks
# - Mimikatz gets killed
# - Account gets disabled
# - Show active response logs

# Trigger honeypot
# - Show immediate response
# - Show all processes killed
# - Show account disabled

# Show compliance
ansible-playbook playbooks/07_compliance_check.yml
```

### Conclusion (2 minutes)

"This demonstrates how Infrastructure as Code enables rapid deployment and testing of security controls, and how automated response can contain threats in real-time."

## 🔐 Security Considerations

### For Production Use

⚠️ **This lab is designed for educational purposes**

Before using in production:

1. **Review all passwords** - Change default credentials
2. **Customize active responses** - Some actions (account disable, network isolation) are very aggressive
3. **Test thoroughly** - Ensure responses don't impact legitimate users
4. **Implement gradual rollout** - Start with alerting only
5. **Add approval workflows** - For critical actions like account disable
6. **Monitor false positives** - Tune detection rules appropriately
7. **Backup configurations** - Before deploying changes

### Honeypot Warning

The honeypot accounts have **Domain Admin** privileges by design. In production:

- Use lower privilege accounts
- Ensure they cannot be used for actual access
- Monitor them continuously

## 📚 Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Ansible Windows Guide](https://docs.ansible.com/ansible/latest/user_guide/windows.html)
- [AD Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

## 🤝 Contributing

Suggestions for improvement:

- Additional detection rules
- More sophisticated active responses
- Integration with SOAR platforms
- Automated forensic collection
- Machine learning-based anomaly detection

## 📝 License

Educational use only. Modify as needed for your environment.

## ✉️ Support

For issues or questions about this implementation, review the troubleshooting section or check the generated logs for detailed error messages.
