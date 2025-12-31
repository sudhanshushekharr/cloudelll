# Quick Reference Guide

## 🚀 Common Commands

### Deployment

```bash
# Full deployment - vulnerable mode
ansible-playbook deploy_all.yml -e "deployment_mode=vulnerable"

# Full deployment - protected mode
ansible-playbook deploy_all.yml -e "deployment_mode=protected"

# Quick mode switch
./switch-mode.sh vulnerable
./switch-mode.sh protected
```

### Individual Components

```bash
# Hardening only
ansible-playbook playbooks/01_baseline_hardening.yml

# Sysmon only
ansible-playbook playbooks/02_deploy_sysmon.yml

# Auditing only
ansible-playbook playbooks/03_configure_auditing.yml

# AD security only
ansible-playbook playbooks/04_ad_security.yml

# Wazuh integration only
ansible-playbook playbooks/05_wazuh_integration.yml

# Compliance check
ansible-playbook playbooks/07_compliance_check.yml
```

### Testing & Verification

```bash
# Test connectivity
ansible windows -m win_ping

# Check what mode you're in
grep "deployment_mode" group_vars/all.yml

# Run ad-hoc command on all Windows hosts
ansible windows -m ansible.windows.win_shell -a "hostname"

# Check specific service
ansible windows -m ansible.windows.win_service -a "name=Sysmon64"
```

## 📊 Monitoring Commands

### On Windows (PowerShell)

```powershell
# Check Sysmon
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10

# Check audit policies
auditpol /get /category:*

# Check password policy
net accounts

# View security log
Get-WinEvent -LogName Security -MaxEvents 20

# Check PowerShell logging
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\*"

# Check running services
Get-Service | Where-Object {$_.Status -eq 'Running'}

# Check honeypot accounts (DC only)
Get-ADUser admin_backup
Get-ADUser svc_test
```

### On Ubuntu (Wazuh Manager)

```bash
# Wazuh service status
systemctl status wazuh-manager

# View real-time alerts
tail -f /var/ossec/logs/alerts/alerts.log

# View active response log
tail -f /var/ossec/logs/active-responses.log

# View ossec.log for errors
tail -f /var/ossec/logs/ossec.log

# Check agent status
/var/ossec/bin/agent_control -l

# Test rules manually
/var/ossec/bin/wazuh-logtest

# View custom rules
cat /var/ossec/etc/rules/local_rules.xml

# Restart Wazuh
systemctl restart wazuh-manager

# Check if active responses are enabled
grep -A5 "active-response" /var/ossec/etc/ossec.conf | grep disabled
```

## 🎯 Attack Simulation Commands

### Mimikatz

```powershell
# Basic credential dump
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Kerberos tickets
mimikatz.exe "privilege::debug" "sekurlsa::tickets" "exit"

# Expected Detection: Rule 100010, 100011
# Protected Mode Response: Process killed, account disabled
```

### BloodHound

```powershell
# SharpHound collection
.\SharpHound.exe -c All

# Expected Detection: Rule 100050, 100051
# Protected Mode Response: Process killed, output files deleted
```

### Kerberoasting

```powershell
# Using Rubeus
.\Rubeus.exe kerberoast

# Using PowerShell
Invoke-Kerberoast

# Expected Detection: Rule 100040, 100041
# Protected Mode Response: Process killed
```

### Responder

```bash
# On attacking machine
python Responder.py -I eth0 -wrf

# Expected Detection: Rule 100060, 100061
# Protected Mode Response: Process killed (if detected on Windows)
```

### AD Reconnaissance

```powershell
# Domain users
net user /domain

# Domain groups
net group /domain

# Domain admins
net group "Domain Admins" /domain

# Domain controllers
nltest /dclist:

# Expected Detection: Rule 100052
# Protected Mode Response: Logged, no immediate block
```

### Honeypot Trigger

```powershell
# Access honeypot file
type C:\Users\Public\Documents\passwords.txt

# Or
type C:\AdminTools\credentials.txt

# Attempt to use honeypot account
runas /user:admin_backup cmd

# Expected Detection: Rule 100081 (file), 100080 (account)
# Protected Mode Response: IMMEDIATE account disable, all processes killed, forced logoff
```

## 🔧 Troubleshooting Commands

### Ansible Issues

```bash
# Verbose output
ansible-playbook deploy_all.yml -vvv

# Check inventory
ansible-inventory --list

# Test specific host
ansible dc25 -m win_ping

# Check WinRM
ansible dc25 -m ansible.windows.win_shell -a "whoami"
```

### Windows Issues

```powershell
# Check WinRM
winrm enumerate winrm/config/listener

# Check WinRM service
Get-Service WinRM

# View WinRM logs
Get-WinEvent -LogName Microsoft-Windows-WinRM/Operational -MaxEvents 20

# Test from Windows to Wazuh (check connectivity)
Test-NetConnection -ComputerName WAZUH_IP -Port 1514
```

### Wazuh Issues

```bash
# Verify Wazuh is running
systemctl status wazuh-manager

# Check for errors
grep -i error /var/ossec/logs/ossec.log | tail -20

# Validate configuration
/var/ossec/bin/verify-agent-conf

# Check agent connection
/var/ossec/bin/agent_control -l

# Force agent reconnect (from Windows)
Restart-Service WazuhSvc

# Check rule loading
grep "Total rules enabled" /var/ossec/logs/ossec.log
```

## 📁 Important File Locations

### Ansible (Control Machine)

```
ansible/
├── inventory.ini                          # Host inventory
├── group_vars/all.yml                     # Global variables
├── deploy_all.yml                         # Master playbook
├── switch-mode.sh                         # Quick mode switcher
├── playbooks/                             # All playbooks
└── compliance_reports/                    # Generated compliance reports
```

### Windows Machines

```
C:\
├── hardening_report_{mode}.json           # Security config
├── audit_policy_{mode}.txt                # Audit settings
├── ad_security_report.json                # AD security status
├── compliance_report.json                 # Compliance check
├── Program Files\Sysmon\                  # Sysmon installation
│   ├── Sysmon64.exe
│   └── sysmonconfig.xml
└── PSTranscripts\                         # PowerShell transcripts
```

### Wazuh Manager (Ubuntu)

```
/var/ossec/
├── etc/
│   ├── ossec.conf                         # Main config
│   └── rules/local_rules.xml              # Custom rules
├── active-response/
│   └── bin/remediate-threat.sh            # Response script
├── logs/
│   ├── alerts/alerts.log                  # All alerts
│   ├── active-responses.log               # Response actions
│   └── ossec.log                          # Service log
└── bin/
    └── agent_control                      # Agent management
```

## 🔄 Workflow Cheat Sheet

### Demo Workflow

```bash
# 1. Start in vulnerable mode
./switch-mode.sh vulnerable

# 2. Run attacks and show detections
# (Mimikatz, BloodHound, etc.)

# 3. Switch to protected
./switch-mode.sh protected

# 4. Run same attacks, show blocking
# (Check active-responses.log)

# 5. Show compliance
ansible-playbook playbooks/07_compliance_check.yml
```

### Daily Operations

```bash
# Morning: Check status
ansible windows -m win_ping
systemctl status wazuh-manager

# Review overnight alerts
tail -100 /var/ossec/logs/alerts/alerts.log

# Run compliance check
ansible-playbook playbooks/07_compliance_check.yml

# Review and clear active responses
cat /var/ossec/logs/active-responses.log
```

### After Attack Simulation

```bash
# 1. Re-enable disabled accounts (if needed)
ansible dc25 -m ansible.windows.win_shell -a "net user USERNAME /active:yes"

# 2. Clear alerts (optional)
# Edit: /var/ossec/logs/alerts/alerts.log

# 3. Reset to vulnerable for next demo
./switch-mode.sh vulnerable
```

## 🎓 One-Liner Useful Commands

```bash
# Quick status check
ansible windows -m ansible.windows.win_shell -a "Get-Service Sysmon64,WazuhSvc | Select Name,Status"

# Check if active responses are on
ssh ubuntu@WAZUH_IP "grep -A2 'active-response' /var/ossec/etc/ossec.conf | grep disabled"

# Count Sysmon events
ansible windows -m ansible.windows.win_shell -a "(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue).Count"

# View last 5 Wazuh alerts
ssh ubuntu@WAZUH_IP "tail -5 /var/ossec/logs/alerts/alerts.log"

# Check which mode you're in
cat group_vars/all.yml | grep deployment_mode

# View last deployment summary
ls -t deployment_summary_*.txt | head -1 | xargs cat
```

## 🆘 Emergency Commands

### Disable All Active Responses Immediately

```bash
# On Wazuh Manager
sudo sed -i 's/<disabled>no<\/disabled>/<disabled>yes<\/disabled>/g' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

### Re-enable Disabled Accounts

```powershell
# On Domain Controller
Get-ADUser -Filter {Enabled -eq $false} | ForEach-Object {
    Enable-ADAccount -Identity $_.SamAccountName
    Write-Host "Enabled: $($_.SamAccountName)"
}
```

### Reset Everything to Default

```bash
# Redeploy in vulnerable mode
./switch-mode.sh vulnerable
```

### Stop Wazuh from Taking Action (But Keep Detecting)

```bash
# On Wazuh Manager - just disable active responses
sudo nano /var/ossec/etc/ossec.conf
# Change all <disabled>no</disabled> to <disabled>yes</disabled>
# Under each <active-response> block

sudo systemctl restart wazuh-manager
```

## 📞 Quick Diagnostics

```bash
# Is everything running?
ansible windows -m win_ping
ssh ubuntu@WAZUH_IP "systemctl is-active wazuh-manager"

# Are agents connected?
ssh ubuntu@WAZUH_IP "/var/ossec/bin/agent_control -l"

# Is Sysmon collecting?
ansible windows -m ansible.windows.win_shell -a "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1"

# Are alerts being generated?
ssh ubuntu@WAZUH_IP "tail -1 /var/ossec/logs/alerts/alerts.log"

# Is active response working?
ssh ubuntu@WAZUH_IP "tail -1 /var/ossec/logs/active-responses.log"
```
