# Complete Setup Guide

## 📋 Prerequisites Checklist

Before starting, ensure you have:

- [ ] 2 Windows Server machines (2022 and 2025) in AWS
- [ ] 1 Ubuntu machine (local) with Wazuh installed
- [ ] Windows machines configured with:
  - [ ] WinRM enabled
  - [ ] ansible_automation user created with Administrator rights
  - [ ] Basic auth enabled for WinRM
- [ ] Wazuh agents installed on Windows machines
- [ ] Network connectivity between all machines
- [ ] Control machine (your laptop/workstation) with Ansible installed

## 🔧 Step-by-Step Setup

### Step 1: Prepare Your Control Machine

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Ansible
sudo apt install -y ansible python3-pip git

# Install Ansible collections for Windows
ansible-galaxy collection install ansible.windows
ansible-galaxy collection install community.windows

# Install WinRM library
pip3 install pywinrm

# Verify installation
ansible --version
```

### Step 2: Clone/Create Project Structure

```bash
# Create project directory
mkdir -p ~/ad-security-lab
cd ~/ad-security-lab

# Create directory structure
mkdir -p playbooks files/wazuh_rules files/scripts templates compliance_reports group_vars
```

### Step 3: Configure Inventory

Create `inventory.ini`:

```ini
[windows]
dc25 ansible_host=10.51.202.134
dc22 ansible_host=10.51.202.189

[domain_controllers]
dc25
dc22

[windows:vars]
ansible_user=ansible_automation
ansible_password=StrongPass!
ansible_connection=winrm
ansible_port=5985
ansible_winrm_transport=basic
ansible_winrm_server_cert_validation=ignore
```

**⚠️ Important**: Replace the IP addresses with your actual Windows machine IPs.

### Step 4: Configure Variables

Create `group_vars/all.yml`:

```yaml
---
# Replace with your Ubuntu Wazuh Manager IP
wazuh_manager_ip: "YOUR_UBUNTU_IP_HERE"

project_name: "ad_security_lab"
deployment_mode: "vulnerable" # Start in vulnerable mode
log_retention_days: 90
timezone: "UTC"
```

**⚠️ Critical**: Replace `YOUR_UBUNTU_IP_HERE` with your Ubuntu machine's IP address.

### Step 5: Test Connectivity

```bash
# Test Windows connectivity
ansible windows -m win_ping

# Expected output:
# dc25 | SUCCESS => {
#     "changed": false,
#     "ping": "pong"
# }
# dc22 | SUCCESS => {
#     "changed": false,
#     "ping": "pong"
# }

# If you get errors, check:
# 1. IP addresses in inventory.ini
# 2. WinRM is running on Windows
# 3. Firewall allows port 5985
# 4. ansible_automation user exists and has admin rights
```

### Step 6: Deploy All Configuration Files

You need to create all these files (I've provided them in previous artifacts):

1. **ansible.cfg** - Ansible configuration
2. **group_vars/all.yml** - Global variables
3. **group_vars/windows.yml** - Windows-specific variables
4. **files/sysmonconfig.xml** - Sysmon configuration
5. **files/wazuh_rules/local_rules.xml** - Custom Wazuh rules
6. **files/scripts/remediate-threat.sh** - Active response script
7. **playbooks/01_baseline_hardening.yml** - Hardening playbook
8. **playbooks/02_deploy_sysmon.yml** - Sysmon deployment
9. **playbooks/03_configure_auditing.yml** - Audit configuration
10. **playbooks/04_ad_security.yml** - AD security
11. **playbooks/05_wazuh_integration.yml** - Wazuh integration
12. **playbooks/07_compliance_check.yml** - Compliance checking
13. **deploy_all.yml** - Master playbook
14. **switch-mode.sh** - Mode switching script

Copy all the artifacts I provided into these files.

### Step 7: Configure Wazuh Manager (Ubuntu)

SSH into your Ubuntu machine:

```bash
ssh user@YOUR_UBUNTU_IP
```

Verify Wazuh is installed and running:

```bash
systemctl status wazuh-manager
```

If not installed, install Wazuh:

```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

# Install Wazuh manager
apt-get update
apt-get install wazuh-manager

# Enable and start
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```

### Step 8: Verify Wazuh Agents

On Ubuntu, check that Windows agents are connected:

```bash
/var/ossec/bin/agent_control -l
```

You should see your Windows machines listed and connected.

If agents aren't connected, on Windows machines:

```powershell
# Check Wazuh service
Get-Service WazuhSvc

# Check Wazuh config
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Restart service
Restart-Service WazuhSvc
```

### Step 9: First Deployment (Vulnerable Mode)

From your control machine:

```bash
cd ~/ad-security-lab

# Deploy in vulnerable mode for testing
ansible-playbook deploy_all.yml -e "deployment_mode=vulnerable"
```

This will take 5-10 minutes. You'll see:

1. ✅ Baseline hardening applied
2. ✅ Sysmon installed and configured
3. ✅ Audit policies enabled
4. ✅ AD security settings configured
5. ✅ Wazuh rules deployed
6. ✅ Summary generated

### Step 10: Verify Deployment

```bash
# Check Windows machines
ansible windows -m ansible.windows.win_shell -a "Get-Service Sysmon64 | Select Name,Status"

# Check Sysmon is collecting events
ansible windows -m ansible.windows.win_shell -a "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1"

# On Ubuntu, check custom rules loaded
ssh user@YOUR_UBUNTU_IP
sudo tail /var/ossec/logs/ossec.log | grep "Total rules enabled"

# Should see your custom rules loaded
```

### Step 11: Test Detection (Without Response)

Since you're in vulnerable mode, attacks will work but will be detected.

On a Windows machine:

```powershell
# Create a test file that will trigger Sysmon
notepad C:\test_mimikatz.exe

# Check if it was detected
# On Ubuntu:
tail -f /var/ossec/logs/alerts/alerts.log
```

### Step 12: Enable Protected Mode

```bash
# Switch to protected mode
./switch-mode.sh protected

# Or manually:
ansible-playbook deploy_all.yml -e "deployment_mode=protected"
```

This will:

- Strengthen all security controls
- Enable active responses
- Deploy honeypots

### Step 13: Test Active Response

On Ubuntu, watch active response log:

```bash
tail -f /var/ossec/logs/active-responses.log
```

On Windows, trigger a detection:

```powershell
# Try to access honeypot file
type C:\Users\Public\Documents\passwords.txt
```

You should see:

1. Alert in Wazuh
2. Active response triggered
3. Your session may be terminated
4. Account may be disabled

### Step 14: Run Compliance Check

```bash
ansible-playbook playbooks/07_compliance_check.yml
```

Check results:

```bash
cat compliance_reports/*_compliance.json | jq .
```

## 🔍 Verification Checklist

After deployment, verify:

### On Windows Machines

- [ ] Sysmon service is running

  ```powershell
  Get-Service Sysmon64
  ```

- [ ] Sysmon events are being generated

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
  ```

- [ ] Audit policies are configured

  ```cmd
  auditpol /get /category:*
  ```

- [ ] Password policy is set

  ```cmd
  net accounts
  ```

- [ ] Wazuh agent is running and connected
  ```powershell
  Get-Service WazuhSvc
  Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String "server"
  ```

### On Wazuh Manager (Ubuntu)

- [ ] Wazuh service is running

  ```bash
  systemctl status wazuh-manager
  ```

- [ ] Agents are connected

  ```bash
  /var/ossec/bin/agent_control -l
  ```

- [ ] Custom rules are loaded

  ```bash
  grep "rule id" /var/ossec/etc/rules/local_rules.xml | wc -l
  ```

- [ ] Active response script exists and is executable

  ```bash
  ls -l /var/ossec/active-response/bin/remediate-threat.sh
  ```

- [ ] Alerts are being received
  ```bash
  tail -5 /var/ossec/logs/alerts/alerts.log
  ```

### On Control Machine

- [ ] Ansible can connect to all hosts

  ```bash
  ansible all -m ping
  ```

- [ ] Deployment summary was created

  ```bash
  ls -l deployment_summary_*.txt
  ```

- [ ] Mode switching script is executable
  ```bash
  ls -l switch-mode.sh
  ```

## 🐛 Common Issues and Solutions

### Issue: "unreachable" error with Ansible

**Solution:**

```bash
# Verify WinRM on Windows
Test-NetConnection -ComputerName localhost -Port 5985

# Check WinRM config
winrm get winrm/config

# If needed, reconfigure WinRM
winrm quickconfig -force
Set-Item WSMan:\localhost\Service\Auth\Basic $true
```

### Issue: Wazuh agents not connecting

**Solution:**

```powershell
# On Windows, check ossec.conf
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Should have correct server IP
# <server>
#   <address>YOUR_UBUNTU_IP</address>

# Restart agent
Restart-Service WazuhSvc

# Check connectivity
Test-NetConnection -ComputerName YOUR_UBUNTU_IP -Port 1514
```

### Issue: Sysmon not capturing events

**Solution:**

```powershell
# Verify service is running
Get-Service Sysmon64

# If not, restart
Restart-Service Sysmon64

# Check event log size (may be full)
wevtutil gl Microsoft-Windows-Sysmon/Operational

# Increase if needed
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
```

### Issue: Active responses not triggering

**Solution:**

```bash
# On Ubuntu, check if responses are disabled
grep -A5 "active-response" /var/ossec/etc/ossec.conf | grep disabled

# Should show <disabled>no</disabled> in protected mode

# Check script permissions
ls -l /var/ossec/active-response/bin/remediate-threat.sh
# Should be executable (750)

# Check if script has errors
bash -n /var/ossec/active-response/bin/remediate-threat.sh

# View response log for errors
tail -50 /var/ossec/logs/active-responses.log
```

### Issue: Playbook fails on certain tasks

**Solution:**

```bash
# Run with verbose output
ansible-playbook deploy_all.yml -vvv -e "deployment_mode=vulnerable"

# Run specific playbook to isolate issue
ansible-playbook playbooks/01_baseline_hardening.yml -vvv

# Check if it's a Windows version issue
ansible windows -m ansible.windows.win_shell -a "systeminfo | findstr OS"
```

## 📚 Next Steps

After successful setup:

1. **Familiarize yourself with the system:**

   - Review the README.md
   - Study QUICK_REFERENCE.md
   - Understand each playbook

2. **Test in vulnerable mode:**

   - Run various attacks
   - Observe Wazuh detections
   - Review alert logs

3. **Test in protected mode:**

   - Run same attacks
   - Verify automated responses
   - Check response logs

4. **Customize for your needs:**

   - Adjust detection rules
   - Modify active responses
   - Add additional honeypots
   - Tune alert levels

5. **Practice demo workflow:**
   - Create a script for your presentation
   - Test mode switching
   - Prepare attack scenarios
   - Know how to show logs effectively

## 🎯 Project Deliverables

For your project, you should have:

1. **Working Infrastructure:**

   - 2 Windows DCs with security controls
   - 1 Wazuh manager with custom rules
   - Automated deployment via Ansible

2. **Documentation:**

   - README.md (complete guide)
   - QUICK_REFERENCE.md (command reference)
   - SETUP_GUIDE.md (this file)
   - Architecture diagrams

3. **Demonstration:**

   - Vulnerable mode with successful attacks
   - Protected mode with automated blocking
   - Compliance reporting
   - Mode switching capability

4. **Reports:**
   - Deployment summaries
   - Compliance check results
   - Active response logs
   - Security posture assessments

## ✅ Final Checklist

Before considering setup complete:

- [ ] All playbooks run without errors
- [ ] Both vulnerable and protected modes work
- [ ] Attack simulations are prepared
- [ ] Wazuh detects attacks in both modes
- [ ] Active responses work in protected mode
- [ ] Compliance checks complete successfully
- [ ] All documentation is ready
- [ ] Demo script is prepared
- [ ] Backup of all configurations exists

Congratulations! Your AD Security Lab is ready! 🎉
