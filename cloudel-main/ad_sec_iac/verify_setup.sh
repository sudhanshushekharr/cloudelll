# Run this script before your presentation

cd ~/Downloads/cloudel-main/ad_sec_iac

echo "=== Pre-Presentation Checklist ==="

# 1. Check Wazuh is running
echo "1. Checking Wazuh Manager..."
sudo systemctl status wazuh-manager | grep Active

# 2. Check agents connected
echo "2. Checking Wazuh agents..."
sudo /var/ossec/bin/agent_control -l

# 3. Check custom rules loaded
echo "3. Checking custom rules..."
sudo grep "rule id=\"100" /var/ossec/etc/rules/local_rules.xml | wc -l

# 4. Check Windows connectivity
echo "4. Testing Windows connectivity..."
ansible windows -m win_ping

# 5. Check Sysmon on Windows
echo "5. Checking Sysmon..."
ansible windows -m ansible.windows.win_shell -a "Get-Service Sysmon64 | Select Name,Status"

# 6. Check current mode
echo "6. Current deployment mode..."
grep deployment_mode group_vars/all.yml

# 7. Test Wazuh dashboard
echo "7. Wazuh Dashboard should be at: http://localhost:5601"
echo "   Username: admin"

echo ""
echo "=== Ready for Demo! ==="