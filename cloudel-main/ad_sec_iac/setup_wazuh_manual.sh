#!/bin/bash
# Manual Wazuh Setup Script
# Run this instead of the Wazuh playbook

set -e  # Exit on error

echo "=== Wazuh Integration Setup ==="
echo ""

# Get current directory
PROJECT_DIR=$(pwd)

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "This script needs sudo privileges. Re-running with sudo..."
    sudo bash "$0" "$@"
    exit $?
fi

# Get deployment mode
DEPLOYMENT_MODE="vulnerable"
if [ ! -z "$1" ]; then
    DEPLOYMENT_MODE="$1"
fi

echo "Deployment Mode: $DEPLOYMENT_MODE"
echo ""

# 1. Install jq if needed
echo "1. Installing dependencies..."
apt-get install -y jq > /dev/null 2>&1
echo "   ✓ jq installed"

# 2. Copy custom rules
echo "2. Deploying custom Wazuh rules..."
cp "$PROJECT_DIR/files/wazuh_rules/local_rules.xml" /var/ossec/etc/rules/local_rules.xml
chown root:wazuh /var/ossec/etc/rules/local_rules.xml
chmod 640 /var/ossec/etc/rules/local_rules.xml
RULES_COUNT=$(grep -c '<rule id="100' /var/ossec/etc/rules/local_rules.xml)
echo "   ✓ Deployed $RULES_COUNT custom rules"

# 3. Copy active response script
echo "3. Deploying active response script..."
cp "$PROJECT_DIR/files/scripts/remediate-threat.sh" /var/ossec/active-response/bin/remediate-threat.sh
chown root:wazuh /var/ossec/active-response/bin/remediate-threat.sh
chmod 750 /var/ossec/active-response/bin/remediate-threat.sh
echo "   ✓ Active response script deployed"

# 4. Configure active responses in ossec.conf
echo "4. Configuring active responses..."

# Remove old ansible-managed blocks if they exist
sed -i '/<!-- BEGIN ANSIBLE MANAGED/,/<!-- END ANSIBLE MANAGED/d' /var/ossec/etc/ossec.conf

# Determine disabled status
if [ "$DEPLOYMENT_MODE" = "protected" ]; then
    DISABLED="no"
    echo "   Mode: PROTECTED (responses ENABLED)"
else
    DISABLED="yes"
    echo "   Mode: VULNERABLE (responses DISABLED)"
fi

# Add command definition (before </ossec_config>)
if ! grep -q "<name>remediate-threat</name>" /var/ossec/etc/ossec.conf; then
    sed -i '/<\/ossec_config>/i \
  <!-- BEGIN ANSIBLE MANAGED BLOCK - Command -->\
  <command>\
    <name>remediate-threat</name>\
    <executable>remediate-threat.sh</executable>\
    <timeout_allowed>no</timeout_allowed>\
  </command>\
  <!-- END ANSIBLE MANAGED BLOCK -->' /var/ossec/etc/ossec.conf
    echo "   ✓ Command definition added"
fi

# Add active response blocks
cat >> /var/ossec/etc/ossec.conf << ACTIVERESPONSE

  <!-- BEGIN ANSIBLE MANAGED BLOCK - Active Responses -->
  <!-- Mimikatz Detection -->
  <active-response>
    <disabled>$DISABLED</disabled>
    <command>remediate-threat</command>
    <location>local</location>
    <rules_id>100010,100011</rules_id>
    <timeout>no</timeout>
  </active-response>

  <!-- LSASS Access -->
  <active-response>
    <disabled>$DISABLED</disabled>
    <command>remediate-threat</command>
    <location>local</location>
    <rules_id>100020</rules_id>
    <timeout>no</timeout>
  </active-response>

  <!-- Kerberoasting -->
  <active-response>
    <disabled>$DISABLED</disabled>
    <command>remediate-threat</command>
    <location>local</location>
    <rules_id>100040,100041</rules_id>
    <timeout>no</timeout>
  </active-response>

  <!-- BloodHound -->
  <active-response>
    <disabled>$DISABLED</disabled>
    <command>remediate-threat</command>
    <location>local</location>
    <rules_id>100050,100051</rules_id>
    <timeout>no</timeout>
  </active-response>

  <!-- Honeypot (CRITICAL) -->
  <active-response>
    <disabled>$DISABLED</disabled>
    <command>remediate-threat</command>
    <location>local</location>
    <rules_id>100080,100081</rules_id>
    <timeout>no</timeout>
  </active-response>

  <!-- Pass-the-Hash -->
  <active-response>
    <disabled>$DISABLED</disabled>
    <command>remediate-threat</command>
    <location>local</location>
    <rules_id>100110</rules_id>
    <timeout>no</timeout>
  </active-response>
  <!-- END ANSIBLE MANAGED BLOCK -->

ACTIVERESPONSE

echo "   ✓ Active response blocks configured"

# 5. Configure Sysmon log collection
echo "5. Configuring log collection..."
if ! grep -q "Microsoft-Windows-Sysmon/Operational" /var/ossec/etc/ossec.conf; then
    # This would require more complex sed, so just note it
    echo "   ! Manual check needed: Ensure Sysmon logs are configured in agent ossec.conf"
fi

# 6. Backup config
echo "6. Creating backup..."
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup.$(date +%s)
echo "   ✓ Config backed up"

# 7. Restart Wazuh
echo "7. Restarting Wazuh Manager..."
systemctl restart wazuh-manager
sleep 5

# 8. Verify
echo "8. Verifying setup..."
if systemctl is-active --quiet wazuh-manager; then
    echo "   ✓ Wazuh Manager is running"
else
    echo "   ✗ WARNING: Wazuh Manager is not running!"
    exit 1
fi

# Check logs for errors
if grep -i error /var/ossec/logs/ossec.log | tail -5 | grep -v "INFO" > /dev/null; then
    echo "   ⚠ Warning: Errors found in Wazuh logs"
    echo "   Check: tail -20 /var/ossec/logs/ossec.log"
fi

# Count rules
TOTAL_RULES=$(grep "Total rules enabled" /var/ossec/logs/ossec.log | tail -1 | grep -oP '\d+' | tail -1)
echo "   ✓ Total rules loaded: $TOTAL_RULES"

echo ""
echo "=== Wazuh Integration Complete ==="
echo ""
echo "Summary:"
echo "  - Custom Rules: $RULES_COUNT deployed"
echo "  - Active Response: $DISABLED (disabled=$DISABLED)"
echo "  - Mode: $DEPLOYMENT_MODE"
echo ""
echo "To check alerts: tail -f /var/ossec/logs/alerts/alerts.log"
echo "To check responses: tail -f /var/ossec/logs/active-responses.log"
echo ""
