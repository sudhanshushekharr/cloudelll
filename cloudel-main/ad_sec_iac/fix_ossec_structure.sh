#!/bin/bash
set -e

echo "=== Fixing ossec.conf structure ==="

# Must run as root
if [ "$EUID" -ne 0 ]; then 
    sudo bash "$0" "$@"
    exit $?
fi

# 1. Backup
echo "1. Creating backup..."
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup.$(date +%s)

# 2. Remove the problematic blocks from second ossec_config section
echo "2. Removing active-response from wrong location..."
sed -i '/<!-- BEGIN ANSIBLE MANAGED BLOCK - Active Responses -->/,/<!-- END ANSIBLE MANAGED BLOCK -->/d' /var/ossec/etc/ossec.conf

# 3. Now add them to the FIRST ossec_config (before the closing tag of FIRST section)
echo "3. Adding active-response blocks to correct location..."

# Find the line number of the FIRST </ossec_config>
FIRST_CLOSE=$(grep -n "^</ossec_config>" /var/ossec/etc/ossec.conf | head -1 | cut -d: -f1)

# Insert active-response blocks BEFORE that line
sed -i "${FIRST_CLOSE}i\\
\\
  <!-- BEGIN ANSIBLE MANAGED BLOCK - Active Responses -->\\
  <!-- Mimikatz Detection -->\\
  <active-response>\\
    <disabled>yes</disabled>\\
    <command>remediate-threat</command>\\
    <location>local</location>\\
    <rules_id>100010,100011</rules_id>\\
  </active-response>\\
\\
  <!-- LSASS Access -->\\
  <active-response>\\
    <disabled>yes</disabled>\\
    <command>remediate-threat</command>\\
    <location>local</location>\\
    <rules_id>100020</rules_id>\\
  </active-response>\\
\\
  <!-- Kerberoasting -->\\
  <active-response>\\
    <disabled>yes</disabled>\\
    <command>remediate-threat</command>\\
    <location>local</location>\\
    <rules_id>100040,100041</rules_id>\\
  </active-response>\\
\\
  <!-- BloodHound -->\\
  <active-response>\\
    <disabled>yes</disabled>\\
    <command>remediate-threat</command>\\
    <location>local</location>\\
    <rules_id>100050,100051</rules_id>\\
  </active-response>\\
\\
  <!-- Honeypot (CRITICAL) -->\\
  <active-response>\\
    <disabled>yes</disabled>\\
    <command>remediate-threat</command>\\
    <location>local</location>\\
    <rules_id>100080,100081</rules_id>\\
  </active-response>\\
\\
  <!-- Pass-the-Hash -->\\
  <active-response>\\
    <disabled>yes</disabled>\\
    <command>remediate-threat</command>\\
    <location>local</location>\\
    <rules_id>100110</rules_id>\\
  </active-response>\\
  <!-- END ANSIBLE MANAGED BLOCK -->\\
" /var/ossec/etc/ossec.conf

echo "4. Validating configuration..."
if /var/ossec/bin/wazuh-logtest -t 2>&1 | grep -i "ERROR"; then
    echo "   ✗ Configuration has errors!"
    echo "   Restoring backup..."
    cp /var/ossec/etc/ossec.conf.backup.* /var/ossec/etc/ossec.conf
    exit 1
else
    echo "   ✓ Configuration is valid!"
fi

echo "5. Restarting Wazuh..."
systemctl restart wazuh-manager
sleep 10

echo "6. Verifying service..."
if systemctl is-active --quiet wazuh-manager; then
    echo "   ✓ Wazuh Manager is running"
else
    echo "   ✗ Service failed to start"
    exit 1
fi

echo ""
echo "=== Fix Complete! ==="
echo ""
echo "The active-response blocks are now in the correct location."
