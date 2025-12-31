#!/bin/bash
# Wazuh Active Response Script for Windows Threats
# This script will be called by Wazuh when specific alerts are triggered
# Save to: /var/ossec/active-response/bin/remediate-threat.sh

LOCAL=$(dirname $0)
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging
LOG_FILE="${PWD}/../logs/active-responses.log"

# Read input from Wazuh
read INPUT_JSON

# Extract alert information
ALERT_ID=$(echo $INPUT_JSON | jq -r '.parameters.alert.rule.id // empty')
AGENT_ID=$(echo $INPUT_JSON | jq -r '.parameters.alert.agent.id // empty')
AGENT_NAME=$(echo $INPUT_JSON | jq -r '.parameters.alert.agent.name // empty')
AGENT_IP=$(echo $INPUT_JSON | jq -r '.parameters.alert.agent.ip // empty')
RULE_LEVEL=$(echo $INPUT_JSON | jq -r '.parameters.alert.rule.level // empty')
DESCRIPTION=$(echo $INPUT_JSON | jq -r '.parameters.alert.rule.description // empty')
USERNAME=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.win.system.targetUserName // empty')
PROCESS=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.win.eventdata.image // empty')

# Log the alert
echo "$(date '+%Y-%m-%d %H:%M:%S') - Active Response Triggered" >>${LOG_FILE}
echo "  Alert ID: ${ALERT_ID}" >>${LOG_FILE}
echo "  Agent: ${AGENT_NAME} (${AGENT_IP})" >>${LOG_FILE}
echo "  Rule Level: ${RULE_LEVEL}" >>${LOG_FILE}
echo "  Description: ${DESCRIPTION}" >>${LOG_FILE}

# Response actions based on Rule ID
case ${ALERT_ID} in

# Mimikatz Detection (Rule 100010, 100011)
100010 | 100011)
  echo "  Action: Mimikatz detected - Initiating containment" >>${LOG_FILE}

  # Kill the process if still running
  if [ ! -z "$PROCESS" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "taskkill /F /IM $(basename $PROCESS) 2>nul"
    echo "  Killed process: $PROCESS" >>${LOG_FILE}
  fi

  # Disable the compromised account if identified
  if [ ! -z "$USERNAME" ] && [ "$USERNAME" != "SYSTEM" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "net user $USERNAME /active:no 2>nul"
    echo "  Disabled user account: $USERNAME" >>${LOG_FILE}
  fi

  # Isolate the machine (disable network adapter)
  # CAUTION: This will disconnect the machine from network
  # /var/ossec/bin/agent_control -b "$AGENT_ID" -e "netsh interface set interface \"Ethernet\" disable"
  echo "  Note: Network isolation available but not executed" >>${LOG_FILE}
  ;;

# LSASS Memory Access (Rule 100020)
100020)
  echo "  Action: LSASS memory access detected - Logging and alerting" >>${LOG_FILE}

  # Kill the suspicious process
  if [ ! -z "$PROCESS" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "taskkill /F /IM $(basename $PROCESS) 2>nul"
    echo "  Killed suspicious process: $PROCESS" >>${LOG_FILE}
  fi

  # Force logoff all sessions of the user
  if [ ! -z "$USERNAME" ] && [ "$USERNAME" != "SYSTEM" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "logoff \$(query user | findstr $USERNAME | awk '{print \$3}') 2>nul"
    echo "  Logged off user: $USERNAME" >>${LOG_FILE}
  fi
  ;;

# Kerberoasting (Rule 100040, 100041)
100040 | 100041)
  echo "  Action: Kerberoasting detected" >>${LOG_FILE}

  # Kill Rubeus/Kerberoasting tool
  if [ ! -z "$PROCESS" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "taskkill /F /IM $(basename $PROCESS) 2>nul"
    echo "  Killed Kerberoasting tool: $PROCESS" >>${LOG_FILE}
  fi

  # Reset password for targeted service accounts (would need specific logic)
  echo "  Recommendation: Reset passwords for service accounts with SPNs" >>${LOG_FILE}
  ;;

# BloodHound Detection (Rule 100050, 100051)
100050 | 100051)
  echo "  Action: BloodHound enumeration detected" >>${LOG_FILE}

  # Kill BloodHound/SharpHound
  if [ ! -z "$PROCESS" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "taskkill /F /IM $(basename $PROCESS) 2>nul"
    echo "  Killed enumeration tool: $PROCESS" >>${LOG_FILE}
  fi

  # Delete BloodHound output files
  /var/ossec/bin/agent_control -b "$AGENT_ID" -e "del /F /Q C:\\Users\\*\\*bloodhound*.zip 2>nul"
  /var/ossec/bin/agent_control -b "$AGENT_ID" -e "del /F /Q C:\\Users\\*\\*bloodhound*.json 2>nul"
  echo "  Attempted to delete BloodHound output files" >>${LOG_FILE}
  ;;

# Honeypot Account/File Access (Rule 100080, 100081)
100080 | 100081)
  echo "  Action: CRITICAL - Honeypot triggered!" >>${LOG_FILE}

  # This is a high-confidence indicator of malicious activity
  # Disable the attacker's account immediately
  if [ ! -z "$USERNAME" ] && [ "$USERNAME" != "SYSTEM" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "net user $USERNAME /active:no 2>nul"
    echo "  EMERGENCY: Disabled account: $USERNAME" >>${LOG_FILE}
  fi

  # Kill all processes owned by the user
  if [ ! -z "$USERNAME" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "taskkill /F /FI \"USERNAME eq $USERNAME\" 2>nul"
    echo "  Killed all processes for user: $USERNAME" >>${LOG_FILE}
  fi

  # Force immediate logoff
  if [ ! -z "$USERNAME" ]; then
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "logoff \$(query user | findstr $USERNAME | awk '{print \$3}') /V 2>nul"
  fi
  ;;

# Pass-the-Hash (Rule 100110)
100110)
  echo "  Action: Possible Pass-the-Hash attack" >>${LOG_FILE}

  if [ ! -z "$USERNAME" ]; then
    # Force password reset on next logon
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "net user $USERNAME /logonpasswordchg:yes 2>nul"
    echo "  Forced password reset for: $USERNAME" >>${LOG_FILE}

    # Logoff the user
    /var/ossec/bin/agent_control -b "$AGENT_ID" -e "logoff \$(query user | findstr $USERNAME | awk '{print \$3}') 2>nul"
  fi
  ;;

*)
  echo "  Action: No specific automated response defined for Rule ${ALERT_ID}" >>${LOG_FILE}
  ;;
esac

# Send email notification for critical alerts (Level 12+)
if [ "$RULE_LEVEL" -ge 12 ]; then
  echo "  Sending email notification for critical alert" >>${LOG_FILE}
  # Configure your email sending here
fi

echo "  Active Response Completed" >>${LOG_FILE}
echo "---" >>${LOG_FILE}

exit 0
