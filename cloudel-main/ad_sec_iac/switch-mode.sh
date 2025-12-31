#!/bin/bash
# Quick mode switching script

MODE=$1

if [ -z "$MODE" ]; then
    echo "Usage: $0 [vulnerable|protected]"
    echo ""
    echo "Current mode:"
    grep "deployment_mode:" group_vars/all.yml
    exit 1
fi

if [ "$MODE" != "vulnerable" ] && [ "$MODE" != "protected" ]; then
    echo "Error: Mode must be 'vulnerable' or 'protected'"
    exit 1
fi

echo "=========================================="
echo "  Switching to $MODE mode"
echo "=========================================="
echo ""

# Update the deployment mode
sed -i "s/deployment_mode: .*/deployment_mode: \"$MODE\"/" group_vars/all.yml

# Run Windows playbooks (no sudo needed)
echo "Deploying Windows configurations..."
ansible-playbook playbooks/01_baseline_hardening.yml -e "deployment_mode=$MODE"
ansible-playbook playbooks/02_deploy_sysmon.yml
ansible-playbook playbooks/03_configure_auditing.yml
ansible-playbook playbooks/04_ad_security.yml -e "deployment_mode=$MODE"

# Setup Wazuh (needs sudo)
echo ""
echo "Configuring Wazuh..."
sudo ./setup_wazuh_manual.sh $MODE

echo ""
echo "=========================================="
echo "  Mode switch complete!"
echo "  Current mode: $MODE"
echo "=========================================="
