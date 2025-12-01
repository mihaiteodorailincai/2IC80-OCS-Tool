#!/bin/bash
# Script to start virtual machines in headless mode (no GUI)

VBoxManage startvm "Attacker" --type headless
VBoxManage startvm "Victim" --type headless
VBoxManage startvm "Gateway" --type headless
VBoxManage startvm "DNS" --type headless

echo "All VMs started in headless mode."

# Use ./start_vms.sh to execute the script. 