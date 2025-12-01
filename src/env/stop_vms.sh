#!/bin/bash
# This script will stop all VMs gracefully

# Stop all VMs
VBoxManage controlvm "Attacker" poweroff
VBoxManage controlvm "Victim" poweroff
VBoxManage controlvm "Gateway" poweroff
VBoxManage controlvm "DNS" poweroff

echo "All VMs have been powered off."

# Use ./stop_vms.sh to execute the script.