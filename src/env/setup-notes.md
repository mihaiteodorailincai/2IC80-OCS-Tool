# MITM LAB SETUP  
**VM user:** `vboxuser`  
**Password:** `VMSpoof123`

This document describes the complete setup of the virtual environment ("the lab") used for the ARP Spoofing, DNS Poisoning, and SSL Stripping project.

Only **one team member** needs to maintain the virtual machines.  
Other team members **use the environment (tool)** for testing their attack modules (ARP, DNS, SSL).

---

# 1. VM Architecture Overview

The project runs inside a dedicated virtual network (via VirtualBox) containing 4 virtual machines:

| VM Name   | IP Address   | Purpose                           |
|-----------|--------------|-----------------------------------|
| **Attacker** | `10.0.0.50` | Runs the MITM tool (our codebase) |
| **Victim**   | `10.0.0.10` | Browser target for attacks        |
| **Gateway**  | `10.0.0.1`  | Router between machines           |
| **DNS**      | `10.0.0.53` | DNS server + HTTPS service        |

All VMs share the same **VirtualBox Internal Network**:
Network mode: Internal Network
Network name: mitmnet
Subnet: 10.0.0.0/24

---

# 2. Access Credentials

All machines use the same credentials:
username: vboxuser
password: VMSpoof123