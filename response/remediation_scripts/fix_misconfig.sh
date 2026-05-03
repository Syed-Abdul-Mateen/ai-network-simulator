#!/bin/bash
# Remediation script to fix common misconfigurations
echo "Applying security fixes..."

# Disable unused services
systemctl stop telnet
systemctl disable telnet

# Enforce password complexity
echo "password requisite pam_pwquality.so retry=3" >> /etc/pam.d/common-password

# Update system
apt update && apt upgrade -y

echo "Remediation complete."