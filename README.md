# -Script-for-Automating-Security-Audits-and-Server-Hardening-on-Linux-Servers

#!/bin/bash

# Security Audit and Hardening Script for Linux Servers
# Author: Yash Karpe

LOGFILE="security_audit.log"
> "$LOGFILE"

echo "Starting Security Audit and Hardening..." | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "User and Group Audits" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

cat /etc/passwd | cut -d: -f1 | tee -a "$LOGFILE"
cat /etc/group | cut -d: -f1 | tee -a "$LOGFILE"

awk -F: '$3 == 0 {print $1}' /etc/passwd | tee -a "$LOGFILE"

sudo awk -F: '($2 == "" ) {print $1 " has no password!"}' /etc/shadow | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "File and Directory Permissions" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

find / -xdev -type f -perm -o+w 2>/dev/null | tee -a "$LOGFILE"
find / -xdev -type d -perm -o+w 2>/dev/null | tee -a "$LOGFILE"

find /home -name ".ssh" -exec ls -ld {} \; | tee -a "$LOGFILE"

find / -perm -4000 -o -perm -2000 -exec ls -lh {} + 2>/dev/null | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "Service Audits" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

systemctl list-units --type=service --state=running | tee -a "$LOGFILE"

ps aux --sort=-%mem | head -n 10 | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "Firewall and Network Security" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

sudo ufw status | tee -a "$LOGFILE"
sudo iptables -L -n | tee -a "$LOGFILE"

netstat -tulpn | tee -a "$LOGFILE"

sysctl net.ipv4.ip_forward | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "IP and Network Configuration Checks" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

ip a | tee -a "$LOGFILE"

hostname -I | tee -a "$LOGFILE"

ss -tulnp | grep ssh | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "Security Updates and Patching" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

sudo apt update && sudo apt list --upgradable | tee -a "$LOGFILE"

sudo apt install unattended-upgrades -y | tee -a "$LOGFILE"
sudo dpkg-reconfigure -plow unattended-upgrades | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "Log Monitoring" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

grep -i "failed password" /var/log/auth.log | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "Server Hardening Steps" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p | tee -a "$LOGFILE"

echo "Setting GRUB password..."
echo "GRUB password setup is required manually."

ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable | tee -a "$LOGFILE"

systemctl enable unattended-upgrades

echo "=================================" | tee -a "$LOGFILE"
echo "Custom Security Checks" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

echo "No additional custom checks configured." | tee -a "$LOGFILE"

echo "=================================" | tee -a "$LOGFILE"
echo "Generating Report" | tee -a "$LOGFILE"
echo "=================================" | tee -a "$LOGFILE"

cat "$LOGFILE"

echo "Security Audit and Hardening Completed!"
