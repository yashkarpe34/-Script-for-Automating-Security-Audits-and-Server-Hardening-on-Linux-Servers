# Security Audit and Server Hardening on linux server

Installation
1. clone the rescprtory
   git clone https://github.com/yashkarpe34/linux-security-audit.git
   cd linux-security-audit

2.Make the script executable
  chmod +x secure_audit.sh

3. cp config/custom_checks.conf.example config/custom_checks.conf

4. Run the script with root privileges:
   sudo ./secure_audit.sh

Configuration:
#custom hardening checks
audit_custom_firewall="iptables -L | grep DROP"
audit_custom_cron="ls -la /etc/cron.*"

custom_checks.conf:
#audit.sh
DISABLE_IPV6="yes"

AUTO_UPDATES="yes"

ALERT_EMAIL="admin@example.com"



Output
audit_report.txt: Summary of audit and hardening steps taken.
