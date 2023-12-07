#!/bin/bash

# Update system packages
apt update && apt upgrade -y

# Install essential hardening tools
apt install -y lynis chkrootkit rkhunter fail2ban denyhosts clamav apparmor-utils unattended-upgrades knockd

# Run comprehensive security audit with Lynis
lynis audit system

# Enable root login only from localhost
sed -i '/^PermitRootLogin/s/.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh

# Set strong password requirements
sed -i '/minlen/s/#*//; /minlen/s/=.*/=16/' /etc/security/pwquality.conf
sed -i '/dcredit/s/#*//; /dcredit/s/=.*/=-2/' /etc/security/pwquality.conf
sed -i '/ucredit/s/#*//; /ucredit/s/=.*/=-2/' /etc/security/pwquality.conf
sed -i '/ocredit/s/#*//; /ocredit/s/=.*/=-2/' /etc/security/pwquality.conf
sed -i '/lcredit/s/#*//; /lcredit/s/=.*/=-2/' /etc/security/pwquality.conf

# Set password expiration and history
sed -i '/^PASS_MAX_DAYS/s/.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/s/.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i '/^PASS_WARN_AGE/s/.*/PASS_WARN_AGE   7/' /etc/login.defs

# Disable unnecessary services
systemctl disable bluetooth
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable lightdm
systemctl disable NetworkManager

# Configure firewall rules (UFW)
ufw default deny incoming
ufw default allow outgoing
ufw allow 2200/tcp
ufw enable

# Configure SSH port and disable password authentication
sed -i '/^#Port/s/.*/Port 2200/' /etc/ssh/sshd_config
sed -i '/^#PasswordAuthentication/s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# Install and configure fail2ban for SSH brute-force protection
cat <<EOT >> /etc/fail2ban/jail.local
[DEFAULT]
bantime = 86400
maxretry = 5
[EOT

echo "[sshd]" >> /etc/fail2ban/jail.local
echo "enabled = true" >> /etc/fail2ban/jail.local

# Configure port knocking with knockd
cat <<EOT >> /etc/knockd.conf
[options]
    UseSyslog

[opencloseSSH]
    sequence    = 5000,6000,7000
    seq_timeout = 15
    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 2200 -j ACCEPT
    tcpflags    = syn
[EOT

systemctl enable knockd
systemctl start knockd

# Install and configure intrusion detection system (OSSEC)
apt install -y ossec-hids-server
/var/ossec/bin/ossec-control start

# Install and configure ClamAV for virus scanning
freshclam
clamscan -r /

# Harden sudo configuration
echo "Defaults timestamp_timeout=60,passwd_timeout=30" >> /etc/sudoers

# Configure secure logging
echo "auth.* /var/log/auth.log" >> /etc/rsyslog.conf
echo "authpriv.* /var/log/auth.log" >> /etc/rsyslog.conf
echo "authpriv.none /var/log/messages" >> /etc/rsyslog.conf

# Enable automatic security updates
echo 'APT::Periodic::Update-Package-Lists "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

# Enable AppArmor for added security
systemctl enable apparmor
systemctl start apparmor

# Set sysctl parameters for improved security
cat <<SYSCTL_CONF >> /etc/sysctl.d/99-security-hardening.conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable IPv6 if not in use
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL_CONF

sysctl --system

# Update and patch known vulnerabilities
apt-get install -y --only-upgrade $(apt list --upgradable 2>/dev/null | grep -oP '^\S+' | grep -vE '(Listing|apt-list|done|Reading)')

# Dead Man's Switch setup
touch /tmp/dead_mans_switch
trap 'touch /tmp/dead_mans_switch' EXIT

# Reset the switch every 12 hours
(sleep 43200 && touch /tmp/dead_mans_switch) & sudo apt-get install -y --only-upgrade

# Reset the dead man's switch at the end of the script
rm -f /tmp/dead_mans_switch

# Reboot for changes to take effect
reboot


