#!/bin/bash
##############################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

############################
# Configure Software Updates
#Current update mechanism excludes kernel updates so that updates do not break common applications
yum update -y --exclude=kernel*
############################

############################
#Sysctl security
#Next we need to have a look inside /etc/sysctl.conf and make some basic changes. 
#If these lines exist, modify them to match below. If they don't exist, simply add them in. 
#If you have multiple network interfaces on the server, some of these may cause issues. 
#Test these before you put them into production. 
#If you want to know more about any of these options, install the kernel-doc package, and look in Documentation/networking/ip-sysctl.txt
# /etc/sysctl.conf
echo "Tunning kernel"
cp /etc/sysctl.conf /etc/sysctl.conf.bak
sleep 15
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 1280" >> /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
############################

#########################
# Configure rsyslog
# Install the rsyslog package 
echo "Install rsyslog"	
yum -y install rsyslog
# Activate the rsyslog Service 	
chkconfig syslog off 
chkconfig rsyslog on
#5.1.3 Configure /etc/rsyslog.conf 	
#Edit the following lines in the /etc/rsyslog.conf file as appropriate for your environment:
cp /etc/rsyslog.conf /etc/rsyslog.conf.bak
echo "auth,user.* /var/log/messages" >> /etc/rsyslog.conf
echo "kern.* /var/log/kern.log" >> /etc/rsyslog.conf
echo "daemon.* /var/log/daemon.log" >> /etc/rsyslog.conf
echo "syslog.* /var/log/syslog" >> /etc/rsyslog.conf
echo "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log" >> /etc/rsyslog.conf
# Execute the following command to restart rsyslogd
pkill -HUP rsyslogd
# Create and Set Permissions on rsyslog Log Files 	
touch /var/log/messages
chown root:root /var/log/messages
chmod og-rwx /var/log/messages
touch /var/log/kern.log
chown root:root /var/log/kern.log
chmod og-rwx /var/log/kern.log
touch /var/log/daemon.log
chown root:root /var/log/daemon.log
chmod og-rwx /var/log/daemon.log
touch /var/log/syslog
chown root:root /var/log/syslog
chmod og-rwx /var/log/syslog
touch /var/log/unused.log
chown root:root /var/log/unused.log
chmod og-rwx /var/log/unused.log
############################

##############################
#5.2 Configure System Accounting (auditd)
# Install audit
yum -y install audit
#5.2.2 Enable auditd Service 	
chkconfig auditd on
service auditd restart

# /etc/audit/audit.rules
echo "Configure audit rules"
cp /etc/audit/audit.rules /etc/audit/audit.rules.bak
sleep 15
cat << 'EOF' > /etc/audit/audit.rules
# Benchmark Adjustments
# Records events that modify time information
-a always,exit -F arch=b64 -S adjtimex -S settimEOMday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimEOMday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Record events that modify account information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

#secops required
#These will track all commands run by root (euid=0).
#Why two rules? The execve syscall must be tracked in both 32 and 64 bit code.
-a exit,always -F arch=b64 -F euid=0 -S execve
-a exit,always -F arch=b32 -F euid=0 -S execve
# Record events that modify the network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Record events that modify the SElinux configuration
-w /etc/selinux/ -p wa -k MAC-policy

# Record logon and logout Events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Record process and session initiation information
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Record discretionary access control permission modification events
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

# Record unauthorized access attempts to files (unsuccessful)
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

# Record files deletion events by User (successful and unsuccessful)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

# Set time of date
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Record system administrator actions
-w /etc/sudoers -p wa -k actions

# Record actions with /var/log/sudo.log
-w /var/log/sudo.log -p wa -k actions

# Record information on kernel module loading and unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
EOF


##################################

#######################################
# Configure cron and anacron
# Enable anacron Daemon 	
yum -y install cronie-anacron
# Enable crond Daemon 	
chkconfig crond on
# Set User/Group Owner and Permission on /etc/anacrontab
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
# Set User/Group Owner and Permission on /etc/crontab 	
chown root:root /etc/crontab 
chmod og-rwx /etc/crontab
# Set User/Group Owner and Permission on /etc/cron.hourly
chown root:root /etc/cron.hourly 
chmod og-rwx /etc/cron.hourly
# Set User/Group Owner and Permission on /etc/cron.daily 	
chown root:root /etc/cron.daily 
chmod og-rwx /etc/cron.daily
# Set User/Group Owner and Permission on /etc/cron.weekly 	
chown root:root /etc/cron.weekly 
chmod og-rwx /etc/cron.weekly
# Set User/Group Owner and Permission on /etc/cron.monthly 	
chown root:root /etc/cron.monthly 
chmod og-rwx /etc/cron.monthly
# Set User/Group Owner and Permission on /etc/cron.d 	
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
########################################

#######################################
# Configure PAM
# Upgrade Password Hashing Algorithm to SHA-512
authconfig --passalgo=sha512 --update
#If it is determined that the password algorithm being used -i is not SHA-512, once it is changed, it is recommended that all userID's be 
#immediately expired and forced to change their passwords on next login. To accomplish that, the following commands can be used.
#Any system accounts that need to be expired should be carefully done separately by the system administrator to prevent any potential problems.
#the below query will print you a list
# echo "Accounts that need to be expired: "
# cat /etc/passwd | awk -F: '( $3 >=500 && $1 != "nfsnobody" ) { print $1 }' | xargs -n 1 chage -d 0
# Edit system-auth

echo "Configure pam authentication"
cp /etc/pam.d/system-auth /etc/pam.d/system-auth.bak

sleep 15
cat << 'EOF' > /etc/pam.d/system-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so
auth        required      pam_tally2.so deny=3 onerr=fail unlock_time=60

account     required      pam_unix.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so
account     required      pam_tally2.so per_user

password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=1
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOF
###################################

###################################
#User Accounts and Environment
sleep 15
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
#find all login users
## get UID limit ##
l=$(grep "^UID_MIN" /etc/login.defs)
## use awk to print if UID >= $UID_LIMIT ##
loginusers=`awk -F':' -v "limit=${l##UID_MIN}" '{ if ( $3 >= limit ) print $1}' /etc/passwd`
#loop through login user list and set password max age to 90 days
for user in $loginusers; do
        echo $user
        chage --maxdays 90 $user
        chage --mindays 1 $user
        chage --warndays 7 $user
done
####################################

###################################
# Remove OS Information from Login Warning Banners
sleep 15
egrep '(\\v|\\r|\\m|\\s)' /etc/issue
egrep '(\\v|\\r|\\m|\\s)' /etc/motd
egrep'(\\v|\\r|\\m|\\s)' /etc/issue.net
sed -i '/\v/d' /etc/issue
sed -i '/\r/d' /etc/issue
sed -i '/\m/d' /etc/issue
sed -i '/\s/d' /etc/issue
sed -i '/\v/d' /etc/motd
sed -i '/\r/d' /etc/motd
sed -i '/\m/d' /etc/motd
sed -i '/\s/d' /etc/motd
sed -i '/\v/d' /etc/issue.net
sed -i '/\r/d' /etc/issue.net
sed -i '/\m/d' /etc/issue.net
sed -i '/\s/d' /etc/issue.net
##################################

#################################
# Verify Permissions on /etc/passwd
/bin/chmod 644 /etc/passwd
# Verify Permissions on /etc/shadow
/bin/chmod 000 /etc/shadow
# Verify Permissions on /etc/gshadow
/bin/chmod 000 /etc/gshadow
# Verify Permissions on /etc/group
/bin/chmod 644 /etc/group
# Verify User/Group Ownership on /etc/passwd
/bin/chown root:root /etc/passwd
# Verify User/Group Ownership on /etc/shadow
/bin/chown root:root /etc/shadow
# Verify User/Group Ownership on /etc/gshadow
/bin/chown root:root /etc/gshadow
# Verify User/Group Ownership on /etc/group
/bin/chown root:root /etc/group
############################

###############################
echo "--- Securing the SSH Daemon ---"
echo "Backing up previous SSHd configurations"
sleep 15
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/PermitRootLogin.*$/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/AllowTcpForwarding.*$/AllowTcpForwarding no/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding.*$/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/LogLevel.*$/LogLevel VERBOSE/g' /etc/ssh/sshd_config
sed -i 's/ClientAliveInterval.*$/ClientAliveInterval 600/g' /etc/ssh/sshd_config
sed -i 's/ClientAliveCountMax.*$/ClientAliveCountMax 0/g' /etc/ssh/sshd_config


#configure sshd to start at boot
chkconfig --level 3 sshd on
chkconfig --level 5 sshd on
#Set Permissions on /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
#commit changes to sshd config
systemctl restart sshd
#################################################

#backup bashrc
for user in `ls /home`; do
	cp /home/$user/.bashrc /home/$user/.bashrc.bk
done
#####################################################################
#reconfigure bashrc
echo "--- Enabling Real time bash history for all current users ---"
sleep 15
for user in `ls /home`; do
	echo 'export HISTCONTROL=ignoredups:erasedups  # no duplicate entries' >> /home/$user/.bashrc
	echo 'export HISTSIZE=100000                   # big big history' >> /home/$user/.bashrc
	echo 'export HISTFILESIZE=100000               # big big history' >> /home/$user/.bashrc
	echo 'export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp' >> /home/$user/.bashrc
	echo "shopt -s histappend                      # append to history, don't overwrite it" >> /home/$user/.bashrc
	echo '# After each command, append to the history file and reread it' >> /home/$user/.bashrc
	echo 'export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"' >> /home/$user/.bashrc
done

#backup bashrc for root
cp /root/.bashrc /root/.bashrc.bk
###############################
#reconfigure /root/bashrc
echo "--- Enabling Real time bash history for root ---"
sleep 15
/bin/cat << 'EOF' > /root/.bashrc

# .bashrc
# User specific aliases and functions
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi
export HISTCONTROL=ignoredups:erasedups  # no duplicate entries
export HISTSIZE=100000                   # big big history
export HISTFILESIZE=100000               # big big history
export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp
shopt -s histappend                      # append to history, don't overwrite it
# After each command, append to the history file and reread it
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
EOF
########################
#backup skel bashrc
cp /etc/skel/.bashrc /etc/skel/.bashrc.bk
#reconfigure /etc/skel/.bashrc
echo "--- Enabling Real time bash history for all future users ---"
/bin/cat << 'EOF' > /etc/skel/.bashrc
# .bashrc
# User specific aliases and functions
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi
export HISTCONTROL=ignoredups:erasedups  # no duplicate entries
export HISTSIZE=100000                   # big big history
export HISTFILESIZE=100000               # big big history
export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp
shopt -s histappend                      # append to history, don't overwrite it
# After each command, append to the history file and reread it
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
EOF
##############################################################################
echo "##############################################################################"
echo "Completed. Please review script output for manual process"
