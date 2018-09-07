# Automation deployment

This will help you prepare environment like: configure and add hostname, disable selinux, disable firewall, install java, ...

# How to

- Copy JDK with format jdk.tgz to roles/java/files/
- Download JCE from oracle (match with JDK version), extract file and copy 2 files (local_policy.jar, US_export_policy.jar) to roles/updatejavajce/files/  (by default, JCE for java 8)
- Make sure from Ansible host can access to remote without pass phrase
- Install Ansible Playbook to Ansible host 
- Edit file common_hosts, example:
```
[all]
ambari ansible_ssh_host=172.31.23.224
namenode01 ansible_ssh_host=172.31.13.123
namenode02 ansible_ssh_host=172.31.4.4
datanode01 ansible_ssh_host=172.31.0.189
datanode02 ansible_ssh_host=172.31.3.96
```    
- Run command: 
```ansible-playbook --private-key /path/to/key -i common_hosts common_site.yml```

# Author: 
- Email: tin@trustingsocial.com
- Slack: tinhuynh