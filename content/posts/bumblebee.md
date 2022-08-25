---
title: "Bumblebee"
date: 2022-08-25T16:35:18-04:00
draft: false
---

# Bumblebee Sample

Bumblebee (Shindig) has been used by TA579 / BazaISO / Exotic Lily / Stolen Images to collect system information and exfil to a C2. Additional second-stage payloads include Cobalt Strike beacons. 

An overlap between Exotic Lily and Wizard Spider is based on both delivering BazarLoader and a unique Cobalt Strike profile. Exotic Lily most likely handles Initial Access, then a second group deploys Conti and Diavol ransomware. 

[https://bazaar.abuse.ch/sample/70eb84a6bce741ff988116434e4f531a724257185ab92df8fcfa90b3def6568f/](https://bazaar.abuse.ch/sample/70eb84a6bce741ff988116434e4f531a724257185ab92df8fcfa90b3def6568f/)

Download zip > .iso file (password protected)> dll/lnk inside

Once the ISO is mounted, the .dll and .lnk are visible. 

![Untitled](/bumblebee/Untitled.png)

### LNK Analysis

Using LECmd.exe to analyze the LNK file. If on Linux, [Lnkinfo](https://manpages.ubuntu.com/manpages/impish/man1/lnkinfo.1.html) gives a similar output.

![Untitled](/bumblebee/Untitled2.png)

![Untitled](/bumblebee/Untitled3.png)

Upon executing the LNK file, a `rundll32` process is created since that’s what was within the LNK file arguments. `/c start rundll32.exe 32de.dll,YTBSBbNTWU`

In Process Hacker, the `rundll32` process reveals some IOCs.

First step is to view the actual process properties and go to the memory tab. 

![Untitled](/bumblebee/Untitled4.png)

Next, dump strings and filter for IPs using a regex pattern. 

`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`

![Untitled](/bumblebee/Untitled5.png)

Now for my lab, I didn’t receive any additional IOCs. All IPs above are from the loopback, ethernet and broadcast address. This may indicate the malware evades virtual machines or it’s user error and I have some settings to modify. But through the tweet below, additional IOCs were actually found. 

[https://twitter.com/Max_Mal_/status/1516352309311246339](https://twitter.com/Max_Mal_/status/1516352309311246339)

- 199.80.55[.]44:443
- 209.141.59[.]96:433
- 23.106.160[.]120:433

### DLL Analysis

Using [CAPA](https://www.mandiant.com/resources/capa-automatically-identify-malware-capabilities), some ATT&CK tactics can be pulled.

![Untitled](/bumblebee/Untitled6.png)

### Intezer Endpoint Analysis

As my IDA skills are weak, I couldn’t go much further into the DLL. Instead, I used Intezer’s [Endpoint scanner](https://analyze.intezer.com/endpoint-analyses) to scan the machine to get useful information.

Some benefits of endpoint analysis:

- **Detection:** Detect sophisticated threats running in-memory, including code injections, packed and multi-stage malware.
- **Lightweight:** A fast scanner that collects and analyzes only the relevant code in memory.
- **Simple:** On-demand scan (no installation is required), easily automated and accessible to analysts of all skill levels.

After scanning the system:

![Untitled](/bumblebee/Untitled7.png)

No surprise here, it’s infected with Bumblebee. But what is interesting is the additional malware found on the system including Khalesi. I was unfamiliar with Khalesi (besides watching Game of Thrones) but luckily you can explore malware within Intezer. 

- Khaleis (Kpot, KPOT Stealer) is a “stealer” malware that focuses on exfiltrating account information and other data from web browsers, instant messengers, email, VPN, RDP, FTP, cryptocurrency, and gaming software.

Scrolling down further, there’s a process tree showing what happened on the system. 

![Untitled](/bumblebee/Untitled8.png)

The command line section to the right correlates to what was seen in the LNK file properties. It executes `rundll32.exe 32de.dll,YTBSBbNTWU`. That second argument obviously does something, but I couldn’t see it. Luckily, Intezer shows it replaced the memory of a module in `c:\windows\winsxs\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.22000.434_none_ce836c1412fb9b57\gdiplus.dll`.

After analyzing `gdiplus.dll`, it’s a trusted Microsoft file which would make sense given the malware overwrote the memory of that DLL. By viewing the code genes of Bumblebee under Intezer’s Code tab, it’s possible the malware is calling `VirtualProtectEx` to achieve this. It gets called again at `0x18003ba03`. 

![Untitled](/bumblebee/Untitled9.png)

From [malapi.io](https://malapi.io/winapi/VirtualProtectEx), `VirtualProtectEx` is often used by malware to modify memory protection in a remote process (often to allow write or execution).

To get more information on Bumblebee itself outside of endpoint scanning, it tags three related samples that can give greater detail as to what the malware fully accomplishes along with more IoCs. 

![Untitled](/bumblebee/Untitled10.png)

There’s a lot to be gathered from a suspicious endpoint and during my first test of the Endpoint Scanner, it serves as a great start. `32de.dll` appears to include a few methods of virtual machine / sandbox evasion, so that may be why the execution appears to stop here.

### References
- https://elis531989.medium.com/the-chronicles-of-bumblebee-the-hook-the-bee-and-the-trickbot-connection-686379311056
- https://research.nccgroup.com/2022/04/29/adventures-in-the-land-of-bumblebee-a-new-malicious-loader/
- https://github.com/Dump-GUY/Malware-analysis-and-Reverse-engineering/blob/main/kpot2/KPOT.md
- https://malapi.io/winapi/VirtualProtectEx