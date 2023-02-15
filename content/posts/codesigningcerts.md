---
title: "Abusing Code Signing Certificates"
date: 2023-02-15T09:09:43-07:00
draft: false
---

## Authenticode Signature

The point of code signing certificates is to verify the file came from a trusted source, the file was not tampered with prior to receiving it, and the file’s origin can be validated. Code signing creates a hash of the code and encrypts it with a private key adding its signature. During execution, this signature is validated and if the hash matches, it gives assurance that the code has not been modified. Users or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.

Microsoft implements a form of code signing using Authenticode technology. 

So first, what is an authenticode digital signature? Simply put, it’s a way to identify the publisher of the software. The software publisher signs the driver or driver package, tagging it with a digital certificate that verifies the identity of the publisher. With embedded signatures, a digital signature is embedded within a ************************nonexecution************************ portion of the driver file. This means authenticode code signing does not alter the executable portion of a driver. 

Authenticode isn’t the only way to sign a driver [package]. The Windows Hardware Certification Kit has test categories for various devices types. If the device type has a test category, the publisher can obtain a WHQL release signature for the driver package. A WHQL release signature consists of a digitally signed catalog file. If a test program is not available, then the publisher can resort to signing the driver using Authenticode.

There are two commands to check / verify a certificate.

### First Tool

First is the PowerShell cmdlet `Get-AuthenticodeSignature` which does exactly what it says. It simply gets the authenticode signature. I’ll use the VS Code executable as an example.

```powershell
PS C:\Users\User > Get-AuthenticodeSignature "C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe"

    Directory: C:\Users\User\AppData\Local\Programs\Microsoft VS Code

SignerCertificate                         Status                                Path
-----------------                         ------                                ----
8740DF4ACB749640AD318E4BE842F72EC651AD80  Valid                                 Code.exe
```

You can go one step further by piping the output to `Format-List`

A quick PowerShell tip: 

This is a large output and maybe you only care about the `SignerCertificate` and `Status` properties but in more detail. Simply append the `-Property` parameter after `Format-List` and specify what properties you want. Example is in the second code block.

```powershell
PS C:\Users\User > Get-AuthenticodeSignature "C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe" | Format-List

SignerCertificate      : [Subject]
                           CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                         [Issuer]
                           CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                         [Serial Number]
                           33000002528B33AAF895F339DB000000000252

                         [Not Before]
                           9/2/2021 11:32:59 AM

                         [Not After]
                           9/1/2022 11:32:59 AM

                         [Thumbprint]
                           8740DF4ACB749640AD318E4BE842F72EC651AD80

TimeStamperCertificate : [Subject]
                           CN=Microsoft Time-Stamp Service, OU=Thales TSS ESN:D082-4BFD-EEBA, OU=Microsoft Ireland
                         Operations Limited, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                         [Issuer]
                           CN=Microsoft Time-Stamp PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                         [Serial Number]
                           330000018FF351A8EB5A72DDCC00010000018F

                         [Not Before]
                           10/28/2021 12:27:46 PM

                         [Not After]
                           1/26/2023 11:27:46 AM

                         [Thumbprint]
                           3E4D2F820476E748070746A02695D1605B419A6A

Status                 : Valid
StatusMessage          : Signature verified.
Path                   : C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe
SignatureType          : Authenticode
IsOSBinary             : False
```

```powershell
PS C:\Users\User > Get-AuthenticodeSignature "C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe" | Format-List -Property Status, SignerCertificate

Status            : Valid
SignerCertificate : [Subject]
                      CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                    [Issuer]
                      CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                    [Serial Number]
                      33000002528B33AAF895F339DB000000000252

                    [Not Before]
                      9/2/2021 11:32:59 AM

                    [Not After]
                      9/1/2022 11:32:59 AM

                    [Thumbprint]
                      8740DF4ACB749640AD318E4BE842F72EC651AD80
```

For those that like GUIs more, you’re probably more familiar with viewing file properties and seeing the certificate that way.

![Untitled](/codesign/Untitled.png)

### Second Tool

The second tool is `SignTool` from the Windows SDK. Unlike `Get-AuthenticodeSignature`, SignTool can verify the certificate of the file by either checking against the Windows driver policy (default) or the Default Authentication Verification Policy. SignTool requires the Windows SDK so download that first. 

[https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)

Using the `/pa` option specifies that the Default Authentication Verification Policy is used. If it isn’t specified, SignTool defaults to the Windows driver policy for verification but can error out if the signature uses a code signing certificate, which for this file, it did.

Without `/pa`

```powershell
PS C:\Users\User > & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe" verify "C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe"
File: C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe
Index  Algorithm  Timestamp
========================================
SignTool Error: A certificate chain processed, but terminated in a root
        certificate which is not trusted by the trust provider.

Number of errors: 1
```

With `/pa`

```powershell
PS C:\Users\User > & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe" verify /pa "C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe"
File: C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe
Index  Algorithm  Timestamp
========================================
0      sha256     RFC3161

Successfully verified: C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe
```

## Abusing Code Signing Certificates

[https://github.com/secretsquirrel/SigThief.git](https://github.com/secretsquirrel/SigThief.git)

This is a tool for copying one cert and applying it to another file (.exe, .cab, .dll, .ocx, .msi, .xpi and .xap files) and kernel-mode software. An example could be applying a Microsoft cert to Mimikatz. The tool itself does not append a valid signature to a file and I’ll get to that later, but it’s purpose is to test various AV vendors to see how they prioritize CAs and if they check the validity of the signature or just who it’s signed by.

## Using SigThief

The tool itself is very straightforward. Take a signature from one file and add it to another. There are other options like ripping the signature and saving it for later, possibly to append the same signature to multiple files. 

In this example, I’ll show how to take a certificate from VS Code and write it to Mimikatz. Mimikatz initially is not signed at all, so for it to have any chance at staying undetected, supplying a certificate is a good choice. 

```powershell
PS C:\Users\User > Get-AuthenticodeSignature "C:\Users\User\Downloads\mimikatz_trunk\x64\mimikatz.exe"

    Directory: C:\Users\User\Downloads\mimikatz_trunk\x64

SignerCertificate                         Status                            Path
-----------------                         ------                            ----
                                          NotSigned                         mimikatz.exe
```

```powershell
PS C:\Tools\SigThief > python .\sigthief.py -i "C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe" -t "C:\Users\User\Downloads\mimikatz_trunk\x64\mimikatz.exe" -o mimicode.exe

!! New Version available now for Dev Tier Sponsors! Sponsor here: https://github.com/sponsors/secretsquirrel

Output file: mimicode.exe
Signature appended.
FIN.

PS C:\Tools\SigThief > .\mimicode.exe                                                                                                                                                                                                               ...#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08                                                             ..## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                                                                               .## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # exit
Bye!
```

```powershell
PS C:\Tools\SigThief > Get-AuthenticodeSignature .\mimicode.exe

    Directory: C:\Tools\SigThief

SignerCertificate                         Status                            Path
-----------------                         ------                            ----
8740DF4ACB749640AD318E4BE842F72EC651AD80  HashMismatch                      mimicode.exe
```

That’s it. The certificate from `code.exe` was copied to `mimikatz.exe` and a new binary was created with a super discrete name. 

Now this file could be uploaded to VT, tested against an AV on your own system, etc. The goal is to see what it can bypass now that a malicious executable is signed from a trusted partner. 

But just because it’s signed from a trusted party doesn’t mean the executable is legit. Similar to HTTPS, just because the site you’re browsing has a lock next to the URL, it just means your connection is private. It doesn’t mean the site you’re visiting is safe.

![Untitled](/codesign/Untitled.jpeg)

With `mimicode.exe` now having a VS Code cert, it ***sort of*** looks legitimate. Look at the `SignerCertificate` of `mimicode.exe` compared to `code.exe`

```powershell
PS C:\Users\User > Get-AuthenticodeSignature "C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe"

    Directory: C:\Users\User\AppData\Local\Programs\Microsoft VS Code

SignerCertificate                         Status                                Path
-----------------                         ------                                ----
8740DF4ACB749640AD318E4BE842F72EC651AD80  Valid                                 Code.exe
```

I say ***sort of*** for multiple reasons. As I mentioned before, the tool itself does not append a valid signature to a file. It’s clear in the Digital Signature Details of the file. 

![Untitled](/codesign/Untitled1.png)

The certificate hash matches the `code.exe` hash, but that’s just pulling a key from a value. Using SigThief, the same can be seen.

```powershell
PS C:\Users\User > & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe" verify /pa "C:\Tools\SigThief\mimicode.exe"
File: C:\Tools\SigThief\mimicode.exe
Index  Algorithm  Timestamp
========================================
SignTool Error: WinVerifyTrust returned error: 0x80096010
        The digital signature of the object did not verify.

Number of errors: 1
```

Unlike the successful verification from `code.exe`, an error is thrown mentioning `WinVerifyTrust`. This is a function within the CryptoAPI that performs a trust verification action on a specified object. This is why SignTool is important as it is actually executing an action, not just getting a value. The data is passed to a trust provider which checks it against the certificate trust list. The reason is the HashMismatch status code when getting the authenticode signature. **The hash of the file does not match the hash stored in the digital signature.** As for a manual way of checking this, I haven’t found one. As for an automated way, this is essentially what the`verify` command is doing within `SignTool`.

In the image above, you might have also noticed the file icon is also the same as Mimikatz. 

The file properties also show a lot of clues:

- File description
- Product name
- Original filename

![Untitled](/codesign/Untitled2.png)

```powershell
PS C:\Tools > Get-Item C:\Tools\SigThief\mimicode.exe | select-object -property *

PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Tools\SigThief\mimicode.exe
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Tools\SigThief
PSChildName       : mimicode.exe
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : False
Mode              : -a----
VersionInfo       : File:             C:\Tools\SigThief\mimicode.exe
                    InternalName:     mimikatz
                    OriginalFilename: mimikatz.exe
                    FileVersion:      2.2.0.0
                    FileDescription:  mimikatz for Windows
                    Product:          mimikatz
                    ProductVersion:   2.2.0.0
                    Debug:            False
                    Patched:          False
                    PreRelease:       True
                    PrivateBuild:     True
                    SpecialBuild:     True
                    Language:         English (United States)

BaseName          : mimicode
Target            : {}
LinkType          :
Name              : mimicode.exe
Length            : 1365416
DirectoryName     : C:\Tools\SigThief
Directory         : C:\Tools\SigThief
IsReadOnly        : False
Exists            : True
FullName          : C:\Tools\SigThief\mimicode.exe
Extension         : .exe
CreationTime      : 2/13/2023 10:18:09 AM
CreationTimeUtc   : 2/13/2023 6:18:09 PM
LastAccessTime    : 2/13/2023 6:38:31 PM
LastAccessTimeUtc : 2/14/2023 2:38:31 AM
LastWriteTime     : 2/13/2023 10:18:09 AM
LastWriteTimeUtc  : 2/13/2023 6:18:09 PM
Attributes        : Archive
```

## Who’s Using This Technique

### MITRE Technique

[T1588.003 - Obtain Capabilities: Code Signing Certificates](https://attack.mitre.org/techniques/T1588/003/)

I covered a lot of ways to check if signatures are valid and easy giveaways that the “trustworthy” executable being run is actually malicious, but that doesn’t mean this technique is easy to mitigate. Stolen certificates are gathered from trusted parties and then sometimes sold on the Dark Web via e-commerce sites. Other times, it’s the result of improperly storing certificates which can be be publicly available.

### LAPSUS$

In March 2022, LAPSUS$ was using stolen Nvidia code signing certificates to sign malware to appear trustworthy and allow malicious drivers to be loaded in Windows. These certificates were expired, but Windows still allowed them to be used for driver signing purposes. Some malware used in this operation included CS beacons, Mimikatz, backdoors, and RATs. All legitimately signed.

A provided mitigation involves configuring [Windows Defender Application Control](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create) policies to control what drivers can be loaded. 

### Palmerworm

Palmerworm (BlackTech) is an espionage group that has used stolen code-signing certificates to sign its payloads.

In another campaign, BlackTech used the Plead backdoor that digitally signs files using a valid D-Link Corporation code signing certificate. This same certificate was used to sign non-malicious D-Link software, indicating the certificate was stolen. Other samples used expired certificates belonging to a Taiwanese company named Changing Information Technology Inc. This company was initially compromised first to obtain the certificates. 

### MegaCortex

MegaCortex ransomware was very busy in 2019 with four versions being developed between January and November. They use code signing certificates issued to fake companies.

- MegaCortex v1: “3AN LIMITED”
- MegaCortex v2: “ABADAN PIZZA LTD”
- MegaCortex v3: “LYUKS ELIT, LTD” and “FELIX MEDIA PTY LTD”
- MegaCortex v4: “MURSA PTY LTD”

### Ryuk

TheDFIRReport wrote about a Ryuk campaign in November 2020 where Ryuk would send a phishing email containing a Google Drive link that downloads a Bazar Loader backdoor. The loader used a code signing certificate signed by Digicert under the organization NOSOV SP Z O O. 

### OutSteel

An email subject translates from Ukrainian to “Report on the commission of crime <targeted individual’s name>”. When a victim clicks the icons over the redacted lines, it runs malicious JavaScript embedded within the document. The executable downloaded by the JavaScript is an initial loader Trojan, whose developers signed using a certificate that has “Electrum Technologies GmbH” within the organization field. This organization is related to the Electrum Bitcoin wallet. The first stage loader is a wrapper for the next few stages that decrypt a DLL. The packer allows a user to clone .NET assemblies from other .NET binaries, as well as from cloning certificates.

### Stuxnet

Yes, hop in the time machine and go back to 2010 when Stuxnet used digital certificates stolen from RealTek and JMicron, two Taiwanese-based companies. 

## Finding Certs

Most threat actors compromise a company and steal certificates and sometimes re-sell the certificates on underground sites. In 2018, TrendMicro reported that fraudulent EV (Extended Validation) certificates were for sale on forums and marketplaces. As of writing, I searched on Ahmia[.]fi for code signing certificates, EV certs, really any keywords pertaining to software certificates but couldn’t come across any forums advertising the sale of such. Fake certificates are also supplied by legitimate CAs that mimic a legitimate organization. One example was a Russian financial broker who became a target of cybercriminals using fraudulent certificates for Razy ransomware. The financial broker in question never requested the certificate. That’s a lot of heavy work before the main campaign can begin and not everyone has the ability to do that level of resource development. So what about OSINT? There was a great open-source technique mentioned by Bill Demirkapi in his [BH/DC talk](https://youtu.be/1H9tEfkjFXs?t=321). He used [GrayhatWarfare](https://buckets.grayhatwarfare.com/) to search for public leaked certificates from S3 buckets by filtering for PFX and P12 file extensions and at the time, he found over 6,000 results. 

## Conclusion

Abusing code signing certificates is not new. In the past few years alone, it has proven to be an effective method of bypassing certain security controls to allow malicious software to run and look seemingly benign. SigThief is a great testing tool to validate the correct policies are in place for allowing specific drivers to run. It is imperative to secure private keys within HSMs to hide and protect cryptographic material as they require physical access to steal keys. Validate certificates prior to using them for code signing and check that the code you’re signing is null of vulnerabilities or malware. Lastly, implement a certificate lifecycle management process. This is a lengthy process but ensures missing, expired, compromised or unused certificates are revoked, renewed or replaced. 

## References

- [https://github.com/secretsquirrel/SigThief](https://github.com/secretsquirrel/SigThief)
- [https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)
- [https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [https://attack.mitre.org/techniques/T1588/003/](https://attack.mitre.org/techniques/T1588/003/)
- [https://www.bleepingcomputer.com/news/security/malware-now-using-nvidias-stolen-code-signing-certificates/](https://www.bleepingcomputer.com/news/security/malware-now-using-nvidias-stolen-code-signing-certificates/)
- [https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create)
- [https://securityintelligence.com/certificates-as-a-service-code-signing-certs-become-popular-cybercrime-commodity/](https://securityintelligence.com/certificates-as-a-service-code-signing-certs-become-popular-cybercrime-commodity/)
- [https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/](https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/)
- [https://www.trendmicro.com/en_us/research/18/d/understanding-code-signing-abuse-in-malware-campaigns.html](https://www.trendmicro.com/en_us/research/18/d/understanding-code-signing-abuse-in-malware-campaigns.html)
- [https://www.encryptionconsulting.com/a-detailed-guide-to-code-signing-abuse/](https://www.encryptionconsulting.com/a-detailed-guide-to-code-signing-abuse/)
