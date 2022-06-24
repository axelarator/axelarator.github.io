---
title: "Hide Artifacts: NTFS File Attributes (T1564.004)"
date: 2022-06-23T20:11:52-04:00
draft: false
---

# Hide Artifacts: NTFS File Attributes


[T1564.004](https://attack.mitre.org/techniques/T1564/004/)

*Data or executables may be stored in New Technology File System (NTFS) partition metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus.* 

*Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. Within MFT entries are file attributes, such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files).*

*The NTFS format has a feature called Extended Attributes (EA), which allows data to be stored as an attribute of a file or folder.*

**Extended Attributes (EA)**

Used to implement the HPFS extended attribute under NTFS. It is a name/value pair where the value has a maximum size of 65536 bytes.

![$EA attribute structure](Ntfs/Untitled.png)

$EA attribute structure

### NTFS

**File Attributes**

**File Streams**

- Streams contain the data that is written to a file which gives more information about a file than its attributes and properties.
- To specify a data stream, use `filename::$DATA` where `$DATA` is the stream type.
- `::$EA` is a stream type that contains **Extended Attributes** data.

### Alternate Data Streams (ADS)

- A data stream that is alternate to the normal data stream. The data attribute (`$DATA`) is called the “normal” data stream or “unnamed” data stream since it can be left blank.
    - A normal data stream looks like `$DATA:""`
    - An alternate data stream can be `$DATA:"SecondStream"`
- To read what’s inside an ADS
    - `Get-Item -path <file> -stream *`
    - `Get-Content -path <file> -stream <stream name>`
- To add streams to a file
    - `set-content -path <path> -stream <stream name>`
- To search for ADS
    - `gci -recurse | % { gi $_.FullName - stream * } | where stream -ne ':$Data'`
- To remove ADS
    - `remove-item -path <path> -stream <stream name>`
- A sysinternals tool called `streams.exe` can also enumerate streams
    - `streams <file path>`

### HPFS

- A legacy file system unlikely to be used in conjunction with modern operating systems.

### MFT

- A metadata structure present on every NTFS formatted partition. It maintains a record for every file on the partition and each record contains file data and metadata.
- Records begin with ASCII string “FILE” (46 49 4C 45)
- Standard Information structure starts with 10 00 00 00
    - Contains a creation timestamp in hex.
- EA information starts with D0 00 00 00
    - The actual start of EA starts with E0 00 00 00
        - This is where the attributes are stored

### Enumerate EA

- [Zeroaccess trojan](https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=c5cf3441-25aa-499e-a693-ac48f54d588f&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments) used ZwSetEaFile and ZwQueryEaFile to interact with Extended Attributes.

### Detection

Attackers are using EA attributes as data storage (PE files) which is not consistent with the key/value pair concept.

```powershell
Group-Object Name
```

Group-Object can be used to group all EAs based on name.

When viewing an EA, they have a value related to a .cat file.

- EAs have a value related to a .cat file or “digitally-signed catalog file.” These files verify the digital signature of other files as a collection and alternative to Authenticode singing each individual file.

By using `Get-AuthenticodeSignature` cmdlet to check the file signature of the catalog referenced in the EA, the thumbprint should be identical to that of the catalog file.

- C:\Windows\bsfvc.exe thumbprint should match the catalog file
    - Filename: bsfvc.exe
    - Value: <cat file>

`sigcheck` from sysinternals with the `-i` parameter can resolve what catalog to use for validating a file.

### References

- [https://posts.specterops.io/host-based-threat-modeling-indicator-design-a9dbbb53d5ea](https://posts.specterops.io/host-based-threat-modeling-indicator-design-a9dbbb53d5ea)
- [https://attack.mitre.org/techniques/T1564/004/](https://attack.mitre.org/techniques/T1564/004/)
- [https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=c5cf3441-25aa-499e-a693-ac48f54d588f&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments](https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=c5cf3441-25aa-499e-a693-ac48f54d588f&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments)
- [https://docs.microsoft.com/en-us/archive/blogs/askcore/ntfs-file-attributes](https://docs.microsoft.com/en-us/archive/blogs/askcore/ntfs-file-attributes)
- [https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams?redirectedfrom=MSDN)
- [https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/](https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/)
- [https://docs.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs](https://docs.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs)
- [https://docs.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs](https://docs.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs)
- [https://github.com/invoke-ir/powerforensics](https://github.com/invoke-ir/powerforensics)
> All inclusive framework for hard drive forensic analysis supporting NTFS and FAT file systems.
- [https://github.com/mattifestation/PSReflect](https://github.com/mattifestation/PSReflect)
> Easily define in-memory enums, structs, and Win32 functions in PowerShell
- [Anatomy of an NTFS FILE Record - Windows File System Forensics](https://www.youtube.com/watch?v=l4IphrAjzeY)