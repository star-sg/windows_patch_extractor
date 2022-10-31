# Magic patch
An extensible tool for extracting windows patches

## Usage
Normal files: Full file doesn't need to apply delta patch

Null files: Compressed file, apply delta patch to NULL buffer

Forward files: Base + Forward = Updated

Reverse files: Upated + Reverse  = Base

- List windows product_id
~~~shell
PS S:\tools\windows_patch_extract> py -3 .\magic.py -l
List of products
{
    "9312": "Windows RT 8.1",
    "9318": "Windows Server 2008 for x64-based Systems Service Pack 2",
    "9344": "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)",
    "10047": "Windows 7 for 32-bit Systems Service Pack 1",
    "10048": "Windows 7 for x64-based Systems Service Pack 1",
    "10049": "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)",
    "10051": "Windows Server 2008 R2 for x64-based Systems Service Pack 1",
    "10287": "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)",
    "10378": "Windows Server 2012",
    "10379": "Windows Server 2012 (Server Core installation)",
    "10481": "Windows 8.1 for 32-bit systems",
    "10482": "Windows 8.1 for x64-based systems",
    "10483": "Windows Server 2012 R2",
    "10543": "Windows Server 2012 R2 (Server Core installation)",
    "10729": "Windows 10 for 32-bit Systems",
    "10735": "Windows 10 for x64-based Systems",
    "10816": "Windows Server 2016",
    "10852": "Windows 10 Version 1607 for 32-bit Systems",
    "10853": "Windows 10 Version 1607 for x64-based Systems",
    "10855": "Windows Server 2016 (Server Core installation)",
    "11568": "Windows 10 Version 1809 for 32-bit Systems",
    "11569": "Windows 10 Version 1809 for x64-based Systems",
    "11570": "Windows 10 Version 1809 for ARM64-based Systems",
    "11571": "Windows Server 2019",
    "11572": "Windows Server 2019 (Server Core installation)",
    "11800": "Windows 10 Version 20H2 for x64-based Systems",
    "11801": "Windows 10 Version 20H2 for 32-bit Systems",
    "11802": "Windows 10 Version 20H2 for ARM64-based Systems",
    "11896": "Windows 10 Version 21H1 for x64-based Systems",
    "11897": "Windows 10 Version 21H1 for ARM64-based Systems",
    "11898": "Windows 10 Version 21H1 for 32-bit Systems",
    "11923": "Windows Server 2022",
    "11924": "Windows Server 2022 (Server Core installation)",
    "11926": "Windows 11 for x64-based Systems",
    "11927": "Windows 11 for ARM64-based Systems",
    "11929": "Windows 10 Version 21H2 for 32-bit Systems",
    "11930": "Windows 10 Version 21H2 for ARM64-based Systems",
    "11931": "Windows 10 Version 21H2 for x64-based Systems",
    "12085": "Windows 11 Version 22H2 for ARM64-based Systems",
    "12086": "Windows 11 Version 22H2 for x64-based Systems"
}
~~~

- Search for a specific CVE update
~~~shell
PS S:\tools\windows_patch_extract> py -3 .\magic.py -cve CVE-2022-37987 12086
[!WARNING] product_id doesn't match local machine
Security update 2022-Oct for CVE-2022-37987 on Windows 11 Version 22H2 for x64-based Systems
{
    "articleName": "5018427",
    "articleUrl": "https://support.microsoft.com/help/5018427",
    "downloadName": "Security Update",
    "downloadUrl": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5018427",
    "fixedBuildNumber": "10.0.22621.674",
    "knownIssuesName": "5018427",
    "knownIssuesUrl": "https://support.microsoft.com/help/5018427",
    "ordinal": 1,
    "rebootRequired": "Yes"
}
~~~

- Expand an update file
~~~shell
PS S:\tools\windows_patch_extract> py -3 .\magic.py -expand E:\windows11.0-kb5018427-x64_ba6a752015a4115e688beea33f2afe8c55156b55.cab
create E:\expand
[INFO] Running expand.exe -F:* E:\windows11.0-kb5018427-x64_ba6a752015a4115e688beea33f2afe8c55156b55.cab E:\expand
[INFO] Running expand.exe -F:* E:\expand\DesktopDeployment.cab E:\expand\DesktopDeployment_cab
[INFO] Running expand.exe -F:* E:\expand\DesktopDeployment_X86.cab E:\expand\DesktopDeployment_X86_cab
[INFO] Running expand.exe -F:* E:\expand\onepackage.AggregatedMetadata.cab E:\expand\onepackage_AggregatedMetadata_cab
[INFO] Running expand.exe -F:* E:\expand\SSU-22621.378-x64.cab E:\expand\SSU-22621_378-x64_cab
[INFO] Found Windows11.0-KB5018427-x64.cab file
[INFO] Running PSFExtractor.exe E:\expand\Windows11.0-KB5018427-x64.cab
[WARNING] ignore wsusscan.cab
~~~

- Scan an expanded directory
~~~shell
PS S:\tools\windows_patch_extract> py -3 .\magic.py -scan e:\expand
[INFO] Scanning e:\expand
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------  --------------  -----  ------
e:\expand\SSU-22621_378-x64_cab\amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35_10.0.22621.378_none_4db921ab6e990364\appxprovisionpackage.dll                   10.0.22621.378  amd64  normal
e:\expand\SSU-22621_378-x64_cab\amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35_10.0.22621.378_none_4db921ab6e990364\appxreg.dll                                10.0.22621.378  amd64  normal
e:\expand\SSU-22621_378-x64_cab\amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35_10.0.22621.378_none_4db921ab6e990364\cmifw.dll                                  10.0.22621.378  amd64  normal
e:\expand\SSU-22621_378-x64_cab\amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35_10.0.22621.378_none_4db921ab6e990364\edgeai.dll                                 10.0.22621.378  amd64  normal
e:\expand\SSU-22621_378-x64_cab\amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35_10.0.22621.378_none_4db921ab6e990364\eventsinstaller.dll                        10.0.22621.378  amd64  normal
e:\expand\SSU-22621_378-x64_cab\amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35_10.0.22621.378_none_4db921ab6e990364\firewallofflineapi.dll                     10.0.22621.378  amd64  normal
...snip...
~~~

- Extract a single file
~~~shell
PS S:\tools\windows_patch_extract> py -3 .\magic.py -extract sxssrv.dll amd64 e:\expand
[INFO] Scanning e:\expand
[INFO] Using cached result
[INFO] Forward file found at E:\expand\Windows10_0-KB5018418-x64_cab\amd64_microsoft-windows-sxssrv_31bf3856ad364e35_10.0.22000.1098_none_d9d9980beec843d4\f\sxssrv.dll
[INFO] Extracting base_file from local machine
[INFO] Reverse file found C:\Windows\WinSxS\amd64_microsoft-windows-sxssrv_31bf3856ad364e35_10.0.22000.1098_none_d9d9980beec843d4\r\sxssrv.dll
[INFO] Normal file found C:\Windows\WinSxS\amd64_microsoft-windows-sxssrv_31bf3856ad364e35_10.0.22000.1098_none_d9d9980beec843d4\sxssrv.dll
[INFO] Applying delta_patch
[INFO] Applying forward_file to base_file
[INFO] File version 10.0.22000.1098 written to e:\sxssrv.dll
~~~

- Extract 2 files for diffing in IDA
~~~shell
PS S:\tools\windows_patch_extract> py -3 .\magic.py -diff vmemulateddevices.dll amd64 E:\expand\
[INFO] Using platform amd64
[INFO] Scanning E:\expand\
[INFO] Forward file found at E:\expand\Windows10_0-KB5018418-x64_cab\amd64_hyperv-vmemulateddevices_31bf3856ad364e35_10.0.22000.1042_none_25945f084ac0858f\f\vmemulateddevices.dll
[INFO] Extracting base_file from local machine
[INFO] Reverse file found C:\Windows\WinSxS\amd64_hyperv-vmemulateddevices_31bf3856ad364e35_10.0.22000.1042_none_25945f084ac0858f\r\vmemulateddevices.dll
[INFO] Normal file found C:\Windows\WinSxS\amd64_hyperv-vmemulateddevices_31bf3856ad364e35_10.0.22000.1042_none_25945f084ac0858f\vmemulateddevices.dll
[INFO] Applying delta_patch
[INFO] Applying forward_file to base_file
[INFO] Found vmemulateddevices.dll version: 10.0.22000.1042 in E:\expand\
[INFO] Searching for older verion of vmemulateddevices.dll in C:\Windows\WinSxS
[INFO] Normal local files with smaller version found:
----------------------------------------------------------------------------------------------------------------------------  --------------  -----  ------
C:\Windows\WinSxS\amd64_hyperv-vmemulateddevices_31bf3856ad364e35_10.0.22000.675_none_a779455e9882cc22\vmemulateddevices.dll  10.0.22000.675  amd64  normal
----------------------------------------------------------------------------------------------------------------------------  --------------  -----  ------
[INFO] Copying C:\Windows\WinSxS\amd64_hyperv-vmemulateddevices_31bf3856ad364e35_10.0.22000.675_none_a779455e9882cc22\vmemulateddevices.dll to E:\
~~~


# Reference
- [PSFExtractor](https://github.com/Secant1006/PSFExtractor)

- [Extracting and Diffing Windows Patches in 2020](https://wumb0.in/extracting-and-diffing-ms-patches-in-2020.html)

- [How to Deal with Microsoft Monthly Updates to Reverse Engineering Binary Patches](https://www.coresecurity.com/core-labs/articles/how-deal-microsoft-monthly-updates-reverse-engineering-binary-patches)
