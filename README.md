# plague
Default Detections for EDR

The detections detailed below are what I attempt to establish on any EDR product I deploy or work on. Take your own considerations for criticality and datasets.

## Tampering with sensors or other security products.

Gather a list of all the systems you use on endpoints as part of your security program. This could be asset management, audit or access control etc. Once you have your list work on understanding how they interact with your endpoints and what components are necessary whether its WMI, GPO client or installed agents. Write a detection that monitors for these components being tampered with such as services being disabled or registry keys being changed.

## Scripts inside temporary directories.

Scripts do execute inside temporary directories for legitimate purposes sometimes but you want to build a detection so you know when this happens. Use this detection as context for others. Directories you want to monitor are:

%userprofile%\AppData\Local\Temp

%systemroot%\Temp

%systemroot%\Windows\Temp

%systemroot%\Documents and Settings%username%\Local Settings\Temp

%systemroot%\Documents and Settings\Default User\Local Settings\Temp

%systemroot%\Documents and Settings\All Users\Local Settings\Temp

## Known bad drivers

Grab the list from (https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md) and just do a simple hash lookup. Easy!

## LOLBAS rename attempts

Here we want to look for files native to the operating system being renamed to avoid detections. Write your detection to capture the hashes of the files here https://lolbas-project.github.io/ and identify those that do not match the appropriate names.

## Windows Firewall Disabled

Build a detection that identifies the services 'Windows Defender Firewall Service' or 'Base Filtering Engine' being disabled. In addition, look to catch any command line that attempts to place incredibly open rules. You can extend this to look for firewall rule entries being rapidly added too.

## Copying of browser data stores

Build a detection that identifies data being copied or moved from the following directories:

\Google\Chrome\User Data\Default\Login Data

\Opera Software\Opera Stable\Login Data

\Mozilla\Firefox\Profiles\

\Microsoft\Edge\User Data\

## Disabling of UAC

Monitor changes to the below registry key as it may suggest that UAC has been disabled.

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

## WMI Executing files

There are lots of ways to execute files using WMI and in my experience it rarely happens legitimately. You want to identify the use of wmic, Invoke-WmiMethod or Win32_Process particularly where a directory is included in the script or 'create' is utilised.

## Shadow Volumes being deleted

Deleting shadow volumes is just a default technique for most ransomware variants now so its a great way to raise red flags. Below are examples of commands:

vssadmin delete shadows /all /quiet

Get-WmiObject -Namespace root\cimv2 -Class Win32_ShadowCopy | Where-Object { $_.VolumeName -eq "C:\" } | ForEach-Object { $_.Delete() }

wbadmin delete systemstatebackup -keepversions:0

## Device being set to safemode using bcdedit cmdline

Look to capture when the below command is ran, it enables malicious actors an easy way to disable security tools and ensure only their binaries are running:

bcdedit /set safeboot {"Minimal", "AlternateShell", "Network"}

## Unauthorized RMM tools use

Enumerate what RMM tools are authorised in your environment and build a detection to flag any other variations. I maintain a list of some here:
https://github.com/QueenSquishy/Zombie/blob/main/Lists/RMM%20Tools



