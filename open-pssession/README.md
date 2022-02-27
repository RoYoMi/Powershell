## Table of Contents

[[_TOC_]]

----

## Synopsis

This module is focused on providing a mechinism for creating new Powershell WinRM sessions into remote computers in an environment where DNS entries are missing or are not accurate. This module creates standard Powershell sessions which can be directly leveraged by other existing scripts and processes. 

## Description 

When endpoint DNS entries are inaccurate or not existent, e.g. VPN connected workstations, we see New-PsSession will fail to connect to about 40% of a randomly selected set of known online devices. 

The problem can be worked around if you already know the correct remote IP. But getting this IP reqiures quering several systems and updating your local hosts file. Or accepting a powershell session where certificate confirmation has been disabled.

Introducing **Open-PsSession** which automates the following process:

  - Find a valid IP address for the remote device from: DNS, CrowdStrike, SCCM
  - Confirm the remote device responds on the HTTPS WinRM port 5986
  - If DNS resolution is not accurate, then update the local hosts file
  - Open a Powershell WinRM session to the remote IP 
  - Confirm the remote device has the correct expected name
  - Modify the session's command prompt to be visually distinct


## Requirements

  - Required: Access to the production admin server. This server has the necessary firewall exceptions in place to allow connecting out to remote end users devices
  - Optional: Access to the CyberArk vault with the CrowdStrike API password. This is only necessary if DNS is inaccurate and the script goes to query CrowdStrike 
  - Optional: Access to the SCCM database to perform a query. This is only necessary if DNS is inaccurate and the script attempts to query SCCM

## Install

### Setup Chocolatey

Install Chocolatey, execute the following in a powershell window with elevated rights.
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco update chocolatey -y
choco --version
```

Setup Windows Engineering Chocolatey repository.
```powershell
choco source add --name WindowsEngineering --source "\\nm.nmfco.com\dfs01\appls\sd\Chocolatey\"
```

### Install Open-PsSession module

From an elevated powershell 7 window issue the following command to install Open-PsSession
```powershell
choco install Open-PsSession -y
```

Setup the scheduled task to query the CrowdStrike API. This command will prompt you for two credentials:
1. The scheduled task credential. This is the AD account the scheduled task will run as.
1. The CrowdStrike API account is the account granted read permission for CrowdStrike.
```powershell
Install-CrowdStrikeScheduledTask
```

Confirm the module is working as expected. This should report back the IP address recorded in CrowdStrike for the current computer.
```powershell
Test-CrowdStrikeQuery
```

### Upgrade Open-PsSession

If Open-PsSession is already installed and you'd like to install the latest version then issue the following command.
```powershell
choco upgrade Open-PsSession -y
```


## Open-PsSession 

The Open-PsSession function call that can create a single powershell session into multiple remote comptuers. 

### -Targets
Array, Required, Can be piped in

An array of any of the following: computer names, FQDN, SCCM created device objects, Powershell sessions.

Duplicate names can be included but the duplicates will be ignored.

### -Credential
Powershell Credential object, Required, Defaults to current user

The account used to connect to the remote workstation. This account must have remote login rights on the remote workstation or you'll receive authentication errors.

If this option is not included then the default action is check if a cached credential exists for this current user. A prexisting cached credential will be tested against AD before the credential is used to open a remote session. If the credential is not valid or doens't exist then the user will be prompted to enter credentials which will then be cached in an encrypted XML file locally in the user's profile. This file can only be decrypted by the current user on the current machine.

The precheck serves to prevent accidently locking out your account if the credential is not valid when opening multiple sessions with one command. This precheck only confirms with AD that the credential is valid, it does not confirm you have rights.


### -CrowdStrikeCache
String, Optional

This option is used internally for opening  multiple parallel connections

This is the full path to a JSON encoded file listing data collected from CrowdStrike


### -IP
String, IPv4 Address

If this is provided then this IP address will be tested before DNS or the other data sources are queried.

It's best to use this option for only single targets. If the system validation fails to confirm this IP is correct then it will still query the other data sources.


### -Server
Switch, Optional, defaults to false

When this switch is used, then Open-PsSession will assume the provided targets are servers and DNS is accurate. With this enabled no additional IP querying will be done.


## Open-MultiPsSession

`Open-PsSession` is a single threaded function and will process each requested server serially. Each connection request could take upwards fo 30 seconds or more. To reduce the wait time when opening many sessions, you can use this `Open-MultiPsSession` command. 

Open-MultiPsSession is wrapper function that will leverage the `foreach -parallel` multithreading built into powershell. In this operation upto 25 unique new runspaces are created at a time. These run spaces will then execute a single Open-PsSession call.

This function is nearly the same, with some minor differences:
  - The -Credential object should be a [CustomCredential] object and not a standard [PsCredential]. This allows the credential to be confirmed with AD; and prevents it from being passed into the other runspaces as plain text.
  - A cache file will be created for CrowdStrike data. This file will contain details obtained from CrowdStrike about all requested computers regardless of whether this data is actually needed. This bypasses a token rate limit issue with the CrowdStrike API when running parallel runspaces, and will accelerate the overall connection time.


### -Targets
Array, Required, Can be piped in

An array of any of the following: computer names, FQDN, SCCM created device objects, Powershell sessions.

Duplicate names can be included but the duplicates will be ignored.


### -Credential
PsCredential or CustomCredential, Required, defaults to a cached credential for the currently logged in user, if no cached credential for the current user then one will be created and the user will be prompted to provide a password

If a PsCredential is provided it will be convered into a CustomCredential which will create an encrypted .clixml file containing the credential. This file will be saved in the user's profile where it can be sourced by the individual runspaces this command will create.

If this option is not included then the default action is check to see if a cached credential exists for the currently logged in user. A prexisting cached credential will be tested against AD before the credential is used to open a remote session. If the credential is not valid or doens't exist then the user will be prompted to enter credentials which will then be cached in an encrypted XML file locally. This file can only be decrypted by the current user on the current machine.

The precheck serves to prevent accidently locking out your account if the credential is not valid when opening multiple sessions with one command. Do not ask me how I know this will happen. This precheck only confirms with AD that the credential is valid, it does not confirm you have rights.


### -CrowdStrikeCache
String, Optional, defaults "c:\temp\CrowdStrikeCache.json"

This is the full path to a JSON encoded file listing data collected from CrowdStrike.

### -ThrottleLimit
Integer, optional, default 25

The number of concurrent runspaces created to process parallel requests. This will directly impact system-wide performance. So it's recommended not to exceed 25.


## Examples

### Inital setup

This can only be used from the production admin server because this server already has the necessary firewall exceptions allowing it to connect out to user endpoints. The `Open-PsSession` and `Open-MultiPsSession` commands are exported and should be avaialble for immediate use. 


### Open a single session to a remote computer

To open a new session to a computer named s987654

```powershell
$sessions = "s987654" | Open-PsSession
```


### Open a session to multiple computers

This command will try to open four sessions, one for each computer listed. Note the last two computers listed are inside a comma delimited string, this is valid since the input can be string names, FQDN's, complex objects with a .name property, or even `,` or `;` delimited strings of names.

```powershell
$Strings = "s987654", "g1234", "etlpf00007575,etlpf00007572"
$Sessions = $Strings | Open-PsSession
$Sessions
```

### Open sessions with SCCM device objects

Here we'll query SCCM looking for 5 workstations who have checked into SCCM in the past 3 hours and completed a hardware inventory more then 7 days ago. Then try to open a Powershell Session with them. Note this function does require you to have SCCM database rights.

```powershell
$Data = Get-SccmCheckinDates -Top 5 -Where "'$((Get-Date).ToUniversalTime().AddHours(-3))' < LastPolicyRequest AND LastHardwareScan < '$((Get-Date).ToUniversalTime().AddDays(-7))'"  -OrderBy "LastHardwareScan"
$Sessions = $Data | Open-PsSession
```

Or we can run that same command using the Open-MultiPsSession to leverage parallel processing.

```powershell
$Data = Get-SccmCheckinDates -Top 5 -Where "'$((Get-Date).ToUniversalTime().AddHours(-3))' < LastPolicyRequest AND LastHardwareScan < '$((Get-Date).ToUniversalTime().AddDays(-7))'"  -OrderBy "LastHardwareScan"
$Sessions = $Data | Open-MultiPsSession
```

Or if you have the SCCM powershell module installed and access into SCCM, you could in theory query all the members of an existing collection and open sessions to them. Some care should be expressed, each session does require network resources and creates a bit of overhead for your local OS, so ... don't go wild opening hundreds of sessions. 

```powershell
Import-Module "$($env:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"; cd NM1:;

$CollectionName = "SCCM Pre-Production Client"
$Devices = Get-CMDeviceCollection -name $CollectionName | Get-CMCollectionMember

$Sessions = $Devices | Select-Object -First 20 | Open-MultiPsSession
```

The same can be accomplished using the Admin service. Again great care should expressed here to not open hundreds of sessions.

```powershell
$Admin = [CustomCredential]::New("nm\mil1007-nm")
$CollectionName = "SCCM Pre-Production Client"
$SiteServer =  @{"NM"="ntdbph8012m00.nm.nmfco.com"; NMTEST="ntdbth7965m00"; NMDEV="ntapdh7589m00"}[$env:UserDomain]

$SmsCollection = Invoke-RestMethod -Uri "https://$($siteserver)/adminservice/wmi/SMS_Collection?`$filter=Name eq '$($CollectionName)'" -Method GET -credential $Admin.PsCredential()  -skipcertificatecheck | Select-Object -ExpandProperty Value
$AllMemberships = Invoke-RestMethod -Uri "https://$($siteserver)/adminservice/wmi/SMS_FullCollectionMembership?`$filter=CollectionID eq '$($SmsCollection.CollectionID)'" -Method GET -credential $Admin.PsCredential() -skipcertificatecheck | Select-Object -ExpandProperty Value

$Sessions = $AllMemberships | Select-Object -First 20 | Open-MultiPsSession
```

## What can we do with an open Powershell session

What follows are some canned examples showing how to use these sessions. We'll assume the `$Sessions` variable is an array of 1 or more sessions you'd like to effect. Your sessions can be created by using one of the methods above, or of from standard commandlets like `New-PsSession` or `Get-PsSession`.

### Access Powershell on the remote computer

Assuming you want to manually enter commands on the remote computer. This will open that session and put at the command prompt. Open-PsSession commands from above will automatically modifiy the command prompt to be visually distinct so help prevent confusion.

```powershell
$Sessions[0] | Enter-PsSession
```

### Trigger CM agent action

These actions are the same actions available on Control Panel\Configuration Manger --> "Actions" tab.

Run the Hardware Inventory
```Powershell
$Sessions | Start-CcmAction -HardwareInventory
```

Run Software Inventory
```powershell
$Sessions | Start-CcmAction -SoftwareInventory
```

Run GPUpdate, Hardware Inventory, and Machine Policy Retriveal.
```powershell
$Sessions | Start-CcmAction -GPUpdate -HardwareInventory -MachinePolicyRetrieval
```

The `Start-CcmAction` will accept the following switches: -GpUpdate, -ApplicationDeployment, -HardwareInventory, -SoftwareInventory, -SoftwareUpdate, -MachinePOlicyRetrieval, -MachinePolicyEvaluation. These switches can be used inter changably and in any order.

The -SoftwareCenter switch is shorthand and will trigger an ApplciationDeployment, MachinePolicyRetrieval, and SoftwareInventory. All of which are required to update Software Center.


### Collect Logs

The `Get-FilesFromPsSession` and it's wrapper `Get-FilesFromMultiPsSession` will yeild identical results. The later will use foreach -parallel to run faster where multiple remove computers are involved.

These commands will do the following for each remote computer:
1. Confirm there is enough free space to handle the request
1. Copy the desired files, standard dos wild cards are allowed, to the remote computer's temp folder
1. Zip the copied files, this makes collecting the files faster. The .zip file name will include the computer name.
1. Clean up temp files.
1. Copy the Zip file from the remote computer to the local d:\temp\RemoteLogs folder
1. Unpack the .zip file to the same folder

Note if you leave the `-DeletePreexistingZip` switch off, then only newer files will be pushed into the zip file. Not including this option might make the operation run faster if you are re-running the same recently used command.

```powershell
$Logs = @("c:\windows\Ccm\Logs\CcmExec.log" 
  , "c:\windows\Ccm\Logs\CcmMessaging.log" 
  , "c:\windows\Ccm\Logs\CCMNotificationAgent.log" 
  , "c:\windows\Ccm\Logs\CcmRestart.log" 
  , "c:\windows\Ccm\Logs\CcmRepair.log" 
  , "c:\windows\Ccm\Logs\InventoryProvider.log" 
  , "c:\windows\Ccm\Logs\SMSTS*.log" 
  , "c:\windows\Ccm\Logs\DataTransferService.log" 
  , "c:\temp\*.transcript.log"
  )
$Sessions | Get-FilesFromMultiPsSession -RemoteSource $logs -DeletePreexistingZip
Explorer d:\temp\RemoteLogs
```

### Search text files for knowing strings or regular expressions

The `Read-CmLogs` command will do the following:
- Read the provided -Log files
- Accept a where statement script block
- Return only the matching lines of text

Note: 
- The filtering happens on the remote computer, so only the interesting data travels on the network. 
- When working with CM log files, the `-Tail` option can be misleading. These logs may contain "hidden" lines. 

Read the last 200 lines of CcmMessaging.log file looking or the string 'token'

```powershell
$Entries = $Sessions | Read-CmLogs -Logs c:\windows\Ccm\Logs\CcmMessaging.log  -Tail 200 -Where { $_.Log -imatch 'token' }
```

Read the last 10 lines CM install logs. This could be used to check the CM Agent install errors. The command includes a handy switch `-Install` which tells the command to read the CM install logs.

```powershell
$Entries = $Sessions | Read-CmLogs -Install -Tail 10 
```

### Set the Configuration Manager client to verbose logging

The `Set-CcmVerbosity` command will enable or disable verbose logging. Once set it will also restart the CM agent so the setting takes effect.

```powershell
$sessions | Set-CcmVerbosity -Enable
```

```powershell
$sessions | Set-CcmVerbosity -Disable
```

### Execute any Adhoc script

`Invoke-ScriptInMultiPsSession` will allow you to execute any adhoc script against established sessions. For obvious reasons this great care should be exercised when using this command.

First create the script you'd like executed. The script will need to include all the bits necessary for it to run, e.g. credentials, additional modules, other code references.

If your script will be returing powershell objects then you'll likely need to add a custom note property so you know where the results came from.

In this example we'll create a scriptblock to go collect the top 5 processes based on CPU load. 
   - the first line gets the desired data, then filters it down to what we need. 
   - the second line creates the custom note property and populates it with the remote device's computername. 
   - the last line returns the results.

```powershell
$Scriptblock = { 
    $Processes = Get-Process | Sort-Object Cpu | select-Object -first 5 
    $Processes | Foreach-Object { Add-Member -InputObject $_ -NotePropertyName FromSession tePropertyValue $env:computername }
    $Processes
    }
```
With the script block created we can pass it into our function, and view the results. Note the `Select-Object *` is required to see all the fields instead of just the default ones.

```powershell
$Results = $Sessions | Invoke-ScriptInMultiPsSession -Scriptblock $Scriptblock
$Results | Select-Object * | Out-Gridview -Title "From Invoke-ScriptInMultiPsSession"
```

In this example we'll get a list of files and folders from c:\temp on each remote computer.

```powershell
$Scriptblock = { 
    $Items = Get-childItem c:\temp\
    $Items | Foreach-Object { Add-Member -InputObject $_ -NotePropertyName FromSession tePropertyValue $env:computername }
    $Items
    }
$Results = $Sessions | Invoke-ScriptInMultiPsSession -Scriptblock $Scriptblock
$Results | Select * | Out-Gridview -Title "From Invoke-ScriptInMultiPsSession"
```


