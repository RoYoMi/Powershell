## Sysnopsis

This class automates the process storing, accessing, and validating credentials which can be tested against a credential manager like AD.

The idea is that some automation steps might accidently use an old/invalid password which could quickly lock an account if left unchecked.

Using tools like the Microsoft created powershell module for credential management is also a good option, but does require it to be setup and managed. 
 
## Design Requirements:
- Use powershell 7 
- never retain the password or credential in memory or plain text
- every time the credential is received it is pulled from the clixml file
- passwords stored in clixml files are only readable by the user who created them and only on the same computer where it was created
- if clixml object does not exist then create it, and test to ensure the created object is valid
- if clixml object fails to validate against the authority then delete the clixml object to prevent it from being used or tested again which if repeated  will eventually lead to account lockout
- test password prior to building a Pack item
- can be extended to support powershell credential manager
- scripts running as service accounts will need a mechanism  to update clixml file password if it changes


## Install

Install Chocolatey, execute the following in a powershell window with elevated rights.
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

Setup Windows Engineering Chocolatey repository.
```powershell
choco source add --name WindowsEngineering --source "\\nm.nmfco.com\dfs01\appls\sd\Chocolatey\"
```

Install the module.
```powershell
choco install Class_CustomCredential -y
```

Confirm the module is working as expected. This command should return a PS credential object. You many also be prompted to input a password, this is normal.
```powershell
using module Class_CustomCredential
[CustomCredential]::New("$($Env:UserDomain)\$($Env:Username)").PsCredential()
```


## Examples

### load the credential

This command can appear in your scripts, if so then it'll need to be inserted before other commands.
```powershell
using module Class_CustomCredential
```

### Get credential

Get the credential for an account you own, if the credential does not yet exist then create it, and prompt the user for the password.
```powershell
$NonAdmin = [CustomCredential]::New("nm\mil1642")
```


### Get credential for a system without a validation mechanism, this is used for things like tokens

```powershell
$TokenCredential = [CustomCredential]::New("a590415bf7b66bfe31f4405dc060e9d4", "NoValidation")
```

### Pass a custom credential into to something expecting a PsCredential

```powershell
$NonAdmin = [CustomCredential]::New("nm\mil1642")
New-PsSession -ComputerName AFakeComputer -Credential $NonAdmin.PsCredential()
```

### Delete the credential file

```powershell
$NonAdmin = [CustomCredential]::New("nm\mil1642")
$NonAdmin.Remove()
```

### Override the credential object for service accounts

This is really useful where service or NPID accounts are being used to run scheduled tasks. Such accounts are not authorized to login and therefore you're not able to easily create a clixml file for a given credential owned by such a user.

Log in to the system using an account with admin rights. This example we're updating a CrowdStrike API credential which is owned by user mecmstp:

```powershell
$TokenCredential = [CustomCredential]::New("a590415bf7b66bfe31f4405dc060e9d4", "NoValidation")
$TokenCredential.CreateManualUpdateFile()
Notepad $TokenCredential.ManualUpdateFile       # store the password in plain text and save the file
```

Place the manual update file into the user's Credential folder
```powershell
Move-Item -Path $TokenCredential.ManualUpdateFile -Destination "$($Env:UserProfile)\..\mecmstp\Credentials\" -Force
```

Once those commands are executed then have the account request the credentials. The plain text file will automatically be deleted and the corresponding clixml file owned by that the user for this credential will be updated.

In this example the scheduled task named Query-CrowdStrike will be triggered. This scheduled task is designated to run using the mecmstp account, and it uses the CrowdStrike API token credential. Therefore when it requests the CrowdStrike API token credential it'll see the json formatted file and will update encrypted clixml file and will delete the Json file. 

```powershell
$env:computername | Get-HostFromCrowdStrikeScheduledTask -ReturnNameResolution
```

