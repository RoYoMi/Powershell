## Table of Contents

[[_TOC_]]

----

## Synopsis

Handy tools created to automate some of the tedious task involved with packing Chocolatey packages

## Description 



## Requirements


## Install

These steps will deploy this module and make it available to your user account.


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

### Install powershell module

From an elevated powershell 7 window issue the following command to install the powershell module.
```powershell
choco install Use-Chocolatey -y
```


### Upgrade the powershell module

If Use-Chocolatey is already installed and you'd like to install the latest version then issue the following command.
```powershell
choco upgrade Use-Chocolatey -y
```


## Functions included in this module

### ConvertTo-PsModuleChocolateyPackage

This will parse the versions from both the Nuspec and .psd1 file. 
If both versions are the same, then the build version number will be incremented and written back to their respecive files
If both versions are different then the latest version number will be used without incrementing, and applied to both files. 

The function will then attempt to `choco pack` against the provided nuspec files.

If a file was packed with an incorrect version, then you'll need to visit the repository and remove the incorrect versioned files.

#### -Out

string, defaults to `\\nm.nmfco.com\dfs01\appls\sd\Chocolatey`

Defines the repository where the resulting package will be placed. At this time we only have a file repository.

#### -NuspecFiles

Array of strings

Full paths to the .nuspec file which defines the package.


#### Examples

This command will repack the Open-PsSession module.

```powershell
ConvertTo-PsModuleChocolateyPackage -NuspecFiles "X:\gitlab\dw-endpoint\Modules\Open-PsSession\Package\Package.nuspec"
```

This will do the same thing but we're illustrating that it works via pipeline.

```powershell
"X:\gitlab\dw-endpoint\Modules\Open-PsSession\Package\Package.nuspec" | ConvertTo-PsModuleChocolateyPackage 
```


