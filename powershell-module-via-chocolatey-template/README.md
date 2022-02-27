## Table of Contents

[[_TOC_]]

----

## Synopsis

This module is designed as a working template for demonstrating how to create your first Chocolatey package.

## Description 

Making powershell modules available via Chocolatey makes keeping them updated super easy. This module contains all the necessary parts for creating a Chocolatey package that deploys a basic powershell module containing a few functions.

The designed intent here is to help jumpstart the process. There are a plethora of options and advanced concepts which are out of scope of this base module.


## Requirements

- Requires Chocolatey installed on the machine where you do development work
- On the computeres where you want to deploy your package
  - Requires Chocolatey installed 
  - Admin rights 


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

### Install Start-SampleFunction module

From an elevated powershell 7 window issue the following command to install Start-SampleFunction.
```powershell
choco install Start-SampleFunction -y
```


### Upgrade Start-SampleFunction

If Open-PsSession is already installed and you'd like to install the latest version then issue the following command.
```powershell
choco upgrade Start-SampleFunction -y
```


## Functions included in this module

### Start-SampleFunction

This function will parrot back a phrase you provide. If no phrase was provided then it'll great the world.

```powershell
Start-SampleFunction -Message "Hi $($env:username)"
```

### Get-Quote

This function will get a silly quote from the interwebs.

```powershell
Get-Quote
```

### Get-OutDoNotRun

Although it is exported do not modify or run this function.

```powershell
Get-OutDoNotRun
```



## ToDo

Things to do when using this template for your powershell module.

1. .psd1 file
   1. Change the GUID when you first create the package. Once this is unique to your package you're no need to change this. A guid can be created in powershell using `[guid]::NewGuid()`
   1. Change the package name
   1. Set version, this should match the version in your .nuspec file
   1. Set exported functions, this will be a comma delimited list
   1. Change the name of the file to match the name of your powershell module
1. .psm1 file
   1. If you have a single powershell file for your module then that file can replace the one in the module folder
   1. If you want to deploy multiple .ps1 files as your module, then include your .ps1 files in the module folder. These will be sourced by the existing .psm1 file
   1. Name this .psm1 file to match the name of your module
1. In your .nuspec file
   1. Set the ID, this will be the name of your product. Replace spaces with hyphens, all letters should be lower case, no crazy characters
   1. Set the package name to match your product, this should match the case of the actual product name
   1. Set version, this should match the version in your .psd1 file
   1. Set author
1. Modify the Chocolatey scripts to fit your install requirements
   1. These chocolatey scripts will be excuted with powershellget. This utility does not have access to all powershell commandlets so overly complex tasks may throw errors
   1. Set the module name variable, this will need to be the actual name of your module, and needs to match the filename (without file extension) on the .psd1 and .psm1 files

1. Create your package. 
   Replace the values in the command to match your package and repository. 

   ```powershell
   $SourceNuspecFile = "X:\gitlab\dw-endpoint\Modules\ModuleTemplate\Start-SampleFunction.nuspec"
   $PackageOutputFolder = "\\nm.nmfco.com\dfs01\appls\sd\Chocolatey"
   choco pack X:\gitlab\dw-endpoint\Modules\ModuleTemplate\Start-SampleFunction.nuspec --out \\nm.nmfco.com\dfs01\appls\sd\Chocolatey
   ```
1. Test your package
   Recommend using the --force option, without this option if the package is already install on your system then Chocolatey will not reinstall the package so your changes will not come through.
   ```powershell
   choco install Start-SampleFunction -y
   ```

1. Version changes. You define the cadence of your version changes. If you change the contents of your package to fix a problem or add a feature then you should also update the version in the .psd1 and the .nuspec files. This will automatically carry forward into your package when you re-pack it. If the version does increase then later users with your package installed can simply issue an update command like:
   ```powershell
   choco upgrade Start-SampleFunction -y
   ```

## GitLab

In GitLab you should create a project that will include your README.md, .nuspec file, and your entire module folder. At some future point we may create a CICD pipeline that will automatically repackage your module as changes are made to it.
