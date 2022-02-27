# ModuleName
$moduleName = 'Class_CustomFile'
# source folder
$extensionDir = Split-Path $MyInvocation.MyCommand.Definition

# preflight
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

# Source and destination variables
$Destination = "$Env:ProgramFiles\WindowsPowerShell\Modules\$moduleName\"
$ExcludeFiles = $(Get-item "$extensionDir\*Chocolatey*.ps1").Name
$source = "$extensionDir\*"

# Copy-Item results differ depending on if destination exists or not, therefore we're creating it if non-existent
if (-not (Test-Path $destination)) { mkdir $destination | Out-Null }
Get-item $source | 
    Where-Object {$_.Name -notin $ExcludeFiles} | 
    Foreach-Object { Copy-Item $_ -Destination $destination -Force -Recurse }

# Import module in current shell session
# Import-Module $moduleName -force
