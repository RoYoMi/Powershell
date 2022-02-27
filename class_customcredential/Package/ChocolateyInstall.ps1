# ModuleName
$moduleName = 'Class_CustomCredential'


# Source and destination variables
    # Folder to copy your files from the unpacked folder. 
    # Note the script will be executing from Package context, so we need to use ".." to navigate down a folder
    $Source = Get-Item "$(Split-Path $MyInvocation.MyCommand.Definition)\..\$ModuleName"

    # make the module available to all users, great care should be expressed if using this is used
    #   $Destination = "$Env:ProgramFiles\WindowsPowerShell\Modules\$ModuleName\"

    # make the module available to your user account, at bit more wild wild west.
    $Destination = "$($Env:UserProfile)\Documents\PowerShell\Modules\$ModuleName"

# Copy-Item results differ depending on if destination exists or not, therefore we're creating it if non-existent
if (-not (Test-Path $Destination)) { 
    new-item -Type Directory -Path $Destination | Out-Null 
    } # end if

# copy files from the Chocolatey library to the actual place where we want them
$Source | Copy-Item -Destination $Destination -Force -Recurse

# preflight
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

# Import module in current shell session
# Import-Module $moduleName -force
