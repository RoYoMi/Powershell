
# this file will be sourced when the package is installed or upgraded

# ModuleName
$ModuleName = 'Use-Chocolatey'

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

# Include any additional steps necessary to install the module like: adding any scheduled tasks, or creating registry keys this module may need created

# Chocolately uses PowershellGet to execute commands, it does not have a full library of commandlets and may throw additional errors
# If you have additional steps to complete like install-module for other products, then either include those modules here or redirect the user to get them separately 

