
# this file will be sourced with the package is uninstalled


# module name
$moduleName = 'Start-SampleFunction'

# Destination variables, describing where the module was installed
    # this destination will make the module available to all users, great care should be expressed if using this is used
    #   $Destination = "$Env:ProgramFiles\WindowsPowerShell\Modules\$ModuleName\"

    # this destination will make the module available to your user account, at bit more wild wild west.
    $Destination = "$($Env:UserProfile)\Documents\PowerShell\Modules\$moduleName\"

# delete the destination folder if it exists
if ( (Test-Path $destination) ) { 
    get-item $Destination | remove-item -Recurse -Force
    } # end if 

# include any additional steps necessary to remove the module like: removing any scheduled tasks, or removing registry keys this module may have created
