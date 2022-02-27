# ModuleName
$moduleName = 'Class_CustomFile'

# Source and destination variables
$Destination = "$Env:ProgramFiles\WindowsPowerShell\Modules\$moduleName\"

# delete the destination folder if it exists
if ( (Test-Path $destination) ) { 
    get-item $Destination | remove-item -Recurse -Force
    }
