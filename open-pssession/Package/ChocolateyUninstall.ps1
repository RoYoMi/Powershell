# module name
$moduleName = 'Open-PsSession'

# Source and destination variables
$Destination = "$Env:ProgramFiles\WindowsPowerShell\Modules\$moduleName\"

# delete the destination folder if it exists
if ( (Test-Path $destination) ) { 
    get-item $Destination | remove-item -Recurse -Force
    }

# remove the scheduled task
if ( $ScheduledTask = Get-scheduledtask -TaskName Query-CrowdStrike -ErrorAction SilentlyContinue ) {
    write-host "  removing Query-CrowdStrike scheduled task"

    $ScheduledTask | Stop-ScheduledTask
    $ScheduledTask | Unregister-ScheduledTask -Confirm:$False -ErrorAction SilentlyContinue

    # delete the scheduled task folders if they existed
    # this command forces the RunInFolder value taken from the scheduled task to look like a real path rather than blindly taking any value :o
    # the path must contain a directory name, the string 'QueryCrowdStrike' and not contain any backtacing parent references like '\..\'
    # it would suck if someone accidently set the value to something like 'c:\AdhocScripts\QueryCrowdStrike\..\..\Windows\System32`
    # I'm sure there are edge cases that will work around this but it limits the dumb obvious ones
    # https://regex101.com/r/Rym6oc/1
    if ( $ScheduledTask.actions.Arguments -imatch '-RunInFolder\s+"(?<RunInFolder>(?![^"]+?[\\/]\.\.[\\/])(?=[a-z]:[\\/][^"]+[\\/]QueryCrowdStrike)[^"]+)' ) { 
        write-host "  Removing Query-CrowdStrike hot folder '$($Matches.RunInFolder)'"
        get-item $Matches.RunInFolder | remove-item -Recurse -Force
        } # end if
    } # end if 

