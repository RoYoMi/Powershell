# https://www.powershellgallery.com/packages/PSFalcon/1.4.2
# Install-Module -Name PSFalcon -RequiredVersion 1.4.2 -SkipPublisherCheck -Scope AllUsers
# 1.4.2 is being used because it has a mechnisim to save the token 


function Get-HostFromCrowdStrike {
    # fetch host information from CrowdStrike
    #
    # crowdstrike rate limits the frequence of queries which makes their API inherrently incompatiable with multithreading
    # to query crowdstrike we must collect the data for all systems, then cache it to a file locally, where the file can then be used 
    #
    # Requires 
    #   Powershell Version 5.1
    #   crowdstrike module
    #   Access to CyberArk vault containing our API user id: 
    #       a590415bf7b66bfe31f4405dc060e9d4 - is what these IDs typically look like
    # 
    # examples:
    #   $CrowdStrikeData = 'B9767.NM.NMFCO.COM' | Get-HostFromCrowdStrike 
    #   
    #   $CrowdStrikeData = $sessions | Get-HostFromCrowdStrike 
    #   $CrowdStrikeData | Select Hostname, Local_IP, First_Seen, Last_Seen, Agent_Local_Time
    #
    #   $CrowdStrikeData = $Data | Get-HostFromCrowdStrike
    #
    #   Create local cache 
    #       ($CrowdStrikeData = $Data | Get-HostFromCrowdStrike) | ConvertTo-Json -Depth 10 | Out-File c:\temp\CrowdStrikeCache.json
    #   Read local cache
    #       $Cache = Get-Contents c:\temp\CrowdStrikeCache.json | ConvertFrom-Json
    #       $HostFromCrowdStrike = Get-Contents c:\temp\CrowdStrikeCache.json | ConvertFrom-Json | ?{ $_.hostname -ieq 'b8284' } | select -first 1


    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [Alias("Session", "Host","Computername")]
        $Targets = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [PSCredential]$Credential = [CustomCredential]::New("a590415bf7b66bfe31f4405dc060e9d4", "NoValidation", "Please provide CrowdStrike API credential stored in CyberArk").PsCredential($false)

        , [switch]$Quiet
        ) # end param$

    begin {
        $AllTargets = New-Object System.Collections.Generic.List[System.Object]
        # token creation is limited to ~15 per 10 minutes
        # tokens will auto expire after 30 minutes, so reuse an existing token if one already exists
        # if ( -not (Test-FalconToken -ErrorAction SilentlyContinue).Token ) {
        #     if ( -not $Quiet ) { write-host "    Requesting CrowdStrike token" -ForegroundColor darkgray }
        #     Request-FalconToken -Host $CrowdStrikeHost -ClientID $Credential.Username -ClientSecret $Credential.GetNetworkCredential().Password
        #     } # end if

        # create the falcon variable
        if (-not($Global:Falcon) -or -not (get-variable -Name Falcon) ) {
            [System.Collections.Hashtable] $Global:Falcon = @{}
            } # end if

        # If missing or expired, request token
        if ( (-not($Falcon.token)) -and (test-path -path "$($env:UserProfile)\Credentials\CrowdStrikeToken.clixml") ) {
            write-host "  Importing token" -ForegroundColor darkgray
            $Global:Falcon = Import-clixml -path "$($env:UserProfile)\Credentials\CrowdStrikeToken.clixml"
            } # end if 

        if ( (-not($Falcon.token)) -or (($Falcon.expires) -le (Get-Date).AddSeconds(-10)) ) {
            write-host "  Requesting new CrowdStrike token" -ForegroundColor darkgray
            Get-CsToken -Id $Credential.Username -Secret $Credential.GetNetworkCredential().Password

            # write token to clixml for subsequent calls
            $Falcon | Export-Clixml -Path "$($env:UserProfile)\Credentials\CrowdStrikeToken.clixml"
            } # end if
        } # end begin
    process {
        # crowdstrike limits the number of auth tokens and queries to something like 15 per 10 minutes.
        # therefore we must collect all the records in one go by creating one enormous filter string
        foreach ( $Entry in $Targets | Format-ComputerName -Format "hostname:'~~~ComputerName~~~'" ) {
            [void]$AllTargets.Add( $Entry ) 
            } # next entry
        } # end process
    End {
        $HostIds    = Get-CsHostId -Filter $(($AllTargets | Select -Unique) -join ",")  | Select-Object -ExpandProperty Resources
        Get-CsHostInfo -ID $HostIds | Select-Object -ExpandProperty Resources
        } # end end
    } # end function Get-HostFromCrowdStrike


function Get-HostFromCrowdStrikeScheduledTask {
    # A scheduled task is used to obfucate our CrowdStrike API account from general users, this allows us to not have to share the password with other teams
    #
    # run the Query-CrowdStrike scheduled task to query CrowdStrike for a list of given target hosts
    # Targets can be: [,;] delimited strings, powershell sessions, SCCM device objects, or generic complex objects with a name field
    # returns the path to the json file created by the scheduled task
    #
    # The scheduled task will automatically delete any json files older than 24 hours
    #
    # examples
    #   # run a query
    #       $data = "S416823", "mc311" | Get-HostFromCrowdStrikeScheduledTask | get-item | get-content | ConvertFrom-Json
    #       $data | select hostname, local_ip | ft
    #
    #   # update the CrowdStrike Token password used by the scheduled task
    #       $Cred = [CustomCredential]::New("a590415bf7b66bfe31f4405dc060e9d4", "NoValidation", "Please provide CrowdStrike API credential stored in CyberArk")
    #       $Cred.CreateManualUpdateFile()
    #       Notepad $Cred.ManualUpdateFile
    #           # insert the password taken from cyberark into the password field of the json file
    #       Copy-Item $Cred.ManualUpdateFile -Destination "$($Env:UserProfile)\..\mecmstp\Credentials\"
    #       $data = "S416823", "mc311" | Get-HostFromCrowdStrikeScheduledTask | get-item | get-content | ConvertFrom-Json
    #       $data | select hostname, local_ip | ft
    param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [Alias("Session", "Host","Computername")]
        $Targets
        , [switch]$ReturnNameResolution
        , $HotFolder = "D:\AdhocScripts\QueryCrowdStrike\HotFolder\"
        , $ScheduledTask = $(Get-ScheduledTask -TaskName Query-CrowdStrike)
        , [int]$Timeout = 300 # seconds
        ) # end param
    begin {
        $AllTargets = New-Object System.Collections.Generic.List[System.Object]
        $UniqueString = "$PID-$(get-date -uFormat %s)"
        $TimeoutDate = (Get-Date).AddSeconds($Timeout)
        } # end begin
    process {
        # batching the provided list of targets makes it run much faster in CrowdStrike
        foreach ( $Entry in $Targets | Format-ComputerName -Format "~~~ComputerName~~~" ) {
            [void]$AllTargets.Add( $Entry ) 
            } # next entry
        } # end process
    End {
        # create Query json file for the scheduled task to read, ala poor man's EDI
        $AllTargets | ConvertTo-JSon | Out-File "$HotFolder\Query-$UniqueString.json"

        # run the scheduled task 
        $ScheduledTask | Start-ScheduledTask

        # wait for Response file to be created and populated
        do {
            Sleep -Seconds 1
            } until ( (Test-Path -path "$HotFolder\Response-$UniqueString.json" -ErrorAction SilentlyContinue) -or $TimeoutDate -le (Get-Date)  )
        # give an extra 2 seconds to allow the system to complete writting to the file
        Sleep -Seconds 2
        if ( Test-Path -path "$HotFolder\Response-$UniqueString.json" ) {
            $ResponseFile = "$HotFolder\Response-$UniqueString.json" | Get-Item
            if ( $ReturnNameResolution ) {
                $ResponseFile | Get-Content | ConvertFrom-Json | Select-Object hostname, local_ip
                }
            else {
                $ResponseFile | select -ExpandProperty FullName
                } # end if 
            } 
        else {
            write-host "  Warning 0169: Failed to get CrowdStrike response file from the scheduled task" -ForegroundColor DarkRed
            } # end if 
        } # end end
    } # end function Get-HostFromCrowdStrikeScheduledTask


function CrowdStrikeScheduledTaskQuery {
    # this is for execution inside a scheduled task
    # 
    # scheduled task settings:
    #   Action
    #       Program/script  : pwsh
    #       arguments       : -ExecutionPolicy Bypass -Command &{ CrowdStrikeScheduledTaskQuery -RunInFolder "D:\AdhocScripts\QueryCrowdStrike" -CrowdStrikeApiUsername a590415bf7b66bfe31f4405dc060e9d4 }
    param (
        $RunInFolder = "D:\AdhocScripts\QueryCrowdStrike"
        , 
        [Parameter(mandatory=$True)]
        $CrowdStrikeApiUsername
        ) # end param
    Start-Transcript -Path "$($RunInFolder)\ScheduledTaskQueryCrowdStrike.transcript.log"

    $cred = [CustomCredential]::New($CrowdStrikeApiUsername, "NoValidation", "Please provide CrowdStrike API credential stored in CyberArk")

    if ( -not(test-path "$($RunInFolder)\HotFolder") ) {
        New-Item -Type Directory -Path "$($RunInFolder)\HotFolder"    
        } # end if 

    # get files from the hot folder
    (join-path $RunInFolder\HotFolder Query-*.json -resolve | get-item).Foreach{ 
        # read any existing Query files, and run the query
        $Data = $_ | Get-Content | ConvertFrom-Json | Get-HostFromCrowdStrike -Credential $Cred.Credential($false)
        # Output the data to a response file in the same folder
        $Data | ConvertTo-Json -Depth 10 | Out-File -Force -Path $($_ -ireplace "(?<=\\)Query(-[^\\]+\.json)$", "Response`$1")
        # delete the input file
        $_ | Remove-Item -force
        } # next file
        
    # clean up any preexisting files which are older than 24 hours
    join-path $RunInFolder\HotFolder *.json -resolve | Get-Item | Where-Object { $_.LastWriteTime -lt (get-date).AddHours(-24) } | Remove-Item -Force

    Stop-Transcript
    } # end CrowdStrikeScheduledTaskQuery


function Test-CrowdStrikeQuery {
    # check a few things
    param (
        $RunInFolder = "D:\AdhocScripts\QueryCrowdStrike"
        ) # end param

    Write-host "Checking Scheduled task"
    $ST = get-scheduledtask -TaskName Query-CrowdStrike
    if ( $ST ) {
        write-host "  Scheduled task was found" -ForegroundColor DarkGreen
        if ( $ST.State -ieq "running" ) { 
            Write-host "  Scheduled task found in running state, stopped" -ForegroundColor DarkGreen
            $ST | Stop-ScheduledTask
            } # end if
        # does the user running the scheduled task have a credential for the CrowdStrike API?
        write-host "  Scheduled task is configured to run as user $($ST.Principal.UserId)" -ForegroundColor darkgray
        try {
            if ( $st.actions.Arguments -imatch "-CrowdStrikeApiUsername\s+(?<CrowdStrikeApiUsername>[0-9a-z]+)" ) {
                $CrowdStrikeApiUsername = $Matches.CrowdStrikeApiUsername
                write-host "  Scheduled task configured to use CrowdStrike API account '$($CrowdStrikeApiUsername)'" -ForegroundColor DarkGreen
                $clixml = get-item "$($env:USERPROFILE)\..\$($ST.Principal.UserId)\Credentials\$($CrowdStrikeApiUsername)*.clixml"
                if ( $clixml ) {
                    write-host "  User $($ST.Principal.UserId) has a credential file for CrowdStrike API account '$($CrowdStrikeApiUsername)'" -ForegroundColor DarkGreen
                    } `
                else {
                    write-host "  User $($ST.Principal.UserId) does not have a credential file for CrowdStrike API. This will prevent the scheduled task working as expected" -ForegroundColor DarkRed
                    } # end if 
                } `
            else {
                write-host "  Scheduled does not appear to be configured to use a CrowdStrike API. Check the action to ensure the '-CrowdStrikeApiUsername' parameter is being used." -ForegroundColor DarkRed
                } # end if 
            } `
        catch {
            write-host "  $($_.Exception.Message)" -ForegroundColor Red
            write-host "  User $($ST.Principal.UserId) not have a credential file for CrowdStrike API" -ForegroundColor yellow
            } # end try catch

        write-host "  Issuing static query via Get-HostFromCrowdStrikeScheduledTask"
        $Data = $env:computername | Get-HostFromCrowdStrikeScheduledTask | get-item | get-content | ConvertFrom-Json
        if ( $Data ) { 
            ($Data |select hostname, local_ip | ft | Out-String) -ireplace "^\s*|\s*$","" -split "`n" | %{ write-host "    $_" -ForegroundColor DarkGreen }
            write-host "  Get-HostFromCrowdStrikeScheduledTask appears to be working" -ForegroundColor DarkGreen
            } `
        else {
            write-host "  Get-HostFromCrowdStrikeScheduledTask failed" -ForegroundColor Red
            Write-host "  Check the scheduled task transcript log"
            get-item "$($RunInFolder)\ScheduledTaskQueryCrowdStrike.transcript.log" | get-content | %{ write-host "    $_" }
            write-host "`n   If the transcript log shows authentication errors with crowdstrike. See also: https://git.nmlv.nml.com/dw-endpoint/dw-endpoint-branches/open-pssession#install"
            } # end if
        } `
    else {
        write-host "  Scheduled task not found, confirm you've created the scheduled task" -ForegroundColor Red
        } # end if 

    if ( $CrowdStrikeApiUsername ) {
        try {
            write-host "Checking non-scheduled task"
            write-host "  Issuing static query via Get-HostFromCrowdStrike"
            [PSCredential]$Credential = [CustomCredential]::New($CrowdStrikeApiUsername, "NoValidation", "Please provide CrowdStrike API credential stored in CyberArk").PsCredential($false)

            $Data = $env:computername | Get-HostFromCrowdStrike -Credential $Credential
            if ( $Data ) {
                ($Data |select hostname, local_ip | ft | Out-String) -ireplace "^\s*|\s*$","" -split "`n" | %{ write-host "    $_" -ForegroundColor DarkGreen }
                write-host "  Get-HostFromCrowdStrike appears to be working" -ForegroundColor DarkGreen
                } `
            else {
                write-host "  No data returned. Could be that $($Env:Computername) is not in the CrowdStrike database" -ForegroundColor DarkYellow
                } # end if
            } `
        catch {
            write-host "  Failed to issue a static query into Get-HostFromCrowdStrike. This is likely because your local account does not have the CrowdStrike API user credential, or the credential is wrong" -ForegroundColor DarkYellow
            } # end try/catch
        } # end if

    } # end function Test-CrowdStrikeQuery


<#
[PSCredential]$ScheduledTaskCredential = [Class_CustomCredential]::New("nm\mecmstp").PsCredential()
[PSCredential]$CrowdStrikeApiCredential = [CustomCredential]::New("d16b3b6cf3494b449b8135a92329df14", "NoValidation").PsCredential

using module Class_CustomCredential
$Options = @{
    ScheduledTaskCredential = [CustomCredential]::New("nm\mecmstp").PsCredential()
    CrowdStrikeApiCredential = [CustomCredential]::New("d16b3b6cf3494b449b8135a92329df14", "NoValidation").PsCredential()
    }

$Options = @{
    ScheduledTaskCredential = Import-Clixml -Path "$($Env:UserProfile)\Credentials\nm_mecmstp_WSP-STNA-002611.clixml"
    CrowdStrikeApiCredential = Import-Clixml -Path "$($Env:UserProfile)\Credentials\d16b3b6cf3494b449b8135a92329df14_WSP-STNA-002611.clixml"
    }

Install-CrowdStrikeScheduledTask @Options
#>

function Install-CrowdStrikeScheduledTask {
    # install the scheduled task on the local server, requires a credential for the user account which will run the scheduled task
    # I'd use the custom_credential here but we don't want to store the credentials under the current user running this
    #
    # Examples:
    #   $Cred = Get-Credential -Message "Enter the username (in the format like: nm\mecmstp) and password for the account which will run the Scheduled Task."
    #   Install-CrowdStrikeScheduledTask -ScheduledTaskCredential $Cred -CrowdStrikeApiUsername a590415bf7b66bfe31f4405dc060e9d4
    #   $env:computername | Get-HostFromCrowdStrikeScheduledTask -ReturnNameResolution
    Param (
        $LocalXmlFile = $($env:PSModulePath -split ";" | get-childitem -recurse | ?{ $_.name -eq "Query-CrowdStrike.xml" } | select-object -first 1)

        , # Do not make this manditory, if made manditory then the get-credential command will not be executed, and its embeded message will not be displayed
        [PSCredential]$ScheduledTaskCredential = $(Get-Credential -Message "Enter the username (in the format like: nm\mecmstp) and password for the account which will run the Scheduled Task.")

        , # Do not make this manditory, if made manditory then the get-credential command will not be executed, and its embeded message will not be displayed
        [PSCredential]$CrowdStrikeApiCredential = $(Get-Credential -Message "Enter the username (in the format like: a590415bf7b66bfe31f4405dc060e9d4) and password for the account for the CrowdStrike API.")
        ) # end param


    # confirm we have credentials
    if ( -not $ScheduledTaskCredential ) { 
        throw "    no Scheduled Task Credential provided. exiting"
        } # end if 
    if ( -not $CrowdStrikeApiCredential ) { 
        throw "    no CrowdStrike Api Credential provided. exiting"
        } # end if 

    # verify the xml file ends with .xml
    if ( $LocalXmlFile -inotmatch "\.xml$" ) {
        throw "    XML '$LocalXmlFile' does not end in '.XML'"
        }
    # ensure source path is accessable
    elseif ( -not (test-path $LocalXmlFile) ) {
        Write-host "    Path '$LocalXmlFile' is not accessable, or does not exist, comfirm you copied it to the remote server already." -ForegroundColor Red
        }
    # import and start the scheduled task 
    elseif ( -not ([xml]$XML = get-content $LocalXmlFile -Raw) ) {
        Write-host "    File '$LocalXmlFile' appears to be empty." -ForegroundColor Red
        }
    else {

        # configure rights to allow user to run as schedule task
        $Members = ([ADSI]"WinNT://./Administrators").psbase.Invoke('Members') | % { ([ADSI]$_).InvokeGet('AdsPath')}
        if ( -not ( $Members | ?{ $_ -imatch $ScheduledTaskCredential.Username.Replace("\","/") } ) ) {
        # if ( -not (Get-LocalGroupMember -Group Administrators -Member $ScheduledTaskCredential.Username) ) {  # I want to use this command but it's bugged on some versions of powershell, so instead we'll do a try/catch
            try {
                Add-LocalGroupMember -group Administrators -Member $ScheduledTaskCredential.Username
                }
            catch {
            write-host "    Warning 0113: 'Add-LocalGroupMmeber' failed" -ForegroundColor DarkYellow
                net localgroup Administrators /add $ScheduledTaskCredential.Username
                } # end try/catch
            } # end if 
        # . $Destination; Grant-LogonAsService -User $Options.User -Permission SeBatchLogonRight

        # replace the arguments if they need correcting
        # $Destination = @{"NMDEV"="\\ntapdh7589m00\Work\Miller\Powershell\Count-SecurityProtocolsInUse.ps1"; NMTEST="\\ntdbth7965m00\Work\Miller\Powershell\Count-SecurityProtocolsInUse.ps1"; NM="\\nm\dfs03\NSD\Miller\Powershell\Count-SecurityProtocolsInUse.ps1"}[$env:UserDomain]
        # $XML.Task.Actions.Exec.Arguments = $XML.Task.Actions.Exec.Arguments -ireplace '(?<=-file ")[^"]*(?=")', $Destination
        $XML.Task.Actions.Exec.Arguments = $XML.Task.Actions.Exec.Arguments -ireplace '(?<=-CrowdStrikeApiUsername "?)[^ "]*(?="| )', $CrowdStrikeApiCredential.Username

        # show action
        write-host "    " -NoNewLine; Write-host " Action: '" -BackgroundColor White -ForegroundColor Black -NoNewLine; Write-host "Powershell $($XML.Task.Actions.Exec.Arguments)" -NoNewLine; Write-Host "'" -BackgroundColor White -ForegroundColor Black

        # configure options
        $Options = @{
            Xml         = $XML.OuterXml
            TaskName    = $($LocalXmlFile | split-path -Leaf ) -ireplace "\.xml\s*$"
            User        = $ScheduledTaskCredential.Username 
            Password    = $ScheduledTaskCredential.GetNetworkCredential().password
            }
        # delete any preexisting scheduled task of the same name
        if ( $ScheduledTask = Get-scheduledtask -TaskName $Options.TaskName -ErrorAction SilentlyContinue ) {
            $ScheduledTask | Stop-ScheduledTask
            $ScheduledTask | Unregister-ScheduledTask -Confirm:$False -ErrorAction SilentlyContinue
            } # end if 


        # install scheduled task
        $RegisteredTask = Register-ScheduledTask @Options
        if ( $ScheduledTask = Get-scheduledtask -TaskName $Options.TaskName ) {
            write-host "    Task matching '$($Options.TaskName)' exists with state '$($ScheduledTask.State)'" -ForegroundColor DarkGreen

            # define the user profile folder
            $UserPath = "$($env:USERPROFILE)\..\$($ScheduledTaskCredential.Username -ireplace '^[^\\]*\\','')\Credentials"

            # create the hot folder if it doesn't yet exist
            "D:\AdhocScripts\QueryCrowdStrike\HotFolder" | ?{ -not (test-path $_) } | %{ $null = New-Item $_ -Type Directory }

            # If the user account profile doesn't exist yet, then launch the scheduled task, this will instantiate the user account profile
            if ( -not (Test-Path $UserPath) ) {
                Get-ScheduledTask -TaskName Query-CrowdStrike | Start-ScheduledTask
                write-host "    User profile for '$($ScheduledTaskCredential.Username -ireplace '^[^\\]*\\','')' exist yet so we'll run the scheduled task to create it."
                write-host "    Waiting for scheduled task to complete running " -NoNewLine
                sleep -seconds 1
                while ( (Get-ScheduledTask -TaskName Query-CrowdStrike).Status -ieq "running" ) {
                    write-host "." -NoNewLine
                    Sleep -seconds 1
                    } # end while
                write-host ""
                } # end if 

            # Create the credential folder if it doesn't yet exist
            $UserPath | ?{ -not (test-path $_) } | %{ $null = New-Item $_ -Type Directory }

            # create the CrowdStrike API credential json file in the Schedule Task user credential repository. This will be automatically deleted on first run
            $JsonFile = "$($UserPath)\$($CrowdStrikeApiCredential.Username)_$($Env:computername).JSON"
            @{Username=$CrowdStrikeApiCredential.Username; Password=$CrowdStrikeApiCredential.GetNetworkCredential().password} | ConvertTo-Json | Out-File $JsonFile -Force

            # launch the scheduled task, this will instantiate the permanent CrowdStrike credential and delete the json file
            Get-ScheduledTask -TaskName Query-CrowdStrike | Start-ScheduledTask
            sleep -seconds 1
            while ( (Get-ScheduledTask -TaskName Query-CrowdStrike).Status -ieq "running" ) {
                write-host "." -NoNewLine
                Sleep -seconds 1
                } # end while
            write-host ""

            # confirm the JSON file was deleted
            if ( Test-Path $JsonFile ) {
                Get-Item $JsonFile | Remove-Item -force
                write-host "    JSON file deleted manually" -ForegroundColor DarkYellow
                } # end if 

            # test CrowdStrike to ensure it's working as expected
            Test-CrowdStrikeQuery
            }
        else {
            $RegisteredTask
            write-host "    Task matching '$($Options.TaskName)' does not exist" -ForegroundColor Red
            } # end if

        } # end if 
    } # end function Install-CrowdStrikeScheduledTask

