function Get-CcmVersion {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $Session | Get-CcmVersion
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        ) # end if 
    begin {
        } # end begin
    Process {
        foreach ( $Session in $Sessions ) {
            Invoke-command -Session $Session -scriptblock {Get-wmiobject -namespace root\ccm -class CCM_InstalledComponent | Select Name, Version} 
            } # next Session 
        } # end process
    } # end function Get-CcmVersion



function Get-PendingRebootStatus {
    # depreciated, use Test-PsSession instead
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $PendingReboot = $Session | Get-PendingRebootStatus
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        ) # end if 
    begin {
        $Script = {
            function CheckPendingReboot {
                # $PendingReboot = CheckPendingReboot
                param ( $Target = $Env:ComputerName ) 
                write-host "  In Session"
                Try {
                    $PendingReboot = $false
    
                    $HKLM = [UInt32] "0x80000002"
                    $WMI_Reg = [WMIClass] "\\$Target\root\default:StdRegProv"
    
                    if ($WMI_Reg) {
                        if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') {$PendingReboot = $true}
                        if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true}
    
                        #Checking for SCCM namespace
                        $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Target -ErrorAction Ignore
                        if ($SCCM_Namespace) {
                            if (([WmiClass]"\\$Target\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq $true) {$PendingReboot = $true}
                            } # end if
    
                        [PSCustomObject]@{
                            PendingReboot = $PendingReboot
                            } # end object
                        } # end if
                    } 
                catch {
                    Write-Error $_.Exception.Message
                    } 
                finally {
                    #Clearing Variables
                    $null = $WMI_Reg
                    $null = $SCCM_Namespace
                    } # end try/catch
                } # end function CheckPendingReboot
            } # end scriptblock
        } # end begin
    Process {
        foreach ( $Session in $Sessions ) {
            Invoke-command -Session $Session -scriptblock $Script
            } # next Session 
        } # end process
    } # end function Get-PendingRebootStatus



function Set-CcmVerbosity {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Set-CcmVerbosity -Enable
    # $session | Set-CcmVerbosity -Disable
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [switch]$Enable
        , [switch]$Disable      # included option for clarity
        ) # end if 
    begin {
        if ( $Enable ) {
            $Script = { 
                write-host "  In Session"
                Get-Service CcmExec
                Write-host "    Setting logs to verbose"
                Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -Name 'LogLevel' -Value '0'
                Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -Name 'LogMaxSize' -Value '5242880'
                Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -Name 'LogMaxHistory' -Value '5'
                New-Item -path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging' -Name 'DebugLogging'
                New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\DebugLogging' -Name "Enabled" -Value 'True' -PropertyType 'String'
                write-host "    Restarting CcmExec service"
                Get-Service CcmExec | Stop-Service
                Get-Service CcmExec | Start-Service
                Get-Service CcmExec
                } # end script
            }
        else {
            $Script = { 
                write-host "  In Session"
                Get-Service CcmExec
                Write-host "    Setting logs to normal"
                Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -Name 'LogLevel' -Value '1'
                Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -Name 'LogMaxSize' -Value '250000'
                Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -Name 'LogMaxHistory' -Value '1'
                Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\DebugLogging' -Name 'Enabled'
                write-host "    Restarting CcmExec service"
                Get-Service CcmExec | Stop-Service
                Get-Service CcmExec | Start-Service
                Get-Service CcmExec
                } # end script
            } # end if
        } # end begin
    Process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script
            } # next Session 
        } # end process
    } # end function Set-CcmVerbosity


function Start-CcmAction {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Start-CcmAction -HardwareInventory
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [switch]$GpUpdate
        , [alias("AD")][switch]$ApplicationDeployment
        , [alias("DDC")][switch]$DiscoveryDataCollection
        , [alias("FC")][switch]$FileCollection
        , [alias("HI")][switch]$HardwareInventory
        , [alias("SI")][switch]$SoftwareInventory
        , [alias("SU")][switch]$SoftwareUpdates
        , [alias("SUS")][switch]$SoftwareUpdateScan
        , [alias("SUDE")][switch]$SoftwareUpdatesDeploymentEvaluation
        , [alias("MPR")][switch]$MachinePolicyRetrieval
        , [alias("MPE")][switch]$MachinePolicyEvaluation
        , [alias("UPR")][switch]$UserPolicyRetrieval
        , [alias("UPE")][switch]$UserPolicyEvaluation

        , [switch]$SoftwareCenter 
        ) # end if 
    begin {
        $ScriptWithBits = {
            Param ( $Instruction )
            # write-host "  In Session $(get-date) localtime"
            $BITS = get-service -Name BITS
            if ( $Bits.Status -ieq "Running" ) {
                write-host "    Bits service $($Bits.StartType) $($Bits.Status)" -ForegroundColor Darkgreen
                } `
            elseif ( $Bits.StartType -ieq "Manual" -and $Bits.Status -ieq "Stopped") {
                write-host "    Bits service $($Bits.StartType) $($Bits.Status)" -ForegroundColor DarkGreen
                } `
            else {
                write-host "     its service $($Bits.StartType) $($Bits.Status)" -ForegroundColor Darkred
                } # end if
            $Last = Get-wmiobject -namespace root\ccm\invagt -class inventoryactionstatus | where-Object {$_.inventoryactionid -eq $Instruction.guid }
            write-host "    $($Instruction.Name)"
            Write-host "      LastCycleStartedDate = $($Last.LastCycleStartedDate)" -ForegroundColor DarkGray
            Write-host "      LastCycleStartedDate = $($Last.LastCycleStartedDate)" -ForegroundColor DarkGray
            Write-host "      LastReportDate = $($Last.LastReportDate)" -ForegroundColor DarkGray
            $Triggered = Invoke-WmiMethod -namespace root\ccm -class SMS_Client -Name TriggerSchedule $Instruction.Guid
            } # end script

        $ScriptWithoutBits = {
            Param ( $Instruction )
            #write-host "  In Session"
            $Triggered = Invoke-WmiMethod -namespace root\ccm -class SMS_Client -Name TriggerSchedule $Instruction.guid
            } # end script

        $ScriptGpUpdate = {
            # write-host "  In Session"
            write-host "    Starting $($Instruction.Name)"
            gpupdate /force
            } # end script

        # full list https://www.manishbangia.com/initiate-sccm-client-actions-cmd-line/
        if ( $SoftwareCenter ) {
            $ApplicationDeployment = $True
            $MachinePolicyRetrieval = $True
            $SoftwareInventory = $True
            } # end if 

        [array]$Instructions = if ( $True ) {
            # list the operations in the order they should be run
            if ( $ApplicationDeployment )               { @{Name="ApplicationDeployment"               ; guid="{00000000-0000-0000-0000-000000000121}"; Logs=@("Appdiscovery.log", "AppIntentEval.log"); ScriptBlock=$ScriptWithoutBits} }
            if ( $DiscoveryDataCollection )             { @{Name="DiscoveryDataCollection"             ; guid="{00000000-0000-0000-0000-000000000003}"; Logs=@("InventoryAgent.log"); ScriptBlock=$ScriptWithoutBits} }
            if ( $FileCollection )                      { @{Name="FileCollection"                      ; guid="{00000000-0000-0000-0000-000000000010}"; Logs=@(); ScriptBlock=$ScriptWithoutBits} }
            if ( $SoftwareUpdates )                     { @{Name="SoftwareUpdates"                     ; guid="{00000000-0000-0000-0000-000000000108}"; Logs=@(); ScriptBlock=$ScriptWithoutBits} }
            if ( $SoftwareUpdateScan )                  { @{Name="SoftwareUpdateScan"                  ; guid="{00000000-0000-0000-0000-000000000113}"; Logs=@("ScanAgent.log"); ScriptBlock=$ScriptWithoutBits} }
            if ( $SoftwareUpdatesDeploymentEvaluation ) { @{Name="SoftwareUpdatesDeploymentEvaluation" ; guid="{00000000-0000-0000-0000-000000000114}"; Logs=@("ScanAgent.log", "UpdateDeployment.log"); ScriptBlock=$ScriptWithoutBits} }
            if ( $MachinePolicyRetrieval )              { @{Name="MachinePolicyRetrieval"              ; guid="{00000000-0000-0000-0000-000000000021}"; Logs=@("PolicyAgent.log"); ScriptBlock=$ScriptWithoutBits} }
            if ( $MachinePolicyEvaluation )             { @{Name="MachinePolicyEvaluation"             ; guid="{00000000-0000-0000-0000-000000000022}"; Logs=@("PolicyAgent.log"); ScriptBlock=$ScriptWithoutBits} }
            if ( $UserPolicyRetrieval )                 { @{Name="UserPolicyRetrieval"                 ; guid="{00000000-0000-0000-0000-000000000026}"; Logs=@(); ScriptBlock=$ScriptWithoutBits} }
            if ( $UserPolicyEvaluation )                { @{Name="UserPolicyEvaluationCycle"           ; guid="{00000000-0000-0000-0000-000000000027}"; Logs=@(); ScriptBlock=$ScriptWithoutBits} }

            if ( $GpUpdate )                            { @{Name="GpUpdate"                             ; guid=""; Logs=@(); ScriptBlock=$ScriptGpUpdate} }

            # these operations will run for a bit and will block other operations so include them last }
            if ( $HardwareInventory )                   { @{Name="HardwareInventory"                   ; guid="{00000000-0000-0000-0000-000000000001}"; Logs=@("Inventoryagent.log"); ScriptBlock=$ScriptWithBits} }
            if ( $SoftwareInventory )                   { @{Name="SoftwareInventory"                   ; guid="{00000000-0000-0000-0000-000000000002}"; Logs=@("Inventoryagent.log"); ScriptBlock=$ScriptWithBits} }
            } 

        $StartDate = get-date
        $Logs = New-Object System.Collections.Generic.List[System.Object]

        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Write-Host "  To Session"
            foreach ( $Instruction in $Instructions ) {
                Invoke-Command -Session $Session -ScriptBlock $Instruction.ScriptBlock -ArgumentList $Instruction
                $Instruction.Logs | %{ [void]$Logs.Add( $_ ) }
                } # end next instruction
            } # next session
        } # end process
    end {
        if ( $Logs ) {
            $Temp = ($Logs | Select-Object -Unique | %{"c:\windows\Ccm\Logs\$_"}) -join '", "'
            $Command = "`$Entries = `$Sessions | Read-CmLogs -Logs ""$Temp""  -Tail 400 -Where {`$_.Date -ge (Get-Date '$(Get-Date)')}; `$Entries | Out-Gridview -Title 'Read-CmLogs'"
            
            write-host "  To query results issue the following command" -ForegroundColor Darkgray
            write-host "  $Command" -ForegroundColor Cyan

            # inject the command into up/down arrow history for easy access,
            # unfortunatly this command gets injected into history but the up/down arrow history in the current window is not updated
            # to view the command using arrows you have to open a new window... which then won't have the session object, 
            # Add-Content -Path (Get-PSReadlineOption).HistorySavePath $Command

            } `
        else {
            write-host "   No actions with known logs issued" -ForegroundColor DarkGray
            } # end if
        } # end end
    } # end function Start-CcmAction


function Set-CcmGenerateNewGUID {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Stop-ServiceInSession -Service CcmExec | ft
    # $session | Set-CcmGenerateNewGUID
    # manually delete device from SCCM
    # $session | Start-ServiceInSession -Service CcmExec | ft
    # $session | Start-CcmAction -MachinePolicyRetrieval -MachinePolicyEvaluation
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        ) # end if 
    begin {
        $Script = {
            write-host "  In Session"
            write-host "    Rename-Item -path ""c:\windows\SMSCFG.ini"" -NewName ""c:\windows\SMSCFG.old.ini"" -force"
            Rename-Item -path "c:\windows\SMSCFG.ini" -NewName "c:\windows\SMSCFG.old.ini" -force
            
            # update computer's AD certificate
            $Certs = Get-Certificate -CertStoreLocation Cert:\LocalMachine\My -Template Machine
            $ThumbPrint = $Certs.Certificate.Thumbprint
            write-host "    Certreq.exe -enroll -q -machine -cert ""*$thumbprint*"" Renew"
            Certreq.exe -enroll -q -machine -cert "*$thumbprint*" Renew
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script
            } # next session
        } # end process
    } # end function Set-CcmGenerateNewGUID


function Clear-CcmCache {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Clear-CcmCache
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        ) # end if 
    begin {
        $Script = {
            write-host "  In Session"
            $UIResourceManger = New-Object -ComObject UIResource.UIResourceMgr
            $Cache = $UIResourceManger.GetCacheInfo()
            $CacheElements = $Cache.GetCacheElements()
            Foreach ( $Element in $Cache.GetCacheElements() )  {
                Write-host "    Deleting '$($Element.ContentID)' in '$($Element.Location)'"
                $Cache.DeleteCacheElement( $Element.CacheElementID )
                } # next element
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script
            } # next session
        } # end process
    } # end function Clear-CcmCache


function Get-MeteredEthernetConnection {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Get-MeteredEthernetConnection | ft
    # $session | Get-MeteredEthernetConnection -WhereNetwork {$_.Name -imatch "Ethernet|Wi-fi|blue"} | ft
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , $WhereNetwork = ""     # = {$_.Name -imatch "Ethernet|Wi-fi"}
        ) # end if 
    begin {
        $Script = {
            Param ( 
                $WhereNetwork
                ) # end param
            write-host "  In Session"
            If ( -NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") ) {
                Throw "    Error 1917: You need to have admin rights to run this command."
                } # end if 
    		Write-Host "    Values observed in 'HKLM:\SOFTWARE\Microsoft\DusmSvc\Profiles\'"
            $NetworkCards = if ( $WhereNetwork ) { 
                write-host "    Applying Filter {$($WhereNetwork)}"
                Get-NetAdapter | Where-Object -FilterScript ([ScriptBlock]::Create($WhereNetwork))
                }
            Else {
                write-host "    No filter applied" -ForegroundColor DarkGray
                Get-NetAdapter
                } # end if
            Foreach ($NetworkCard in $NetworkCards) {
                $UserCost = get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DusmSvc\Profiles\$($NetworkCard.InterfaceGuid)\*" -Name UserCost -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserCost
                [pscustomobject][ordered]@{
                    Name = $NetworkCard.Name
                    InterfaceGuid = $NetworkCard.InterfaceGuid
                    UserCost = "$($UserCost)=$(@{''='Not Set'; '0'='Not Metered'; '2'='Metered'}["$([string]$UserCost)"])"
                    InterfaceDescription = $NetworkCard.InterfaceDescription
                    } # end hash
                } # next NetworkCard
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script -ArgumentList $WhereNetwork.ToString()
            } # next session
        } # end process
    } # end function Get-MeteredEthernetConnection
function Set-MeteredEthernetConnection {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Set-MeteredEthernetConnection -NotMetered
    # $session | Set-MeteredEthernetConnection -NotMetered -WhereNetwork {$_.Name -imatch "Ethernet|Wi-fi"}
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , $WhereNetwork = ""         # = {$_.Name -imatch "Ethernet|Wi-fi"}
   		, [Switch]$Metered
		, [Switch]$NotMetered
        , [switch]$DoNotRestartCcmExec

        ) # end if 
    begin {
        # Set metered Ethertnet connection value
        # This setting is stored in registry 
        #   Windows 10 early than v1909 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost
        #   Windows 10 after v1909 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DusmSvc\Profiles\* -Name UserCost 0=NotMetered, 2=Metered
 		if ( $Metered -and $NotMetered ) { throw "Error 1961: You selected both metered and notmetered, you should only select one option" }
		$DesiredSetting = 0
		if ( $Metered ) 	{ $DesiredSetting = 2 }
		if ( $NotMetered ) 	{ $DesiredSetting = 0 }
        
       $Script = {
            Param ( 
                $WhereNetwork
                , $DesiredSetting 
                ) # end param
            write-host "  In Session"
            If ( -NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") ) {
                Throw "    Error 0527: You need to have admin rights to run this command. No changes made."
                } # end if 
    		[int]$CountChanges = 0
            $NetworkCards = if ( $WhereNetwork ) { 
                write-host "    Applying Filter {$($WhereNetwork)}"
                Get-NetAdapter | Where-Object -FilterScript ([ScriptBlock]::Create($WhereNetwork))
                }
            Else {
                write-host "    No filter appled"
                Get-NetAdapter
                } # end if

            Foreach ($NetworkCard in $NetworkCards) {
                $registryPath = "HKLM:\SOFTWARE\Microsoft\DusmSvc\Profiles\$($NetworkCard.InterfaceGuid)\*"

                write-host "    $($NetworkCard.InterfaceGuid), $($NetworkCard.Name), $($NetworkCard.InterfaceDescription)"
                # write-host "      '$registryPath'" -ForegroundColor DarkGray

                $UserCostBefore = get-ItemProperty -Path $registryPath -Name UserCost -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserCost

                if ( [string]$DesiredSetting -eq [string]$UserCostBefore ) {
                    Write-host "      Was Already '$($registryPath)' = '$($UserCostBefore)'" -ForegroundColor DarkGreen
                    } 
                else {
                    if ( -not (test-path $RegistryPath) ) { New-Item -Path $RegistryPath -Force | Out-Null }

                    New-ItemProperty -Path $registryPath -Name UserCost -Value $DesiredSetting -PropertyType DWORD -Force | Out-Null
                    $UserCostAfter = get-ItemProperty -Path $registryPath -Name UserCost | Select-Object -ExpandProperty UserCost

                    $Options = if ( $UserCostAfter -eq $DesiredSetting ) { 
                        @{ForegroundColor="DarkGreen"} 
                        $CountChanges += 1
                        } 
                    else { @{ForegroundColor="Red"} }
                    Write-host "      Was         '$($registryPath)' = '$($UserCostBefore)'" @Options
                    Write-host "      IsNow       '$($registryPath)' = '$($UserCostAfter)'" @Options
                    } # end if
                } # next NetworkCard
            # Restart "date usage" DusmSvc for the settings to take effect, but only if there were successful changes
            if ( $CountChanges -gt 0 ) {
                Write-host "    restarting Service DusmSvc"
                Restart-Service -Name DusmSvc  -Force
                if ( $DoNotRestartCcmExec ) {
                    write-host "    Not restarting service CcmExec"
                    }
                else {
                    Write-host "    restarting Service CcmExec"
                    Restart-Service -Name CcmExec  -Force
                    } # end if
                } # end if

            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script -ArgumentList $WhereNetwork.ToString(), $DesiredSetting
            } # next session
        } # end process
    } # end function Set-MeteredEtherNetConnection



function Get-CcmNetworkCost {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $CcmNetworkCost = $session | Get-CcmNetworkCost
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        ) # end if 
    begin {
        $Script = {
            write-host "  In Session"
            $CcmNetworkCost = (Invoke-CimMethod -ClassName "CCM_ClientUtilities" -Namespace "root\ccm\ClientSDK"  -MethodName GetNetworkCost).Value
            Write-Host "    CCM_ClientUtilities::root\ccm\ClientSDK.GetNetworkCost is set to '$CcmNetworkCost' = '$(@{'1'='not metered';'2'='metered'}[[string]$CcmNetworkCost])'"
            Write-Output $CcmNetworkCost
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script
            } # next session
        } # end process
    } # end function Get-CcmNetworkCost
function Get-CcmActualConfigMeteredNetworkUsage {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $CcmActualConfigMeteredNetworkUsage = $session | Get-CcmActualConfigMeteredNetworkUsage
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        ) # end if 
    begin {
        $Script = {
            write-host "  In Session"
            $obj = Get-CIMInstance -Namespace "root\ccm\Policy\Machine\ActualConfig" -ClassName CCM_NetworkSettings
            Write-Host "      CCM_ClientUtilities::root\ccm\Policy\Machine\ActualConfig.CCM_NetworkSettings.MeteredNetworkUsage is set to '$($obj.MeteredNetworkUsage)' = '$(@{'0'='unknown';'1'='not metered';'2'='metered'; '4'='Unknown'}[[string]$obj.MeteredNetworkUsage])'"
            write-output $obj
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script
            } # next session
        } # end process
    } # end function Get-CcmActualConfigMeteredNetworkUsage
function Set-CcmNetworkCost {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Set-CcmNetworkCost -Metered
    # $session | Set-CcmNetworkCost -NotMetered
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [switch]$Metered
		, [switch]$NotMetered
        , [switch]$DoNotRestartCcmExec
        ) # end if 
    begin {
        [int]$DesiredNetworkCostSetting = 0
        if ( $Metered ) { $DesiredNetworkCostSetting = 2 }
        if ( $NotMetered ) { $DesiredNetworkCostSetting = 1 }
        If ( $DesiredNetworkCostSetting -eq 0 ) {
            throw "  Error 0535: Show setting neither -Metered or -NotMetered were selected"
            } # end if
        $Script = {
            Param ( 
                $DesiredNetworkCostSetting
                , $MyTimeZone 
                , $DoNotRestartCcmExec
                ) # end param
            function Get-CcmNetworkCost {
                $CcmNetworkCost = (Invoke-CimMethod -Namespace "root\ccm\ClientSDK" -ClassName "CCM_ClientUtilities" -MethodName GetNetworkCost).Value
                Write-Host "      CCM_ClientUtilities::root\ccm\ClientSDK.GetNetworkCost is set to '$CcmNetworkCost' = '$(@{'1'='not metered';'2'='metered'}[[string]$CcmNetworkCost])'"
                Write-Output $CcmNetworkCost
                } # end function Get-CcmNetworkCost
            function Get-ActualConfig { 
                $obj = Get-CIMInstance -Namespace "root\ccm\Policy\Machine\ActualConfig" -ClassName CCM_NetworkSettings
                Write-Host "      CCM_ClientUtilities::root\ccm\Policy\Machine\ActualConfig.CCM_NetworkSettings.MeteredNetworkUsage is set to '$($obj.MeteredNetworkUsage)' = '$(@{'1'='not metered';'2'='metered';'4'='unknown'}[[string]$obj.MeteredNetworkUsage])'"
                write-output $obj
                } # end function Get-ActualConfig

            write-host "  In Session"
    		write-host "    Desired Setting = '$($DesiredNetworkCostSetting)' = '$(@{'1'='not metered';'2'='metered'}[[string]$DesiredNetworkCostSetting])'"
            Write-host "    Show setting before changing CcmExec"
            $CcmNetworkCost = Get-CcmNetworkCost
      		$obj = Get-ActualConfig

            If ( $obj.MeteredNetworkUsage -eq $DesiredNetworkCostSetting ) {
                Write-Host "    CCM_ClientUtilities::root\ccm\Policy\Machine\ActualConfig.CCM_NetworkSettings.MeteredNetworkUsage is already set to '$($obj.MeteredNetworkUsage)', no change made" -ForegroundColor Green
                }
            else {
                Write-Host "    Reseting ConfigMgr CCM_NetworkSettings Policy"
                $obj | Set-CimInstance -Property @{ MeteredNetworkUsage=$DesiredNetworkCostSetting }

                Write-host "    Show setting after change but before restarting CcmExec"
                $CcmNetworkCost = Get-CcmNetworkCost
          		$obj = Get-ActualConfig

                if ( $DoNotRestartCcmExec ) {
                    write-host "    Not restarting service CcmExec because -DoNotRestartCcmExec switch was present"
                    }
                else {
                    Write-host "    Restart-Service -Name ccmexec -ErrorAction SilentlyContinue"
                    Restart-Service -Name ccmexec -ErrorAction SilentlyContinue
                    } # end if

                # Give policies time to churn
                $Until = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((get-date).AddSeconds(30), [System.TimeZoneInfo]::Local.Id, $MyTimeZone) | get-date -Format HH:mm:ss
                write-host "    Sleeping for 30 seconds (until $($Until) $($MyTimeZone -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')) to give policies time to churn" -ForegroundColor DarkGray
                Start-Sleep -Seconds 30

                # Remove the policy entry from WMI
                write-host "    Remove policy entry from WMI"
                $obj | Remove-CimInstance
                Invoke-CimMethod -Namespace "root\ccm" -ClassName "SMS_Client" -MethodName RequestMachinePolicy -Arguments @{uFlags = [uint32]1 } | Out-Null
                Invoke-CimMethod -Namespace "root\ccm" -ClassName "SMS_Client" -MethodName EvaluateMachinePolicy | Out-Null

                Write-host "    Show setting After removing policy entry from WMI"
                $CcmNetworkCost = Get-CcmNetworkCost
          		$obj = Get-ActualConfig
                } # end if 

            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script -ArgumentList $DesiredNetworkCostSetting, ([System.TimeZoneInfo]::Local.Id), $DoNotRestartCcmExec
            } # next session
        } # end process
    } # end function Set-CcmNetworkCost




function Install-CcmAgent {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Install-CcmAgent
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )

        , [string]$SourceFiles = @{""="\\ntdbph8012m00\sms_nm1\Client\"; "NM"="\\ntdbph8012m00\sms_nm1\Client\"; NMTEST="\\ntdbth7965m00\sms_nmt\Client\"; NMDEV="\\ntapdh7589m00\sms_nmd\Client\"}[[string]$env:UserDomain]

        , $RemoteDestination = "C:\Windows\ccmsetup\"
        ) # end if 
    begin {
        $SourceFiles = $SourceFiles -Replace "[\\*]+$",""
        $ScriptMkDir = {
            Param (
                $FilePath
                ) # end param
            write-host "  Install-CcmAgent::Mkdir"
            Write-Host "    New-Item -Type Directory -Path ""$FilePath"" -Force"
            New-Item -Type Directory -Path "$FilePath" -Force | Out-Null
            if ( Test-Path $FilePath ) {
                write-host "     '$FilePath' Success" -ForegroundColor DarkGreen
                }
            else {
                write-host "     '$FilePath' does not exist" -ForegroundColor Yellow
                } # end if
            } # end script
        $ScriptInstall = {
            Param (
                $MyTimeZone
                , $FilePath
                , $ManagementPoint = @{""="wsp-stna-010657.nm.nmfco.com"; "NM"="wsp-stna-010657.nm.nmfco.com"; NMTEST="ntapth7641m00.nmtest.nmfco.com"; NMDEV="ntapdh7589m00.nmdev.nmfco.com"}[[string]$env:UserDomain]
                , $SiteCode = @{""="NM1"; "NM"="NM1"; NMTEST="NMT"; NMDEV="NMD"}[[string]$env:UserDomain]
                , $LogFilePath = "$($Env:SystemDrive)\Windows\ccmsetup\Logs\ccmsetup.log"
                ) # end param
            write-host "  Install-CcmAgent::Install $([System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $MyTimeZone)) $($MyTimeZone -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')"
            # Write-Host "    '$($FilePath)\Ccmsetup.exe' /mp:$ManagementPoint SMSSITECODE=$SiteCode /forceinstall"
            write-host "    Start-Process -FilePath ""$($FilePath)\Ccmsetup.exe"" -Wait -ArgumentList ""/mp:$ManagementPoint RESETKEYINFORMATION=TRUE SMSSITECODE=$SiteCode SMSSLP=$($ManagementPoint) FSP=$($ManagementPoint) /forceinstall"""
            $InstallProcess = Start-Process -FilePath "$($FilePath)\Ccmsetup.exe" -Wait -ArgumentList "/mp:$ManagementPoint RESETKEYINFORMATION=TRUE SMSSITECODE=$SiteCode SMSSLP=$($ManagementPoint) FSP=$($ManagementPoint) /forceinstall"
            # $InstallProcess = Start-Process -FilePath 'c:\windows\temp\ccmsetup.exe' -PassThru -Wait -ArgumentList "/mp:$($CMMP) /source:http://$($CMMP)/CCM_Client CCMHTTPPORT=80 RESETKEYINFORMATION=TRUE SMSSITECODE=$($CMSiteCode) SMSSLP=$($CMMP) FSP=$($CMMP)" 

            # give ccmsetup time to start its spawned process
            write-host "    Installing " -NoNewLine
            1..3 | %{ Write-host "." -NoNewLine; Start-Sleep 10 }
            while (($ReturnCode = Get-Content -Path $LogFilePath -Tail 1 | Select-String -Pattern "CcmSetup is exiting with return code|CcmSetup failed with error code") -eq $null -and (get-service -Name CcmSetup | ?{ $_.Status -ine "Stopped"}) )  { 
                # Check every 10 seconds for an exit code
                write-host "." -NoNewLine
                Start-Sleep 10 
                } # end while

            write-host
            # confirm service
            if ( $Service = Get-Service -Name CcmExec -ErrorAction SilentlyContinue ) { 
                write-host "    '$($Service.Name)' '$($Service.DisplayName)' exists and is '$($Service.Status)'" -ForegroundColor DarkGreen
                }
            else {
                write-host "    '$($Name)' service does not exist" -ForegroundColor Red
                } # end if 
            # confirm log
            if ( $ReturnCode -imatch "CcmSetup is exiting with return code (?<Code>[0-9x]+)" ) {
                $Code = $Matches.Code
                switch ( $Matches.Code ) {
                    0 { write-host "    Return Code: '$($Code)' Success" -ForegroundColor DarkGreen; break }
                    6 { write-host "    Return Code: '$($Code)' Error" -ForegroundColor Red; break }
                    7 { write-host "    Return Code: '$($Code)' Reboot Required" -ForegroundColor Yellow; break }
                    8 { write-host "    Return Code: '$($Code)' Setup already running"; break }
                    9 { write-host "    Return Code: '$($Code)' Prerequisite evaluation failure" -ForegroundColor Red; break }
                    10 { write-host "    Return Code: '$($Code)' Setup manifest hash validation failure" -ForegroundColor Red; break }
                    default { write-host "    Return Code: '$($Code)' unknown code" -ForegroundColor Red; break }
                    } # end switch
                } 
            else {
                write-host "    Last line from '$LogFilePath':$ReturnCode" -ForegroundColor Red
                } # end if 
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-Command -Session $Session $ScriptMkDir -ArgumentList $RemoteDestination

            write-host "  Copy-Item -ToSession `$Session -Path ""$SourceFiles\*"" -Destination ""$RemoteDestination"" -Recurse -Force"
            Copy-Item -ToSession $Session -Path "$SourceFiles\*" -Destination "$RemoteDestination" -Recurse -Force

            Invoke-command -Session $Session -scriptblock $ScriptInstall -ArgumentList ([System.TimeZoneInfo]::Local.Id), $RemoteDestination
            } # next session
        } # end process
    } # end function Install-CcmAgent
function Install-CcmAgentMultiSession {
    # Examples
    #   Create a sessions
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [string]$SourceFiles = @{""="\\ntdbph8012m00\sms_nm1\Client\"; "NM"="\\ntdbph8012m00\sms_nm1\Client\"; NMTEST="\\ntdbth7965m00\sms_nmt\Client\"; NMDEV="\\ntapdh7589m00\sms_nmd\Client\"}[[string]$env:UserDomain]
        , $RemoteDestination = "C:\Windows\ccmsetup\"
        , $Credential = [CustomCredential]::New("$($Env:UserDomain)\$($Env:Username -ireplace '-.*$',"-$($Env:UserDomain)")")

        , $ThrottleLimit = 25
        ) # end Param
    begin {
        # yes we could use the #Requires commmand but that would invalidate the entire script instead of just this one function
        if ( $PsVersiontable.PsVersion -le [system.version]"7.0" ) { throw "error 1565: Get-FilesFromMultiPsSession requires Powershell version 7. This is being run in powershell version '$($PsVersionTable.PsVersion)' on '$($Env:Computername)'" } # end if
        $AllTargets = New-Object System.Collections.Generic.List[System.Object]
        if ( $Credential -is [PsCredential] ) {
            $Credential = [CustomCredential]::New($Credential)
            } # end if

        $Script = {
            #Include Variable SourceFiles
            #Include Variable RemoteDestination
            # skip Include Function Install-CcmAgent
            # skip Include Function Pluralize

            Import-Module Open-PsSession -DisableNameChecking

            #Include Variable Credential
            $PsSessionOptions = @{
                cred = $Credential
                UseSSL = $True
                } # end hash

            $_ | New-PsSession @PsSessionOptions | Install-CcmAgent -SourceFiles $SourceFiles -RemoteDestination $RemoteDestination
            } # end script
        $Script = Optimize-PackScript -Script $Script -Variable @{SourceFiles=$SourceFiles; RemoteDestination=$RemoteDestination; Credential=$Credential}
        } # end begin
    Process {
        foreach ( $Entry in $Sessions | Format-ComputerName -Format "~~~ComputerName~~~.~~~Domain~~~" ) {
            [void]$AllTargets.Add( $Entry ) 
            } # next entry
        } # end process
    End {
        Write-Host "Processing $(Pluralize -Quantify $AllTargets -One '~~~Number~~~ session' -Many '~~~Number~~~ sessions')"
        #write-host "Processing $($AllTargets.count) sessions"
        $Jobs = $AllTargets | Foreach-Object -Parallel $Script -ThrottleLimit $ThrottleLimit -AsJob

        # the sessions created inside the foreach -Parallel command will be valid sessions but only from inside their respective multi-treaded session
        # we need to open those sessions here, which will require an additional step
        $Jobs | Wait-Job | Receive-Job
        } # end end
    } # end function Install-CcmAgentMultiSession


function Remove-CcmAgent {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Remove-CcmAgent
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [switch]$Extended
        ) # end if 
    begin {
        # https://www.optimizationcore.com/deployment/sccm-client-complete-remove-uninstall-powershell-script/ 
        $ScriptBasic = {
            param (
                $MyTimeZone
                , $LogFilePath = "$($Env:SystemDrive)\Windows\ccmsetup\Logs\ccmsetup.log"
                ) # end param

            function CheckService {
                # CheckService -Name CcmExec 
                param ( $Name )
                if ( $Service = Get-Service -Name $Name -ErrorAction SilentlyContinue ) { 
                    write-host "    '$($Service.Name)' '$($Service.DisplayName)' still exists and is '$($Service.Status)'" -ForegroundColor Red
                    }
                else {
                    write-host "    '$($Name)' service does not exist" -ForegroundColor Darkgreen
                    } # end if 
                } # end function

            write-host "  Remove-CcmAgent::Basic $([System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $MyTimeZone)) $($MyTimeZone -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')"
            
            if ( Test-Path "$($env:SystemDrive)\Windows\ccmsetup\ccmsetup.exe" ) { 
                write-host "    Start-Process -FilePath ""$($env:SystemDrive)\Windows\ccmsetup\ccmsetup.exe"" -ArgumentList ""/uninstall"""
                Start-Process -FilePath "$($env:SystemDrive)\Windows\ccmsetup\ccmsetup.exe" -ArgumentList "/uninstall"
                # give ccmsetup time to start its spawned process
                write-host "    Uninstalling " -NoNewLine
                1..3 | %{ Write-host "." -NoNewLine; Start-Sleep 10 }
                while (($ReturnCode = Get-Content -Path $LogFilePath -Tail 1 | Select-String -Pattern "CcmSetup is exiting with return code" -SimpleMatch) -eq $null)  { 
                    # Check every 10 seconds for an exit code
                    write-host "." -NoNewLine
                    Start-Sleep 10 
                    } # end while
                write-host
                if ( $ReturnCode -imatch "CcmSetup is exiting with return code (?<Code>[0-9x]+)" ) {
                    if ( $Matches.Code -eq 0 ) {
                        write-host "    Return Code: '$($Matches.Code)' Success" -ForegroundColor DarkGreen
                        } 
                    else {
                        write-host "    Return Code: '$($Matches.Code)'" -ForegroundColor Yellow
                        } # end if 
                    } 
                else {
                    write-host "    Last line from '$LogFilePath':$ReturnCode" -ForegroundColor Red
                    } # end if 

                CheckService -Name CcmExec 
                CheckService -Name CcmSetup 
                }
            else {
                write-host "    ""$($env:SystemDrive)\Windows\ccmsetup\ccmsetup.exe"" file not found."
                CheckService -Name CcmExec 
                } # end if 
            } # end script
        $ScriptExtended = {
            write-host "  Remove-CcmAgent::Extended $([System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $MyTimeZone)) $($MyTimeZone -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')"
            # Delete the folder of the SCCM Client installation: "C:\Windows\CCM"
            Remove-Item -Path "$($Env:WinDir)\CCM" -Force -Recurse -Confirm:$false -Verbose

            # Delete the folder of the SCCM Client Cache of all the packages and Applications that were downloaded and installed on the Computer: "C:\Windows\ccmcache"
            Remove-Item -Path "$($Env:WinDir)\CCMSetup" -Force -Recurse -Confirm:$false -Verbose

            # Delete the folder of the SCCM Client Setup files that were used to install the client: "C:\Windows\ccmsetup"
            Remove-Item -Path "$($Env:WinDir)\CCMCache" -Force -Recurse -Confirm:$false -Verbose

            # Delete the file with the certificate GUID and SMS GUID that current Client was registered with
            Remove-Item -Path "$($Env:WinDir)\smscfg.ini" -Force -Confirm:$false -Verbose

            # Delete the certificate itself
            Remove-Item -Path 'HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*' -Force -Confirm:$false -Verbose

            # Remove all the registry keys associated with the SCCM Client that might not be removed by ccmsetup.exe
            Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Force -Recurse -Verbose
            Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM' -Force -Recurse -Confirm:$false -Verbose
            Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\SMS' -Force -Recurse -Confirm:$false -Verbose
            Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS' -Force -Recurse -Confirm:$false -Verbose
            Remove-Item -Path 'HKLM:\Software\Microsoft\CCMSetup' -Force -Recurse -Confirm:$false -Verbose
            Remove-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\CCMSetup' -Force -Confirm:$false -Recurse -Verbose

            # Remove the service from "Services"
            Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CcmExec' -Force -Recurse -Confirm:$false -Verbose
            Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ccmsetup' -Force -Recurse -Confirm:$false -Verbose

            # Remove the Namespaces from the WMI repository
            Get-CimInstance -query "Select * From __Namespace Where Name='CCM'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false
            Get-CimInstance -query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false
            Get-CimInstance -query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false
            Get-CimInstance -query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" | Remove-CimInstance -Verbose -Confirm:$false

            # Alternative command for WMI Removal in case of something goes wrong with the above.
            # Get-WmiObject -query "Select * From __Namespace Where Name='CCM'" -Namespace "root" | Remove-WmiObject -Verbose | Out-Host
            # Get-WmiObject -query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" | Remove-WmiObject -Verbose | Out-Host
            # Get-WmiObject -query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" | Remove-WmiObject -Verbose | Out-Host
            # Get-WmiObject -query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" | Remove-WmiObject -Verbose | Out-Host
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $ScriptBasic -ArgumentList ([System.TimeZoneInfo]::Local.Id)
            if ( $Extended ) {
                Invoke-command -Session $Session -scriptblock $ScriptExtended
                } # end if
            } # next session
        } # end process
    } # end function Remove-CcmAgent
function Remove-CcmAgentMultiSession {
    # Examples
    #   Create a sessions
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [switch]$Extended

        , $Credential = [CustomCredential]::New("$($Env:UserDomain)\$($Env:Username -ireplace '-.*$',"-$($Env:UserDomain)")")
        , $ThrottleLimit = 25
        ) # end Param
    begin {
        # yes we could use the #Requires commmand but that would invalidate the entire script instead of just this one function
        if ( $PsVersiontable.PsVersion -le [system.version]"7.0" ) { throw "error 1565: Get-FilesFromMultiPsSession requires Powershell version 7. This is being run in powershell version '$($PsVersionTable.PsVersion)' on '$($Env:Computername)'" } # end if
        $AllTargets = New-Object System.Collections.Generic.List[System.Object]
        # repackage the provided credetial as CustomCredential object
        if ( $Credential -is [PsCredential] ) {
            $Credential = [CustomCredential]::New($Credential)
            } # end if
        $Script = {
            #Include Variable Extended
            #Include Variable Credential
            # skip Include Function Remove-CcmAgent
            # skip Include Function Pluralize

            Import-Module Open-PsSession -DisableNameChecking

            $PsSessionOptions = @{
                cred = $Credential
                UseSSL = $True
                } # end hash

            $_ | New-PsSession @PsSessionOptions | Remove-CcmAgent -Extended:@{'0'=$False; '1'=$True}[$Extended]
            } # end script
        $Script = Optimize-PackScript -Script $Script -Variable @{Extended=$Extended; Credential=$Credential}
        } # end begin
    Process {
        foreach ( $Entry in $Sessions | Format-ComputerName -Format "~~~ComputerName~~~.~~~Domain~~~" ) {
            [void]$AllTargets.Add( $Entry ) 
            } # next entry
        } # end process
    End {
        Write-Host "Processing $(Pluralize -Quantify $AllTargets -One '~~~Number~~~ session' -Many '~~~Number~~~ sessions')"
        # write-host "Processing $($AllTargets.count) sessions"
        $Jobs = $AllTargets | Foreach-Object -Parallel $Script -ThrottleLimit $ThrottleLimit -AsJob

        # the sessions created inside the foreach -Parallel command will be valid sessions but only from inside their respective multi-treaded session
        # we need to open those sessions here, which will require an additional step
        $Jobs | Wait-Job | Receive-Job
        } # end end
    } # end function Remove-CcmAgentMultiSession


function Read-CmLogs {
    # parses Ccm logs into a PsCustomObject with all the same fields except:
    #   - date and time fields from the log are converted into:
    #       - Date which is the datetime for your local system
    #       - UTC which is the utc for the log entry
    # reads both CM agent logs and server CM logs (two different formats)
    # examples
    #   CcmSetup Log
    #       $Entries = $Sessions | Read-CmLogs 
    #   CcmSetup Log looking for specific entries, filtering is done on the remote system
    #       $Entries = $Sessions | Read-CmLogs -Install -Tail 200 -Where { $_.Log -imatch 'w' }
    #       $Entries = $Sessions | Read-CmLogs -Install -Tail 2000 -Where { $_.Type -imatch '[23]' }
    #       $Entries = $Sessions | Read-CmLogs -Install -Tail 2000 -Where { (Get-Date).AddDays(-1) -le $_.Date  }
    #   dataldr.log from a server
    #       $Entries = $Sessions | Read-CmLogs -Logs "D:\Program Files\Microsoft Configuration Manager\Logs\dataldr.log" -Tail 200 -Where { $_.Log -imatch 'w' }
    #   Use a predefined date variable
    #       $Date = (Get-Date).AddHours(-10)
    #       $Where = [scriptblock]::Create( "`$_.Log -imatch 'Requesting Machine|Raising event|Assignent Request' -and `$_.Date -gt (get-date '$Date')" )
    #       $Entries = $Sessions | Read-CmLogs -Logs c:\windows\Ccm\Logs\PolicyAgent.log  -Tail 200 -Where $Where
    #   
    Param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [array]$Logs = "$($Env:SystemDrive)\Windows\ccmsetup\Logs\ccmsetup.log"
        , [int]$Tail = 10
        , $Where = "" # wherenetwork
        , $MyTimeZone = [System.TimeZoneInfo]::Local
        , [switch]$Quiet

        , [switch]$Install
        , [switch]$Communication
        ) # end param
    Begin {
        $AllTargets = New-Object System.Collections.Generic.List[System.Object]
        if ( $Install ) { 
            $Logs += "$($Env:SystemDrive)\Windows\ccmsetup\Logs\ccmsetup.log"
            } # end if 

        if ( $Communication ) { 
            $Logs += "$($Env:SystemDrive)\Ccm\Logs\CcmExec.log"
            $Logs += "$($Env:SystemDrive)\Ccm\Logs\CcmMessaging.log"
            $Logs += "$($Env:SystemDrive)\Ccm\Logs\CCMNotificationAgent.log"
            $Logs += "$($Env:SystemDrive)\Ccm\Logs\CcmRestart.log"
            $Logs += "$($Env:SystemDrive)\Ccm\Logs\CcmRepair.log"
            $Logs += "$($Env:SystemDrive)\Ccm\Logs\InventoryProvider.log"
            } # end if 

        [array]$Logs = $Logs | select -unique

        $Script = {
            Param (
                [array]$Logs = "$($Env:SystemDrive)\Windows\ccmsetup\Logs\ccmsetup.log"
                , [int]$Tail = 10
                , $Where = ""
                , $MyTimeZone = [System.TimeZoneInfo]::Local
                , $Quiet = $false
                ) # end param
            write-host "  In session '$($env:computername)'"
            #Include Variable Logs
            #Include Variable Tail
            #Include Variable WhereFilter
            #Include Variable MyTimeZone
            #Include Variable Quiet

            if ( [bool][int]$Quiet ) { write-host "    Quiet = '$($Quiet)'" -ForegroundColor DarkGray }
            if ( $Where ) { 
                write-host "    Applying Filter {$($Where)}" -ForegroundColor Darkgray
                [scriptblock]$FilterScript = ([ScriptBlock]::Create($Where))
                } # end if 
            # https://regex101.com/r/UsYWSI/1
            # $Regex = '<!\[Log\[(?<Log>(?:(?!\]LOG\]!>).)*)\]LOG\]!><time="(?<Time>[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,3})(?<Direction>[+-])(?<Offset>[0-9]{1,3})"\s*date="(?<Date>[^"]*)"\s*Component="(?<Component>[^"]*)"\s*Context="(?<Context>[^"]*)"\s*Type="(?<Type>[^"]*)"\s*Thread="(?<Thread>[^"]*)"\s*File="(?<File>[^"]*)">'
            $Regex = '<!\[Log\[(?<Log>(?:(?!\]LOG\]!>).)*)\]LOG\]!><time="(?<Time>[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,3})(?<Direction>[+-])(?<Offset>[0-9]{1,3})"\s*date="(?<Date>[^"]*)"\s*Component="(?<Component>[^"]*)"\s*Context="(?<Context>[^"]*)"\s*Type="(?<Type>[^"]*)"\s*Thread="(?<Thread>[^"]*)"\s*File="(?<File>[^"]*)">|^(?<Log>(?:(?!\$\$<|$).)*)[$]{2}<(?<Component>(?:(?!><).)*)><(?<Date>[0-9]{2}-[0-9]{2}-[0-9]{4})\ +(?<Time>[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,3})(?<Direction>[+-])(?<Offset>[0-9]{1,3})><thread=(?<thread>(?:(?!>$).)*)>$'
            foreach ( $Log in $Logs ) {
                write-host "    Get-Content -Path '$Log' -Tail $Tail" -ForegroundColor Darkgray
                foreach ( $Entry in Get-Content -Path $Log -Tail $Tail ) {
                    if ( $Entry -imatch $Regex ) {
                        # flip the utc direction around because so we correctly solve the time difference 
                        $OffsetDirection = @{"+" = "-"; "-" = "+"}[$matches.Direction]
                        $UTCTime = [datetime]::ParseExact($("$($matches.Date) $($matches.Time)$($OffsetDirection)$($matches.Offset/60)"),"MM-dd-yyyy HH:mm:ss.fffz", $null, "AdjustToUniversal")
                        $Output = [pscustomobject]@{
                            Computer    = $env:computername
                            LogFile     = $Log
                            Date        = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($UTCTime, "UTC", $MyTimeZone.ID)
                            Log         = $Matches.Log
                            Component   = $Matches.Component
                            Context     = $Matches.Context
                            Type        = $Matches.Type
                            Thread      = $Matches.Thread
                            File        = $Matches.File
                            RawDate     = get-date "$($Matches.Date) $($Matches.Time)"
                            UTC         = $UTCTime
                            } # end hash

                        $ReturnEntry = if ( [bool]$Where ) { 
                            [bool]($Output | Where-Object -FilterScript $FilterScript)
                            }
                        else { 
                            $True
                            } # end if 

                        if ( $ReturnEntry ) {
                            if ( -not $Quiet ) {
                                $Options = @{}
                                if ( $Output.Log -imatch "success|done|return code 0" ) { $Options.ForegroundColor = "green" }
                                elseif ( $Output.Type -eq 2 ) { $Options.ForegroundColor = "yellow" }
                                elseif ( $Output.Log -imatch "failed|error" -or $Output.Type -eq 3 ) { $Options.ForegroundColor = "Red" }
                                write-host "      $($Output.Date) $($Output.Log)" @Options
                                } # end if
                            write-output $Output
                            } # end if wherefilter
                        } # end if regex
                    } # next entry
                } # next log
            } # end script
        $Script = Optimize-PackScript -Script $Script -Variable @{Logs=$Logs; Tail=$Tail; Where=$Where; MyTimeZone=$MyTimeZone; Quiet=$([int][bool]$Quiet)}
        } # end begin
    Process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)" -ForegroundColor Cyan
            Invoke-command -Session $Session -scriptblock $Script -ArgumentList $Logs, $Tail, $Where, $MyTimeZone, $([int][bool]$Quiet)
            } # next session
#        foreach ( $Entry in $Sessions | Format-ComputerName -Format "~~~ComputerName~~~.~~~Domain~~~" ) {
#            [void]$AllTargets.Add( $Entry ) 
#            } # next entry
        } # end process
    End {
#        write-host "Processing $($AllTargets.count) sessions"
#        $Jobs = $AllTargets | Foreach-Object -Parallel $Script -ThrottleLimit $ThrottleLimit -AsJob
#
#        # the sessions created inside the foreach -Parallel command will be valid sessions but only from inside their respective multi-treaded session
#        # we need to open those sessions here, which will require an additional step
#        $Jobs | Wait-Job | Receive-Job
        } # end end
    } # end function Read-CmLogs



function Test-ConnectionToSiteServer {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Test-ConnectionToSiteServer -SiteServers wsp-stna-010657.nm.nmfco.com
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [array]$SiteServers = "wsp-stna-010657.nm.nmfco.com"
        ) # end if 
    begin {
        $Script = {
            Param (
                [array]$SiteServers
                ) # end param
            write-host "  In Session"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $Certificates = Get-ChildItem -Path "cert:\CurrentUser\my" -Recurse
            If ( $Certificiates ) {
                $iwr = Foreach ( $Certificate in Get-ChildItem -Path "cert:\CurrentUser\my" -Recurse ) {
                    Write-host "    Certificate Thumbprint: '$($Certificate.Thumbprint)'"
                    foreach ( $SiteServer in $SiteServers ) {
                        Foreach ( $QueryString in "MPLIST", "MPCERT", "MPKeyInformation") {
                            Invoke-WebRequest "https://$($SiteServer)/SMS_MP/.sms_aut?$($QueryString)" -Certificate $certificate -UseBasicParsing
                            } # next query string
                        } # next SiteServer
                    } # next certificate
                $iwr | select StatusCode, StatusDescription, @{n="URI"; e={$_.BaseResponse.ResponseUri}}
                    
                } Else {
                Write-host "    no certificates in 'cert:\CurrentUser\My' found" -ForegroundColor Yellow
                } # end if
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            Invoke-command -Session $Session -scriptblock $Script -ArgumentList $SiteServers
            } # next session
        } # end process
    } # end function Test-ConnectionToSiteServer



function Get-CcmLogs {
    # This function collects logs directly from the client, but will require the CcmExec service to be stopped, or else some of the important logs will be seen as "in use"
    # due to these limitations this solution is not ideal
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Get-CcmLogs -CutoffDate (Get-Date).AddDays(-2)
    # Explorer "x:\temp\$($session.ComputerName)"
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , $CutoffDate = (Get-Date).AddYears(-20)
        , $Destination = "x:\temp\"
        ) # end if 
    begin {
        $Script = {
            param (
                $FilePath
                , $CutoffDate = (Get-Date).AddYears(-20)
                ) # end param
            Write-Host "path = '$FilePath'"
            Write-Host "CutoffDate = '$CutoffDate'"
            Get-Item -Path $FilePath | Get-ChildItem -Recurse | Where { $_.LastWriteTime -gt $CutoffDate }
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            new-item -ItemType Directory -Path "$Destination\$($session.ComputerName)\Ccm" -Force
            $Files = Invoke-Command -Session $Session -Scriptblock $Script -ArgumentList "c:\windows\Ccm\Logs\", (Get-Date).AddDays(-2)
            Copy-Item -FromSession $Session -Path $Files.FullName -Destination "$Destination\$($session.ComputerName)\Ccm\" -Force

            new-item -ItemType Directory -Path "x:\temp\$($session.ComputerName)\CcmSetup" -Force
            Copy-item -Recurse -FromSession $Session -Path "c:\windows\ccmSetup\logs\*" -Destination "x:\temp\$($session.ComputerName)\CcmSetup\" -Force
            } # next session
        } # end process
    } # end function Get-CcmLogs


function Get-SccmCheckinDates {
    # queries the most recent X number of workstations to have checked into SCCM
    # tests opening a WinRM session to those workstations
    # reports test progress and success or failure
    # returns the session object
    #
    # examples
    #   $Data = Get-SccmCheckinDates -Top 100
    #   $Data | Out-Gridview
    #   $Sessions = $Data | Open-MultiPsSession
    #
    #   Get devices which have a recent Policy request and a Hardware scan older than 7 days
    #       $Data = Get-SccmCheckinDates -Top 100 -Where "'$((Get-Date).AddHours(-3))' < LastPolicyRequest AND LastHardwareScan < '$((Get-Date).AddDays(-7))'"  -OrderBy "LastHardwareScan"
    #       $Data | ft
    #
    #   Get dates for given sessions
    #       $Data = $Sessions | Get-SccmCheckinDates -Top 25 -OrderBy "LastHardwareScan Desc"
    #       $Data | ft
    #
    #   Get devices for specific users
    #       $Data = Get-SccmCheckinDates -Top 25 -Where "User_Name0 like 'mil1642%'"
    #       $Data | ft
    #
    #   Get devies that have same ip range
    #       $Data = Get-SccmCheckinDates -Top 10000
    #       [IpAddress]$Subnet = "10.185.130.0" # 10.185.130.0\23
    #       [IpAddress]$SubnetMask = "255.255.254.0"
    #       $DataSameIpRange = $Data | ?{ $_.IpAddresses -split "," | ?{ $_ } | ?{ $Subnet.Address -eq ( ([IpAddress]$_).Address -band $SubnetMask.Address) } }

    Param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [alias("Sessions")]
        $Targets = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )

        , [int]$Top
        , [string]$OrderBy = "LastPolicyRequest DESC"
        , [string]$Where    # = "$((Get-Date).AddHours(-1)) < LastPolicyRequest"
        , [string]$LocalDateTimeOffset = $(Get-Date -format "yyyy-MM-dd HH:mm:ss.ms000 K")  # must look like "2021-12-14 08:34:30.3430000 -06:00" or null, if null then will return UTC time

        , [string]$SiteServer = @{""="ntdbph8012m00.nm.nmfco.com"; "NM"="ntdbph8012m00.nm.nmfco.com"; NMTEST="ntdbth7965m00"; NMDEV="ntapdh7589m00"}[[string]$env:UserDomain]
        , [string]$DatabaseName = @{""="CM_NM1"; "NM"="CM_NM1"; NMTEST="NMT"; NMDEV="CM_NMD"}[[string]$env:UserDomain]
        ) # end param
    Begin {
        write-host "Querying SCCM for dates"
        [string]$Top = if ( $Top -is [int] -and $Top -gt 0 ) {
            " Top $Top "
            } # end if 
        [string]$Where = if ( $Where -is [string] -and "$Where" -ne "" ) {
            " and ( $($Where) )  "
            } # end if 
        [string]$OrderBy = if ( $OrderBy -is [string] -and "$OrderBy" -ne "" ) {
            " Order by $($OrderBy)  "
            } # end if 
        $Dates = if ( $LocalDateTimeOffset ) { 
            write-host "  Dates will be converted to this offset '$LocalDateTimeOffset'" -foregroundcolor DarkGreen
            @"
                , CONVERT(datetime, SWITCHOFFSET(CONVERT(datetimeoffset, LastHardwareScan),     DATENAME(TzOffset, '$LocalDateTimeOffset'))) AS LastHardwareScan
                , CONVERT(datetime, SWITCHOFFSET(CONVERT(datetimeoffset, LastDDR),              DATENAME(TzOffset, '$LocalDateTimeOffset'))) AS LastDDR
                , CONVERT(datetime, SWITCHOFFSET(CONVERT(datetimeoffset, LastPolicyRequest),    DATENAME(TzOffset, '$LocalDateTimeOffset'))) AS LastPolicyRequest
                , CONVERT(datetime, SWITCHOFFSET(CONVERT(datetimeoffset, LastSoftwareScan),     DATENAME(TzOffset, '$LocalDateTimeOffset'))) AS LastSoftwareScan 
"@
            } 
        else {
            write-host "  Dates are UTC direct from the database" -ForegroundColor DarkYellow
            @"
                , LastHardwareScan
                , LastDDR
                , LastPolicyRequest
                , SINV.LastSoftwareScan as LastSoftwareScan 
"@
            } # end if 

        $AllTargets = New-Object System.Collections.Generic.List[System.Object]
        $SqlStatement = @"
            select ~~~Top~~~ 
                rSys.Name0 as Name
                $Dates
                , LastMpServerName
                , rSys.User_Name0
                , (
                    STUFF(
                        (
                            Select ',' + ip.IP_Addresses0
                            from v_RA_System_IPAddresses AS IP
                            Where ip.IP_Addresses0 not like '%:%'
                                and IP.ResourceID = rSys.ResourceID
                            FOR XML PATH(''), TYPE, ROOT
                            )
                        .value('root[1]','nvarchar(max)')
                        ,1,1,'')
                    ) as IPAddresses
            from $($DatabaseName).dbo.v_R_System rSys
            left join (
                select *
                from $($DatabaseName).dbo.vWorkstationStatus
                where LastPolicyRequest in ( select max(LastPolicyRequest) from $($DatabaseName).dbo.vWorkstationStatus group by ResourceID )
                ) as LatestWorkstationStatus on LatestWorkstationStatus.ResourceID = rSys.ResourceID
            left join $($DatabaseName).dbo.vSoftwareInventoryStatus SINV on SINV.ResourceID = rSys.ResourceID 
            Where rSys.Operating_System_Name_and0 like '%workstation%'
            AND rSys.Name0 not like 'ws%'
            AND rSys.Name0 not like 'nt%'
            AND rSys.Name0 not like 'etl%'
            AND rSys.Name0 not like 'vtx%'
            AND rSys.Name0 not like 'vfx%'
            AND rSys.Name0 not like 'rpa%'
            ~~~Where~~~ 
            ~~~OrderBy~~~
"@
        } # end begin

    Process {
        if ( $Targets ) {
            foreach ( $Entry in $Targets | Format-ComputerName -Format "rSys.Name0 = '~~~ComputerName~~~'" ) {
                [void]$AllTargets.Add( $Entry ) 
                } # next entry
            } # end if
        } # end process
    End {
        if ( $AllTargets ) {
            $Where += " and ( " + ($AllTargets  -join " or ") + " ) "
            } # end if 
        $SqlStatement = $SqlStatement.Replace("~~~Top~~~", $Top)
        $SqlStatement = $SqlStatement.Replace("~~~Where~~~", $Where)
        $SqlStatement = $SqlStatement.Replace("~~~OrderBy~~~", $OrderBy)

        $SqlData = Invoke-SQL -SqlStatement $SqlStatement
        write-host "  Found $(Pluralize -Quantify $SqlData.Name -One '~~~Number~~~ record' -Many '~~~Number~~~ records')" -ForegroundColor DarkGray
        write-Output $SqlData
        } # end end
    } # end function Get-SccmCheckinDates



function Get-DeviceFromSccm {
    # gets device information for specified machines. 
    #
    # examples:
    #   $session = Open-Pssession B8978.nm.nmfco.com
    #   $session | Get-DeviceFromSccm
    #   $Device = $session | Get-DeviceFromSccm
    #   $Device.IPAddresses | ?{ $_ -imatch "^\s*(?:[0-9]{1,3}(?:\.|\s*$)){4}\s*" }
    #  
    #   $Device = "b0330" | Get-DeviceFromSccm
    #   $Device = "b0330", "B8978.nm.nmfco.com" | Get-DeviceFromSccm
    #  
    #   $Device = "b0330" | Get-DeviceFromSccm | select Name, ClientVersion, LastDDR, LastPolicyRequest, LastHardwareScan, LastSoftwareScan, Username
    #   $Device = $session | Get-DeviceFromSccm | select Name, ClientVersion, LastDDR, LastPolicyRequest, LastHardwareScan, LastSoftwareScan, Username
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [array]$Computers = $( get-pssession | ?{ $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [PSCredential]$Credential = [CustomCredential]::New("$($Env:UserDomain)\$($Env:Username -ireplace '-.*$',"-$($Env:UserDomain)")").Credential()
        , [string]$SiteServer = @{""="ntdbph8012m00.nm.nmfco.com"; "NM"="ntdbph8012m00.nm.nmfco.com"; NMTEST="ntdbth7965m00"; NMDEV="ntapdh7589m00"}[[string]$env:UserDomain]
        , [string]$DatabaseName = @{""="CM_NM1"; "NM"="CM_NM1"; NMTEST="CM_NMT"; NMDEV="CM_NMD"}[[string]$env:UserDomain]
        ) # end if 
    begin {
        # skip Include function Invoke-Sql
        #Include Variable Credential

        Import-Module Open-PsSession -DisableNameChecking

        [hashtable]$Options = @{
            Credential = $Credential
            } # end hash
        if ( $PsVersionTable.psVersion -lt [version]"6.0.0.0" ) {
            try {
                add-type @"
                    using System.Net;
                    using System.Security.Cryptography.X509Certificates;
                    public class TrustAllCertsPolicy : ICertificatePolicy {
                        public bool CheckValidationResult( ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem ) { return true; }
                        }
"@
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                }
            catch {}
            }
        else {
            $Options.SkipCertificateCheck = $True
            } # end if 
        $SqlStatment = "select LastHardwareScan, LastDDR, LastPolicyRequest, LastMpServerName, vWorkstationStatus.UserName as Username, SINV.LastSoftwareScan as LastSoftwareScan from $($DatabaseName).dbo.vWorkstationStatus left join $($DatabaseName).dbo.vSoftwareInventoryStatus SINV on vWorkstationStatus.ResourceID = SINV.ResourceID ~~~Where~~~"
        } # end begin
    process {
        Foreach ( $Computername in $Computers | Format-ComputerName -Format "~~~ComputerName~~~" ) {
            $Output = if ( $Computername ) {
                # write-host "$Computername"
                try {
                    Invoke-RestMethod -Uri "https://$($siteserver)/adminservice/wmi/sms_r_system?`$filter=name eq '$($Computername)'" -Method GET @Options | Select-Object -ExpandProperty Value
                    }
                catch {
                    write-host "  $($_.Exception.Message)" -ForegroundColor DarkRed
                    } # end try/catch
                } # end if

            if ( $Output ) { 
                # try to collate sql data into the object
                try {
                    $SqlData = Invoke-SQL -SqlStatement $($SqlStatment -ireplace "~~~Where~~~", " where vWorkstationStatus.Name = '$Computername' ")
                    foreach ( $Property in $SqlData | GM -MemberType Property ) {
                        $Output | Add-Member -NotePropertyName $Property.Name -NotePropertyValue $SqlData.$($Property.Name)
                        } # next Property
                    }
                Catch {
                    } # end try/catch
                Write-output $Output
                Remove-Variable -Name Output
                } # end if
            } # next Computer
        } # end process
    } # end function Get-DeviceFromSccm


