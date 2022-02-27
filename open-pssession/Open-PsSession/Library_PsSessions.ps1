
# to rebuild this package
#   ConvertTo-PsModuleChocolateyPackage -NuspecFiles X:\gitlab\dw-endpoint\Modules\Open-PsSession\Package\Package.nuspec

    function Open-PsSession {
        # Creates a ps session, and will create a hosts entry to facilitate servers where DNS doesn't resolve
        # Targets that do not resolve to IP addresses then this will query SCCM for the latest known IP address
        #    -IP allows you to provide an ip address for the target, is only useful when making a single connection, SCCM will be queried for the latest known IP if this value is omitted
        # examples: 
        # $Sessions = $Targets | Open-PsSession
        #
        #   - CrowdStrikeCache = string, path to file; really only usefull when running this in parallel. CrowdStrike will rate limit connection tokens, there for a parallel call will need to front load us with a cache file
        # requires: 
        #   # CrowdStrike powershell module
        #       # remove older versions
        #           Uninstall-Module -Name PSFalcon -AllVersions
        #       # install the current version
        #           Install-Module -Name PSFalcon -Scope AllUsers
        #
        #   Repack the chocolatey package
        #       choco pack X:\gitlab\dw-endpoint\Modules\open-pssession\Package\Package.nuspec --out \\nm.nmfco.com\dfs01\appls\sd\Chocolatey
        #
        #   Install module
        #       Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        #       choco upgrade chocolatey -y
        #       choco install Open-PsSession -y
        #
        #   Uninstall module
        #       choco uninstall Open-PsSession -y
        #
        param (
            [Parameter(mandatory=$True, Position=0, ValueFromPipeline=$True)]
            [alias("ResourceName", "Device", "Computer", "ComputerName", "FQDN", "Session")]
            [Array]$Targets
            
            , [string]$CrowdStrikeCache # = "c:\temp\CrowdStrikeCache.json"
            , [switch]$Server
            , 
            [ValidatePattern('^\s*(?:[0-9]{1,3}(?:\.|\s*$)){4}$|^$')]
            $IP
            , [PsCredential]$Credential = [CustomCredential]::New("$($Env:UserDomain)\$($Env:Username -ireplace '-.*$',"-$($Env:UserDomain)")").Credential()
            ) # end param
        begin {
            write-host "Open-PsSession v$((Get-Module Open-PsSession).Version.ToString())" -ForegroundColor DarkGray
            if ( $Server ) { 
                Write-host "$("_" * $Host.UI.RawUI.WindowSize.Width)`nOpening sessions"
                }
            else {
                # this will force the import of the two classes, this is important when using the 
                Import-Module Open-PsSession -DisableNameChecking

                #Include Variable Credential
                #Include Variable CrowdStrikeCache
                $PsSessionOptions = @{
                    Cred = $Credential
                    ErrorAction = "SilentlyContinue"
                    # OpenTimeout = 60000 # milliseconds to wait for the session connection to be established
                    } # end hash
                $LogEntry = [PsCustomObject]@{
                    Date = get-date -format "yyyyMMdd-HHmmss"
                    Username = $env:username
                    Computername = $env:Computername
                    Commandlet = "Open-PsSession"
                    Event = ""
                    } # end hash
                        
                function Write-Log {
                    # Example 
                    #   write-Log -Entry $Entry
                    param (
                        $Entry
                        , $Log = "$($Env:HomeDrive)$($env:HomePath)\Documents\Winrm.log"
                        ) # end param
                    $Header, $Body = $Entry | ConvertTo-Csv -NoTypeInformation
                    if ( -not (Test-Path $Log) ) { $Body | Out-File -FilePath $Log }
                    $Body | Out-File -Append -FilePath $Log
                    } # end function
                } # end if Server
            } # end begin
        Process {

            if ( $Server ) { 
                Foreach ( $Target in $Targets ) {
                    write-host "  $Target " -NoNewLine
                    try { 
                        $Session = $Target | New-PsSession -Credential $Credential
                        Invoke-Command -Session $Session -ScriptBlock {write-host "Success" -ForegroundColor DarkGreen} 
                        $Session
                        } catch { Write-Host "Failed" -ForegroundColor Red }
                    } # next target
                }
            else {


                # loop for each target
                foreach ( $Target in $Targets | Format-ComputerName -Format "~~~ComputerName~~~.~~~Domain~~~" ) {
                    Write-Host "'$Target'"
                    [hashtable]$IpAddressesTried = @{}
                    $boolValidSessionFound = $false
                    # remove pre-existing host file entries for this target
                    try {
                        Remove-HostEntry -LockFile "$($Env:systemdrive)\temp\Hosts.lock" -Name $Target -WithNote "Created for Open-PsSession, delete me"
                        }
                    catch {
                        if ( $_.Exception.Message -imatch "Access to the path '[^']+' is denied" ) {
                            throw "Error 0236: You do not have suffecent rights on this computer to lock files and update the hosts file.`nEnding script prematurely since the required rights are not available"
                            } # end if
                        throw $_.Exception.Message
                        } # end try/catch
                    $DnsResolved = Resolve-DNSName -Name $Target -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IpAddress

                    # get list of possible IPs from each source
                    foreach ( $SourceName in "Provided", "DNS", "CrowdStrike", "SCCM" ) {
                        if ( -not $boolValidSessionFound ) {
                            # fetch IPs from source, Do no fetch all possible IPs from all sources since some sources are either slow or don't play well with multi-treading
                            $PossibleIPs = switch ( $SourceName ) {
                                "Provided" {
                                    if ( $IP ) {
                                        write-host "  Using $($SourceName)" -ForegroundColor DarkGray
                                        $IP
                                        } # end if 
                                    break
                                    } 
                                "DNS" { 
                                    write-host "  Using $($SourceName)" -ForegroundColor DarkGray
                                    if ( $DnsResolved ) { 
                                        Write-Host "    DNS resolved to '$($DnsResolved)'" -ForegroundColor darkgreen
                                        } 
                                    else {
                                        Write-Host "    DNS did not resolve" -ForegroundColor darkyellow
                                        }  # end if 
                                    $DnsResolved
                                    break 
                                    } 
                                "SCCM" { 
                                    write-host "  Using $($SourceName)" -ForegroundColor DarkGray
                                    try {
                                        $Device = $Target | Get-DeviceFromSccm -Credential $Credential

                                        # construct a meaningfull message to the user
                                        $LastPolicyRequest = [System.TimeZoneInfo]::ConvertTimeFromUtc($Device.LastPolicyRequest, [System.TimeZoneInfo]::Local)
                                        $HoursAgo = if ( $LastPolicyRequest ) { [math]::Round(((Get-Date) - $LastPolicyRequest).TotalHours, 2) } else { "" }
                            
                                        [hashtable]$WriteOptions = @{ ForegroundColor = "DarkGreen" }
                                        if ( [math]::Abs($HoursAgo) -gt 8 ) { $WriteOptions.ForegroundColor = "DarkYellow" }
                                        if ( [math]::Abs($HoursAgo) -gt 24 ) { $WriteOptions.ForegroundColor = "DarkRed" }
                                        Write-Host "    SCCM Last policy request was '$($HoursAgo)' hours ago at '$($LastPolicyRequest)' $([System.TimeZoneInfo]::Local.Id -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')"  @WriteOptions
                            
                                        # use only ipv4 addresses
                                        $Device.IPAddresses | Where-Object { $_ -imatch "^\s*(?:[0-9]{1,3}(?:\.|\s*$)){4}\s*" }
                                        } 
                                    catch {
                                        write-host "    Failed to connect to SCCM. Skipping" -ForegroundColor DarkYellow
                                        } # end try/catch
                                    break
                                    } # end SCCM
                                "CrowdStrike" { 
                                    write-host "  Using $($SourceName)" -ForegroundColor DarkGray
                                    # if a CrowdStrikeCache file was provided then use that, otherwise directly query CrowdStrike
                                    $CrowdStrikeData = if ( $CrowdStrikeCache ) {
                                        # check the file age if greater than 10 minutes return warning
                                        if ( Test-Path $CrowdStrikeCache ) {
                                            $CacheFile = Get-Item -Path $CrowdStrikeCache
                                            $MinutesAgo = [math]::Round(((Get-Date) - $CacheFile.LastWriteTime).TotalMinutes, 2) 

                                            if ( $MinutesAgo -ge 15 ) {
                                                [hashtable]$WriteOptions = @{ ForegroundColor = "DarkGreen" }
                                                if ( [math]::Abs($MinutesAgo) -gt 6 ) { $WriteOptions.ForegroundColor = "DarkYellow" }
                                                if ( [math]::Abs($MinutesAgo) -gt 15 ) { $WriteOptions.ForegroundColor = "DarkRed" }
                                                write-host "    Warning 1118: CrowdStrikeCache last write time was '$($MinutesAgo)' minutes ago at '$($CacheFile.LastWriteTime)' $([System.TimeZoneInfo]::Local.Id -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')" -ForegroundColor DarkYellow
                                                } # end if 
                                            Get-Content c:\temp\CrowdStrikeCache.json | ConvertFrom-Json | Where-Object { $_.hostname -ieq $($Target | Format-ComputerName -Format "~~~Computername~~~") } | Select-Object -first 1
                                            } # end if 
                                        }
                                    else {
                                        # $Target | Get-HostFromCrowdStrike 
                                        $Target | Get-HostFromCrowdStrikeScheduledTask | Get-Item | Get-Content | ConvertFrom-Json
                                        } # end if 

                                    if ( $CrowdStrikeData ) { 
                                        $CrowdStrikeData.Local_Ip
                                        try {
                                            $FirstSeen = [System.TimeZoneInfo]::ConvertTimeFromUtc($CrowdStrikeData.First_Seen, [System.TimeZoneInfo]::Local)
                                            }
                                        catch {
                                            write-host "    minor cosmetic issue 0186: $($_.Exception.Message)" -ForegroundColor DarkGray
                                            } # end try/catch
                                        try {
                                            $LastSeen = [System.TimeZoneInfo]::ConvertTimeFromUtc($CrowdStrikeData.Last_Seen, [System.TimeZoneInfo]::Local)
                                            }
                                        catch {
                                            write-host "    minor cosmetic issue 0192: $($_.Exception.Message)" -ForegroundColor DarkGray
                                            } # end try/catch
                                        $MinutesAgo = if ( $LastSeen ) { [math]::Round(((Get-Date) - $LastSeen).TotalMinutes, 2) } else { "" }
                                        $LogEntry.Event += ", Per CrowdStrike '$($PossibleIPs -join ',')' was last seen '$($MinutesAgo)' minutes ago"

                                        # CrowdStrike agents will check in every 6 minutes
                                        [hashtable]$WriteOptions = @{ ForegroundColor = "DarkGreen" }
                                        if ( [math]::Abs($MinutesAgo) -gt 6 ) { $WriteOptions.ForegroundColor = "DarkYellow" }
                                        if ( [math]::Abs($MinutesAgo) -gt 15 ) { $WriteOptions.ForegroundColor = "DarkRed" }
                                        Write-Host "    First Seen '$($FirstSeen)' $([System.TimeZoneInfo]::Local.Id -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')" -ForegroundColor darkgray
                                        Write-Host "    Last Seen '$($MinutesAgo)' minutes ago at '$($LastSeen)' $([System.TimeZoneInfo]::Local.Id -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')"  @WriteOptions
                                        } 
                                    else {
                                        write-host "    Warning 1130: Target '$($Target)' not found in CrowdStrikeCache." -ForegroundColor DarkYellow
                                        } # end if 
                                    break
                                    } # end CrowdStrike
                                Default { Write-Host "    Warning 1079: SourceName '$($SourceName)' is not recognized" -ForegroundColor DarkYellow }
                                } # end switch

                            # use only ipv4 addresses
                            $PossibleIPs = $PossibleIPs | Where-Object { $_ -imatch "^\s*(?:[0-9]{1,3}(?:\.|\s*$)){4}\s*" }

                            # sort IPs so the one most likely to be successful are first
                            $TryPossibleIPs = New-Object System.Collections.Generic.List[System.Object]
                            $LowProbablity = "^(?:10\.0\.|192\.)"
                            $PossibleIPs | Where-Object { $_ -inotmatch $LowProbablity } | ForEach-Object { $TryPossibleIPs.Add( $_ ) }
                            $PossibleIPs | Where-Object { $_ -imatch    $LowProbablity } | ForEach-Object { $TryPossibleIPs.Add( $_ ) }

                            # foreach possible IPv4 address, test the port, then establish a session, then test the session to confirm it's correct
                            foreach ( $PossibleIP in $TryPossibleIPs ) {
                                if ( -not $boolValidSessionFound ) {
                                    # if we already tested this ip then skip it
                                    if ( $IpAddressesTried.ContainsKey( $PossibleIp ) ) {
                                        write-host "    Skipping IP '$($PossibleIP)' from '$($SourceName)' because it was previously tested in: $($IpAddressesTried[$PossibleIp] -join ', ')" -ForegroundColor DarkYellow
                                        $IpAddressesTried[$PossibleIp] += $SourceName
                                        }
                                    else {
                                        # we should only execute this set of steps for this IP if we have not already tested it
                                        $IpAddressesTried[$PossibleIp] = @( $SourceName )
                                        # test port 5986 on IP
                                        write-host "    Testing possible IP '$($PossibleIP)' from '$($SourceName)'" -ForegroundColor DarkGray
                                        $TestConnection = Test-NetConnection $PossibleIP -port 5986 -WarningVariable Warning -WarningAction SilentlyContinue
                                        if ( -not $TestConnection.TcpTestSucceeded ) { 
                                            write-host "    Warning 1172: $($Warning)" -ForegroundColor Yellow
                                            }
                                        else {
                                            # if port test was successful
                                            write-host "    '$($SourceName)' known IP '$PossibleIP' responds to WinRM port 5986" -ForegroundColor DarkGreen
                                            $LogEntry.Event += ", responds to port 5986 ping on ip '$($PossibleIP)' from '$($SourceName)'"

                                            # remove pre-existing entries for this host
                                            Remove-HostEntry -LockFile "$($Env:systemdrive)\temp\Hosts.lock" -Name $Target -WithNote "Created for Open-PsSession, delete me"

                                            # if source is not DNS then set a host file entry for this PossibleIP
                                            if ( $SourceName -inotmatch "^DNS$" ) {
                                                if ( [IpAddress]$DnsResolved -eq [IpAddress]$PossibleIP ) {
                                                    Write-Host "    DNS mataches source '$($SourceName)'" -ForegroundColor DarkGray
                                                    }
                                                else {
                                                    Write-Host "    DNS '$($DnsResolved)' not equal to '$($SourceName)' '$($PossibleIP -join ',')' setting host file entry" -ForegroundColor DarkGray
                                                    $LogEntry.Event += ", DNS '$($DnsResolved)' to '$($SourceName)' '$($PossibleIP)' mismatch. Setting hosts to favor '$($PossibleIP)'"
                                                    # write-host "Set-HostEntry -LockFile ""$($Env:systemdrive)\temp\Hosts.lock"" -Name $Target -IP $PossibleIP -Note ""Created for Open-PsSession, delete me"""
                                                    Set-HostEntry -LockFile "$($Env:systemdrive)\temp\Hosts.lock" -Name $Target -IP $PossibleIP -Note "Created for Open-PsSession, delete me"
                                                    } # end if
                                                } # end if DNS

                                            # attempt to open a session to the target
                                            $error.Clear()
                                            $PsSessionOptions.ComputerName = $Target
                                            Write-Host "    Attempting connection" -ForegroundColor darkgray -NoNewLine
                                            $Session = new-pssession -UseSSL @PsSessionOptions

                                            if ( -not $Session ) { 
                                                # failed, try the connection with skipping certificate checks
                                                Write-Host " using -SkipCNCheck -SkipCaCheck" -ForegroundColor Yellow -NoNewLine
                                                $Session = new-pssession -UseSSL -SessionOption $(New-PsSessionOption -SkipCNCheck -SkipCaCheck) @PsSessionOptions
                                                } # end if

                                            if ( -not $Session ) { 
                                                # failed, try the connection with skipping certificate checks
                                                write-host ""
                                                Write-Host "    Attempting connection" -ForegroundColor darkgray -NoNewLine
                                                Write-Host " using -UseSSL:`$false" -ForegroundColor Yellow -NoNewLine
                                                $Session = new-pssession @PsSessionOptions
                                                } # end if

                                            if ( -not $Session ) {
                                                Write-Host " Failed to connect" -ForegroundColor Red
                                                $boolValidSessionFound = $False
                                                continue
                                                } # end if 

                                            # if session is live, 
                                            #   then query remote computer for its computername and confirm it's what we expect, and configure the prompt to be more obvious
                                            try { 
                                                $ScriptBlock = {
                                                    function Prompt {
                                                        $Computer = "[$($Env:Computername).$($Env:UserDNSDomain)]"
                                                        $Orange = "202"
                                                        $Yellow = "226"
                                                        write-host "$([char]27)[48;5;$($Orange)m$([char]27)[38;5;$($Yellow)m$($Computer)$([char]27)[0m" -NoNewLine
                                                        write-host " $pwd" -NoNewLine
                                                        # PS remote will append hostname and ps>
                                                        # to remove these
                                                        $RedactString += "[$($Env:Computername).$($Env:UserDNSDomain)]: " -replace ".", "`b"
                                                        $RedactString += "[$($Env:Computername).$($Env:UserDNSDomain)]: " -replace ".", " "
                                                        $RedactString += "[$($Env:Computername).$($Env:UserDNSDomain)]: " -replace ".", "`b"
                                                        return "$RedactString> "	
                                                        }
                                                    write-host " Open" -ForegroundColor DarkGreen -NoNewLine; 
                                                    Write-Output "$($Env:computername).$($Env:UserDnsDomain)" 
                                                    } # end scriptblock

                                                $RemoteComputername = Invoke-Command -session $Session -ScriptBlock $ScriptBlock
                                                if ( $Target -ieq $RemoteComputername ) {
                                                    Write-Host ", computer name is correct, " -ForegroundColor DarkGreen -NoNewLine
                                                    Write-host " Success " -ForegroundColor White -BackgroundColor Green
                                                    $LogEntry.Event += ", Successful connection"

                                                    $boolValidSessionFound = $True
                                                    Write-Output $Session
                                                    break
                                                    }
                                                else {
                                                    Write-Host " Remote name '$($RemoteComputerName)' is wrong" -ForegroundColor Darkred
                                                    $boolValidSessionFound = $False
                                                    } # end if
                                                } 
                                            catch { 
                                                Write-Host " Failed " -ForegroundColor White -BackgroundColor Red
                                                write-host $_ 
                                                } # end try/catch
                                            } # end if else ( -not $TestConnection.TcpTestSucceeded )
                                        } # if else ( $IpAddressesTried.ContainsKey( $PossibleIp ) )
                                    } # end elseif ( -not $boolValidSessionFound ) {
                                } # next PossibleIp
                            } # end if ( -not $boolValidSessionFound )
                        } # next sourcename
                    } # next target
                } # end if Server
            } # end process
        end {
            } # end end
        } # end function Open-PsSession


    function Open-MultiPsSession {
        # Creates a ps session, and will create a hosts entry to facilitate servers where DNS doesn't resolve
        # Targets that do not resolve to IP addresses then this will query SCCM for the latest known IP address
        #    -IP allows you to provide an ip address for the target, is only useful when making a single connection, SCCM will be queried for the latest known IP if this value is omitted
        # examples: 
        # $Sessions = $Targets | Open-MultiPsSession
        param (
            [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
            [alias("ResourceName", "Device", "Computer", "ComputerName", "FQDN", "Session")]
#            [ValidatePattern('^\s*(?:[a-z][a-z0-9_-]{1,25}(?:\.|\s*$)){0,4}$')]
            [Array]$Targets
            , 
            [alias("Credential")] # the script will accept either a Class_CustomCredential or PsCredential object, this makes VSCode code checker happy
            $CC = [CustomCredential]::New("$($Env:UserDomain)\$($Env:Username -ireplace '-.*$',"-$($Env:UserDomain)")")
            , [string]$CrowdStrikeCache = "c:\temp\CrowdStrikeCache.json"
            , [int]$ThrottleLimit = 25
            ) # end param
        begin {
            $StartTime = Get-Date
            Write-Host "Started '$($StartTime)'" -ForegroundColor DarkGray
            # yes we could use the #Requires commmand but that would invalidate the entire script instead of just this one function
            if ( $PsVersiontable.PsVersion -le [system.version]"7.0" ) { throw "error 0298: Open-MultiPsSession requires Powershell version 7. This is being run in powershell version '$($PsVersionTable.PsVersion)' on '$($Env:Computername)'" } # end if
            $AllTargets = New-Object System.Collections.Generic.List[System.Object]
            $Script = {
                Import-Module Open-PsSession -DisableNameChecking
                # skip Include-InsertFunctionsHere
                # skip Include function Open-PsSession
                $_ | Open-PsSession
                } # end script
            # if the provided credential is a PsCredential then convert it to a CustomCredential
            if ( $CC -is [PsCredential] ) {
                $CC = [CustomCredential]::New($CC)
                } # end if
            } # end begin
        Process {
            foreach ( $Entry in $Targets | Format-ComputerName -Format "~~~ComputerName~~~.~~~Domain~~~" ) {
                [void]$AllTargets.Add( $Entry ) 
                } # next entry
            } # end process
        End {
            $AllTargets = $AllTargets | Select-Object -Unique

            Write-Host "Creating local CrowdStrike Cache at '$($CrowdStrikeCache)' for $($AllTargets.count) unique names" -ForegroundColor darkgray
            $CrowdStrikeCache = $AllTargets | Get-HostFromCrowdStrikeScheduledTask
            if ( -not (Test-Path $CrowdStrikeCache -ErrorAction SilentlyContinue) ) {
                write-host "Failed to create CrowdStrike Cache file at '$($CrowdStrikeCache)'" -ForegroundColor Yellow
                } # end if 
#             ($CrowdStrikeData = $AllTargets | Get-HostFromCrowdStrike) | ConvertTo-Json -Depth 10 | Out-File $CrowdStrikeCache -Force

            $Script = Optimize-PackScript -Script $Script -Variable @{Credential=$CC; CrowdStrikeCache=$CrowdStrikeCache}
            Write-Host "Processing $(Pluralize -Quantify $AllTargets -One '~~~Number~~~ record' -Many '~~~Number~~~ records')"
            $Jobs = $AllTargets | Foreach-Object -Parallel $Script -ThrottleLimit $ThrottleLimit -AsJob

            # the sessions created inside the foreach -Parallel command will be valid sessions but only from inside their respective multi-treaded session
            # we need to open those sessions here, which will require an additional step
            $Sessions = foreach ( $Job in $Jobs | Wait-Job | Receive-Job ) {
                $ConfigureSession = {
                    function Prompt {
                        $Computer = "[$($Env:Computername).$($Env:UserDNSDomain)]"
                        $Orange = "202"
                        $Yellow = "226"
                        write-host "$([char]27)[48;5;$($Orange)m$([char]27)[38;5;$($Yellow)m$($Computer)$([char]27)[0m" -NoNewLine
                        write-host " $pwd" -NoNewLine
                        # PS remote will append hostname and ps>
                        # to remove these
                        $RedactString += "[$($Env:Computername).$($Env:UserDNSDomain)]: " -replace ".", "`b"
                        $RedactString += "[$($Env:Computername).$($Env:UserDNSDomain)]: " -replace ".", " "
                        $RedactString += "[$($Env:Computername).$($Env:UserDNSDomain)]: " -replace ".", "`b"
                        return "$RedactString> "	
                        }
                    } # end scriptblock

                try {
                    ($Session = $Job | New-PsSession)
                    Invoke-Command -session $Session -ScriptBlock $ConfigureSession
                    }
                catch { # [System.Management.Automation.Remoting.PSRemotingTransportException] {
                    # As runtime goes up, the likely hood of computers being accessable then becoming inaccessable goes up
                    if ( $_.Exception.Message -imatch "that the computer is accessible over the network" ) {
                        Write-Host "  Target '$($Session.ComputerName.ToLower())' had a valid session but now appears to be offline" -ForegroundColor DarkYellow
                        }
                    else {
                        Write-host "  Error 1476: $($_.Exception.Message)" -ForegroundColor Red
                        } # end if
                    } # end try/catch
                } # next job

            Write-Host "Opened $(Pluralize -Quantify $Sessions -One '~~~Number~~~ session' -Many '~~~Number~~~ sessions')"
            # Write-Host "Opened $($Sessions.Count) sessions"
            Write-Output $Sessions
            $EndTime = Get-Date
            Write-Host "Ended '$($EndTime)' $([System.TimeZoneInfo]::Local.Id -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', ''), total runtime '$([Math]::Round(($EndTime - $StartTime).TotalMinutes, 2))' minutes" -ForegroundColor DarkGray
            } # end end
        } # end function Open-MultiPsSession



function Test-PsSession {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $Results = $Session | Test-PsSession
    param (
        [Parameter(mandatory=$false, Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } )
        ) # end if 
    begin {
        $Script = { 
            param ( 
                $MyTimeZone
                , $ExpectComputerName 
                , [Switch]$CheckPendingFileRenameOperationsCheck
                ) # end if 

            $Output = @{
                ComputerName = $env:COMPUTERNAME
                CorrectComputerName = $Env:ComputerName -ieq $ExpectComputerName
                } # end hash
            Write-host "  In Session with $($env:computername)" -ForegroundColor @{'True'='DarkGreen'; 'false'='Red'; ''='darkgray'}[[string]$Output.CorrectComputerName]

            $Output.LastBootUpTime = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime 
            $Output.LastBootUpTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($Output.LastBootUpTime, [System.TimeZoneInfo]::Local.Id, $MyTimeZone)
            Write-host "    LastBootUpTime = $($Output.LastBootUpTime) $($MyTimeZone -replace '(?:^\s*|(?<=\b[^ ])(?:(?<!\s\b).)*)', '')" -ForegroundColor DarkGray

            # check system reboot status
            $invokeWmiMethodParameters = @{
                Namespace    = 'root/default'
                Class        = 'StdRegProv'
                Name         = 'EnumKey'
                ComputerName = $env:COMPUTERNAME
                ErrorAction  = 'Stop'
                } # end hash

            $hklm = [UInt32] "0x80000002"
                    
            ## Query the Component Based Servicing Reg Key
            $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\')
            $Output.ComponentBasedServicing = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames -contains 'RebootPending'

            ## Query WUAU from the registry
            $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\')
            $Output.WindowsUpdateAutoUpdate = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames -contains 'RebootRequired'

            ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
            $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Services\Netlogon')
            $registryNetlogon = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames
            $Output.PendingDomainJoin = ($registryNetlogon -contains 'JoinDomain') -or ($registryNetlogon -contains 'AvoidSpnSet')

            ## Query ComputerName and ActiveComputerName from the registry and setting the MethodName to GetMultiStringValue
            $invokeWmiMethodParameters.Name = 'GetMultiStringValue'
            $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\', 'ComputerName')
            $registryActiveComputerName = Invoke-WmiMethod @invokeWmiMethodParameters

            $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\', 'ComputerName')
            $registryComputerName = Invoke-WmiMethod @invokeWmiMethodParameters

            $Output.PendingComputerRenameDomainJoin = $registryActiveComputerName -ne $registryComputerName -or $Output.PendingDomainJoin

            ## Query PendingFileRenameOperations from the registry
            if ( $PSBoundParameters.ContainsKey('CheckPendingFileRenameOperationsCheck'))  {
                $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\Session Manager\', 'PendingFileRenameOperations')
                $Output.PendingFileRenameOperationsValue = (Invoke-WmiMethod @invokeWmiMethodParameters).sValue
                $Output.PendingFileRenameOperations = [bool]$Output.PendingFileRenameOperationsValue
                } # end if

            ## Query ClientSDK for pending reboot status, unless SkipConfigurationManagerClientCheck is present
            if (-not $PSBoundParameters.ContainsKey('SkipConfigurationManagerClientCheck')) {
                $invokeWmiMethodParameters.NameSpace = 'ROOT\ccm\ClientSDK'
                $invokeWmiMethodParameters.Class = 'CCM_ClientUtilities'
                $invokeWmiMethodParameters.Name = 'DetermineifRebootPending'
                $invokeWmiMethodParameters.Remove('ArgumentList')

                try {
                    $sccmClientSDK = Invoke-WmiMethod @invokeWmiMethodParameters
                    $Output.SystemCenterConfigManager = $sccmClientSDK.ReturnValue -eq 0 -and ($sccmClientSDK.IsHardRebootPending -or $sccmClientSDK.RebootPending)
                    }
                catch {
                    $Output.SystemCenterConfigManager = $null
                    Write-Verbose -Message ($script:localizedData.invokeWmiClientSDKError -f $env:COMPUTERNAME) 
                    } # end try/catch
                } # end if

            $Output.IsRebootPending = [bool]($Output["ComponentBasedServicing", "PendingComputerRenameDomainJoin", "PendingDomainJoin", "PendingFileRenameOperations", "SystemCenterConfigManager", "WindowsUpdateAutoUpdate"] | Where-Object { $_ })

            $Output = [PSCustomObject]$Output
            Write-Output $Output

            # display output in stoplight color scheme
            $Color = @{'True'='Yellow'; 'false'='darkgreen'; ''='darkgray'}
            If ( $Output.IsRebootPending ) {
                write-host "    Reboot Pending" -ForegroundColor $Color[[string]$Output.IsRebootPending]
                $Indent = "      "
                ($Output | Select-Object "ComponentBasedServicing", "PendingComputerRenameDomainJoin", "SystemCenterConfigManager", "WindowsUpdateAutoUpdate", "IsRebootPending" | Format-List | Out-String) -replace "^\s+|\s+$" -split "\n" -replace "^",$Indent | ForEach-Object { write-host $_ -ForegroundColor $Color[( $_ -replace "^.*:\s+|\s+$", "")] }
                } 
            else {
                write-host "    Reboot not pending" -ForegroundColor darkgreen
                } # end if 

            } # end script
        } # end begin
    Process {
        foreach ( $Session in $Sessions ) {
            Invoke-Command -Session $Session -ScriptBlock $Script  -ArgumentList ([System.TimeZoneInfo]::Local.Id), ($Session | Format-ComputerName -Format "~~~ComputerName~~~")
            } # next Session 
        } # end process
    } # end function Test-PsSession



function Stop-ServiceInSession {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Stop-ServiceInSession -Service CcmExec | ft
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , 
        [Alias("Service", "Services")]
        [array]$ServiceNames = "CcmExec"
        ) # end if 
    begin {
        $Script = { 
            Param ( $ServiceName )
            ($s=Get-service -name $ServiceName | Where-Object{ $_.Status -ine 'Stopped'} ) | Select-Object Name, @{Name="When";e={"Before"}},Status,StartType
            $s | stop-Service
            $s | set-service -Status stopped -StartupType Disabled
            Get-service -name $ServiceName | Select-Object Name, @{Name="When";e={"After"}},Status,StartType
            } # end script
        } # end begin
    Process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            foreach ( $ServiceName in $ServiceNames ) {
                Invoke-command -Session $Session -scriptblock $Script -ArgumentList $ServiceName
                } # next ServiceName 
            } # next Session 
        } # end process
    } # end function Stop-ServiceInSession


function Start-ServiceInSession {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Start-ServiceInSession -Service CcmExec | ft
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , 
        [Alias("Service")]
        [array]$ServiceNames = "CcmExec"
        ) # end if 
    begin {
        $Script = { 
            Param ( $ServiceName )
            ($s=Get-service -name $ServiceName) | Select-Object Name, @{Name="When";e={"Before"}},Status,StartType
            $s | set-service -Status Running -StartupType Automatic
            Get-service -name $ServiceName | Select-Object Name, @{Name="When";e={"After"}},Status,StartType
            } # end script
        } # end begin
    Process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            foreach ( $ServiceName in $ServiceNames ) {
                Invoke-command -Session $Session -scriptblock $Script -ArgumentList $ServiceName
                } # next ServiceName 
            } # next Session 
        } # end process
    } # end function Start-ServiceInSession


function Get-FilesFromPsSession {
    # copies entire file folder from a session to the local machine
    # use case: get all CCM logs
    # The script will:
    #   1. copy the targeted files to a temp location. This bypasses the annoying "file in use error" when copying files remotely
    #   2. compress the files in the temp location. This makes the package much smaller and easier to transfer
    #   3. copy the compressed file 
    #   4. delete the files from the temp location
    #   5. unpack the local copy of the zip file
    #
    # Examples
    #   $session = Open-PsSession RC176.nm.nmfco.com
    #   $session | Get-FilesFromPsSession -CutoffDate (Get-Date).AddDays(-2) -RemoteSource "c:\windows\Ccm\Logs" -RemoteDestination "c:\Temp\Logs\Ccm" -Destination "x:\Temp\~~~SessionComputername~~~\"
    #   Explorer "x:\temp\$($session.ComputerName)"
    #
    #   Get the important logs
    #       $Logs = New-Object System.Collections.Generic.List[System.Object]
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CcmExec.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CcmMessaging.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CCMNotificationAgent.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CcmRestart.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CcmRepair.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\ClientIDManagerStartup.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\InventoryProvider.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\ClientLocation.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\LocationServices.log" )
    #       $Sessions | Get-FilesFromPsSession -RemoteSource $logs -DeletePreexistingZip
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , $CutoffDate = (Get-Date).AddYears(-20)
        , $RemoteSource = "c:\windows\Ccm\Logs"
        , $RemoteDestination = "c:\Temp\Logs\~~~SessionComputername~~~"
        , $Destination = "D:\Temp\RemoteLogs"
        , [switch]$DeletePreexistingZip # If false then a preexisting zip file will be updated with newer sub files, this will run a bit faster if you're always getting the same files
        ) # end param
    begin {
        $Script = {
            Param( $CutoffDate, $RemoteSource, $RemoteDestination, $RemoteZipFile, $DeletePreexistingZip )

            $RemoteDestination = $RemoteDestination -ireplace "~~~SessionComputername~~~", $ENV:Computername
            $RemoteZipFile = $RemoteZipFile -ireplace "~~~SessionComputername~~~", $ENV:Computername
            if ( $RemoteDestination -inotmatch "^\w:\\temp" ) { throw "Error 256: -RemoteDestination must be in a temp folder" }
            write-host "  In Session"

            if ( (Test-Path $RemoteZipFile) ) {
#            if ( (Test-Path $RemoteZipFile) -and $DeletePreexistingZip ) {
                write-host "    Removing preexisting zip file" -ForegroundColor DarkGray
                Remove-Item -Path $RemoteZipFile -Force
                } # end if 
            # change directory to a file system incase previous session commands left us in a non file system location. This avoids errors like "object reference not set to an instance of an object"
            Set-Location -Path $Env:SystemDrive

            # duplicate files to temporary holding
            write-host "    New-Item -ItemType Directory -Path $RemoteDestination -Force" -ForegroundColor DarkGray
            New-Item -ItemType Directory -Path $RemoteDestination -Force | out-null
            $Files = Get-Item -Path $RemoteSource | Get-ChildItem | Where-Object { $_.LastWriteTime -gt $CutoffDate }

            # confirm we have the necessary free space
            $TotalSize = $Files | ForEach-Object { [int]$_.length } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $Drive = Get-PsDrive -Name ( $RemoteDestination -replace ":.*$","" )
            if ( $Drive ) {
                if ( $TotalSize * 2.1 -ge $Drive.Free ) { Throw "    Error 0280: Drive on remote computer only has $([math]::Round($Drive.Free / 1mb,2))mb free, this operation is projected to need $([math]::Round($TotalSize * 2.1 / 1mb))mb free, no actions done" }
                $UsedPercent = $Drive.Used / ($Drive.Free + $Drive.Used) * 100
                if ( $UsedPercent -ge 90 ) { write-host "    Warning 0281: Drive '$($Drive.Name):' on remote computer has $([math]::Round($UsedPercent,2))% or $([math]::Round($Drive.Free /1gb))gb free recommend investigating free space." -ForegroundColor Yellow }
                } # end if 

            # Write-Host "Processing $(Pluralize -Quantify $Files -One "'$($Files.FullName)'" -Many '~~~Number~~~ total files')"
            write-host "    Copy-Item  -Path $($Files.Count) total files -Destination $RemoteDestination -Force" -ForegroundColor DarkGray
            write-host "    This operation is projected to use $([math]::Round($TotalSize * 2.1 / 1mb))mb of the available $([math]::Round($Drive.Free /1mb, 2))mb free space" -ForegroundColor DarkGreen
            Copy-Item  -Path $Files.FullName -Destination $RemoteDestination -Force

            # compress files for transport
            write-host "    Compress-Archive -Path $RemoteDestination -DestinationPath $RemoteZipFile -CompressionLevel Optimal -Update" -ForegroundColor DarkGray
            Compress-Archive -Path $RemoteDestination -DestinationPath $RemoteZipFile -CompressionLevel Optimal -Update

            # clean up 
            write-host "    Remove-Item -Path "$($RemoteDestination)\" -Recurse -Force" -ForegroundColor DarkGray
            Remove-Item -Path "$($RemoteDestination)\" -Recurse -Force
            # leave the zip file incase we re-run then the previous zip file will just be freshened
            # Remove-Item -Path $RemoteZipFile -Force
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            # script block will collect all files and place them into the designated remote location
            $ThisRemoteDestination = $RemoteDestination -ireplace "~~~SessionComputername~~~", $session.ComputerName
            $ThisRemoteZipfile = $ThisRemoteDestination -ireplace "~~~SessionComputername~~~", $session.ComputerName -ireplace "\\*$", ".zip" 
            Invoke-Command -Session $Session -Scriptblock $Script -ArgumentList $CutoffDate, $RemoteSource, $ThisRemoteDestination, $ThisRemoteZipfile, $DeletePreexistingZip

            # Transfer zip file to here
            $ThisDestination = $Destination -ireplace "~~~SessionComputername~~~", $session.ComputerName -ireplace "\\*$", ""

            CopyItemFromSession -FromSession $Session -RemoteFile $ThisRemoteZipfile -Destination $ThisDestination

            UnpackZipFile -ZipFile "$($ThisDestination)\$($ThisRemoteZipfile | Split-Path -Leaf)" -Destination $ThisDestination

            } # next session
        } # end process
    } # end function Get-FilesFromPsSession
function Get-FilesFromMultiPsSession {
    # Examples
    #   Create a sessions
    #       $Data = Get-SccmCheckinDates -Top 100 -Where "'$((Get-Date).AddHours(-3))' < LastPolicyRequest AND LastHardwareScan < '$((Get-Date).AddDays(-7))'"
    #       $sessions = $Data | Open-MultiPsSession 
    #
    #   All files written in the past 1 days
    #       $Sessions | Get-FilesFromMultiPsSession -Cutoff $(Get-Date).AddDays(-1)
    #
    #   Get only the CcmMessaging.log file
    #       $Sessions | Get-FilesFromMultiPsSession -RemoteSource c:\windows\Ccm\Logs\CcmMessaging.log -DeletePreexistingZip
    #
    #   Get the important logs
    #       $Logs = New-Object System.Collections.Generic.List[System.Object]
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CcmExec.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CcmMessaging.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CCMNotificationAgent.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CcmRestart.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\CcmRepair.log" )
    #       [void]$Logs.Add( "c:\windows\Ccm\Logs\InventoryProvider.log" )
    #       $Sessions | Get-FilesFromMultiPsSession -RemoteSource $logs -DeletePreexistingZip
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [alias("Sessions")]
        $Targets = $( get-pssession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , $CutoffDate = (Get-Date).AddYears(-20)
        , $RemoteSource = "c:\windows\Ccm\Logs"
        , $RemoteDestination = "c:\Temp\Logs\~~~SessionComputername~~~"
        , $Destination = "D:\temp\RemoteLogs"
        , [switch]$DeletePreexistingZip # If false then a preexisting zip file will be updated with newer sub files, this will run a bit faster if you're always getting the same files

        , $ThrottleLimit = 25
        , 
        [alias("Credential")] # the script will accept either a custom credential or PsCredential object, this makes VSCode code checker happy
        $CC = [CustomCredential]::New("$($Env:UserDomain)\$($Env:Username -ireplace '-.*$',"-$($Env:UserDomain)")")
        ) # end Param
    begin {
        # yes we could use the #Requires commmand but that would invalidate the entire script instead of just this one function
        if ( $PsVersiontable.PsVersion -le [system.version]"7.0" ) { throw "error 1565: Get-FilesFromMultiPsSession requires Powershell version 7. This is being run in powershell version '$($PsVersionTable.PsVersion)' on '$($Env:Computername)'" } # end if
        $AllTargets = New-Object System.Collections.Generic.List[System.Object]
        if ( $CC -is [PsCredential] ) {
            $CC = [CustomCredential]::New($CC)
            } # end if

        $Script = {
            #Include Variable CutoffDate
            #Include Variable RemoteSource
            #Include Variable RemoteDestination
            #Include Variable Destination
            #Include Variable Credential
            #Include Variable DeletePreexistingZip
            # skip Include Function Get-FilesFromPsSession
            # skip Include Function Pluralize

            Import-Module Open-PsSession -DisableNameChecking

            $PsSessionOptions = @{
                cred = $Credential
                UseSSL = $True
                } # end hash

            $_ | New-PsSession @PsSessionOptions | Get-FilesFromPsSession -CutoffDate $CutoffDate.Value -RemoteSource $RemoteSource -RemoteDestination $RemoteDestination -Destination $Destination
            } # end script
        $Script = Optimize-PackScript -Script $Script -Variable @{DeletePreexistingZip=[int][bool]$DeletePreexistingZip; CutoffDate=$CutoffDate; RemoteSource=$RemoteSource; RemoteDestination=$RemoteDestination; Destination=$Destination; Credential=$CC}
        } # end begin
    Process {
        foreach ( $Entry in $Targets | Format-ComputerName -Format "~~~ComputerName~~~.~~~Domain~~~" ) {
            [void]$AllTargets.Add( $Entry ) 
            } # next entry
        } # end process
    End {
        Write-Host "Processing $(Pluralize -Quantify $AllTargets -One '~~~Number~~~ record' -Many '~~~Number~~~ records')"
        # write-host "Processing $($AllTargets.count) records"
        $Jobs = $AllTargets | Foreach-Object -Parallel $Script -ThrottleLimit $ThrottleLimit -AsJob

        # the sessions created inside the foreach -Parallel command will be valid sessions but only from inside their respective multi-treaded session
        # we need to open those sessions here, which will require an additional step
        $Jobs | Wait-Job | Receive-Job
        } # end end
    } # end function Get-FilesFromMultiPsSession


function Get-EventLogFromSession {
    # $session = Open-PsSession n8302.nm.nmfco.com
    # $session | Get-EventLogFromSession -Lognames "Microsoft-Windows-NetworkProfile/Operational"
    # Explorer "x:\temp\$($session.ComputerName)"
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        $Sessions = $( get-pssession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )
        , [array]$Lognames = "Microsoft-Windows-NetworkProfile/Operational"
        , $RemoteDestination = "$($Env:SystemDrive)\Temp\"
        , $Filename = $($Logname -replace '/','_')
        , $Destination = "D:\Temp\RemoteLogs\~~~SessionComputername~~~\"
        ) # end if 
    begin {
        $Script = {
            Param (
                $Logname = "Microsoft-Windows-NetworkProfile/Operational"
                , $Filename = $($Logname -replace '/','_')
                , $RemoteDestination = "$($Env:SystemDrive)\Temp\"
                ) # end param
            write-host "  In Session"
            Set-Location $env:SystemDrive
            write-host "    get-winevent -logname '$($Logname)'" -ForegroundColor DarkGray
            get-winevent -logname $Logname | Select-Object TimeCreated, ProviderName, Id, @{n='Message';e={$_.Message -replace '\s+', " "}} | Export-CSV -Path "$($RemoteDestination)\$($Filename).csv" -NoTypeInformation -Force 
            write-host "    Compress log to $($RemoteDestination)\$($Filename).zip" -ForegroundColor DarkGray
            Compress-Archive -Path "$($RemoteDestination)\$($Filename).csv" -DestinationPath "$($RemoteDestination)\$($Filename).zip" -CompressionLevel Optimal -Update
            # clean up 
            write-host "    Remove-Item -Path ""$($RemoteDestination)\$($Filename).csv"" -Recurse -Force" -ForegroundColor DarkGray
            Remove-Item -Path "$($RemoteDestination)\$($Filename).csv" -Recurse -Force
            write-output "$($RemoteDestination)\$($Filename).zip"
            } # end script
        } # end begin
    process {
        foreach ( $Session in $Sessions ) {
            Write-Host "$($session.ComputerName)"
            $ThisDestination = $Destination.Replace("~~~SessionComputername~~~", $session.ComputerName) -ireplace "\\*$", ""
            foreach ( $Logname in $Lognames ) {
                $ThisRemoteZipfile = Invoke-command -Session $Session -ScriptBlock $Script -ArgumentList $Logname

                CopyItemFromSession -FromSession $Session -RemoteFile $ThisRemoteZipfile -Destination $ThisDestination

                UnpackZipFile -ZipFile "$($ThisDestination)\$($ThisRemoteZipfile | Split-Path -Leaf)" -Destination $ThisDestination

                } # next logname
            } # next session 
        } # end process
    } # end function Get-EventLogFromSession


function CopyItemFromSession {
    param (
        $FromSession
        , $RemoteFile
        , $Destination
        ) # end param
    write-host "  Copy-Item -FromSession `$Session -Path ""$RemoteFile"" -Destination ""$($Destination)\"" -Force" -ForegroundColor DarkGray
    if ( -not ( Test-Path $Destination ) ) {
        write-host "  New-Item -ItemType Directory -Path $Destination -Force" -ForegroundColor DarkGray
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        } # end if 
    Copy-Item -FromSession $Session -Path $RemoteFile -Destination "$($Destination)\" -Force 
    } # end function CopyItemFromSession


function Invoke-ScriptInMultiPsSession {
    # Examples
    #   Create a sessions
    #       $Data = Get-SccmCheckinDates -Top 100 -Where "'$((Get-Date).AddHours(-3))' < LastPolicyRequest AND LastHardwareScan < '$((Get-Date).AddDays(-7))'"
    #       $Sessions = $Data | Open-MultiPsSession 
    #
    #   Construct the script block you'd like to run remotely
    #   Note, to diferentiate where each result is from you need to add a custom NoteProperty, this will make reporting back easier
    #       $Scriptblock = { 
    #           $Processes = Get-Process | Sort-Object Cpu | select-Object -first 5 
    #           $Processes | Foreach-Object { Add-Member -InputObject $_ -NotePropertyName FromSession -NotePropertyValue $env:computername }
    #           $Processes
    #           }
    #       $Scriptblock = { 
    #           $Items = Get-childItem c:\temp\
    #           $Items | Foreach-Object { Add-Member -InputObject $_ -NotePropertyName FromSession -NotePropertyValue $env:computername }
    #           $Items
    #           }
    #
    #   Run your script against the remote systems and collect the results. 
    #   Note the select statement is required to show all the fields, to include the custom field we added in the base script
    #       $Results = $Sessions | Invoke-ScriptInMultiPsSession -Scriptblock $Scriptblock
    #       $Results | Select * | Out-Gridview -Title "From Invoke-ScriptInMultiPsSession"
    #
    param (
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [alias("Sessions")]
        $Targets = $( get-pssession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Sort-Object Computername -unique )

        , 
        [Parameter(Mandatory=$True)]
        [scriptblock]$Scriptblock

        , $ThrottleLimit = 25
        ) # end Param
    begin {
        # yes we could use the #Requires commmand but that would invalidate the entire script instead of just this one function
        if ( $PsVersiontable.PsVersion -le [system.version]"7.0" ) { throw "error 1565: Get-FilesFromMultiPsSession requires Powershell version 7. This is being run in powershell version '$($PsVersionTable.PsVersion)' on '$($Env:Computername)'" } # end if
        $AllTargets = New-Object System.Collections.Generic.List[System.Object]

        } # end begin
    Process {
        foreach ( $Entry in $Targets | Format-ComputerName -Format "~~~ComputerName~~~.~~~Domain~~~" ) {
            [void]$AllTargets.Add( $Entry ) 
            } # next entry
        } # end process
    End {
        Write-Host "Processing $(Pluralize -Quantify $AllTargets -One '~~~Number~~~ record' -Many '~~~Number~~~ records')"
        # write-host "Processing $($AllTargets.count) records"
        $Jobs = $AllTargets | Foreach-Object -Parallel $ScriptBlock -ThrottleLimit $ThrottleLimit -AsJob

        # collect the results of each job
        # note each job will have lost the context where it was running, so we need to include context inside the raw script
        $Jobs | Wait-Job | Receive-Job
        } # end end
    } # end function Get-FilesFromMultiPsSession

