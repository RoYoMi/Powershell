function ConvertTo-Hashtable {
    # takes a PScustomObject with nested values, and converts it to a Hashtable
    # https://4sysops.com/archives/convert-json-to-a-powershell-hash-table/
    [CmdletBinding()]
    [OutputType('hashtable')]
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
        ) # end param
    process {
        ## Return null if the input is null. This can happen when calling the function
        ## recursively and a property is null
        if ($null -eq $InputObject) {
            return $null
            } # end if
        ## Check if the input is an array or collection. If so, we also need to convert
        ## those types into hash tables as well. This function will convert all child
        ## objects into hash tables (if applicable)
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $collection = @(
                foreach ($object in $InputObject) {
                    ConvertTo-Hashtable -InputObject $object
                    } # next object
                ) # end collection
            ## Return the array but don't enumerate it because the object may be pretty complex
            Write-Output -NoEnumerate $collection
            }
        elseif ($InputObject -is [psobject]) { ## If the object has properties that need enumeration
            ## Convert it to its own hash table and return it
            $hash = @{}
            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertTo-Hashtable -InputObject $property.Value
                } # next property
            $hash
            } 
        else {
            ## If the object isn't an array, collection, or other object, it's already a hash table
            ## So just return it.
            $InputObject
            } # end if
        } # end process
    } # end function

function Format-ComputerName {
    # helper function to boil objects down to just names. 
    # This will accept an object and will attempt to make sense of it.
    # Currently supported: Powershell Sessions, Get-CmDevice, Hashtables with "name" field, [,;] delimited strings
    # examples:
    #   $session | Format-ComputerName | Open-PsSession
    #   $sessions | Format-ComputerName -Format "~~~ComputerName~~~"
    param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [alias("ResourceName", "Device", "Computer", "ComputerName", "FQDN", "Session")]
        $Targets
        , $Format = "~~~ComputerName~~~.~~~Domain~~~"
        , $DefaultDomain = $Env:UserDnsDomain
        ) # end param
    begin {
        } # end begin
    process {
        foreach ( $Target in $Targets ) {
            $Records = if ( $Target.Gettype().Name -ieq "PSSession" ) {
                $Target.Computername
                } 
            elseif ( $Target -is [PsObject] -and $Target.__Class -ieq "SMS_R_System" ) {
                $Target.Name
                }
            elseif ( $Target -is [System.Data.DataRow] -and ($Target | gm -Type Property -Name Name) ) {
                $Target.Name
                }
            elseif ( $Target -is [IpAddress] ) {
                write-Output $Target
                break
                } 
            elseif ( $Target -is [string] ) {
                $Target -split "\s*[ ,;]\s*"
                } 
            elseif ( $Target | gm -type Property -Name Name ) {
                $Target.Name
                }
            elseif ( $Target | gm -type NoteProperty -Name Name ) {
                $Target.Name
                }
            else {
                ""
                } # end if

            foreach ( $Record in $Records ) {
                if ( $Record -imatch "^\s*(?<ComputerName>[^.]+)(?:\.(?<domain>[^.]+.*?))\s*$" ) {
                    $Format -iReplace "~~~ComputerName~~~", $Matches.ComputerName.ToLower() -iReplace "~~~Domain~~~", $Matches.Domain.ToLower()
                    }
                elseif ( $Record -imatch "^\s*(?<computername>[^.]+)\s*$" ) {
                    $Format -iReplace "~~~ComputerName~~~", $Matches.ComputerName.ToLower() -iReplace "~~~Domain~~~", $DefaultDomain.ToLower()
                    }
                else {
                    $Record
                    } # else 
                } # next Record
            } # next target
        } # end process
    } # end function Format-ComputerName


Function Get-FileLock {
    # locks a file
    # depreciated, use Class_CustomFile instead
    # $Lock = Get-FileLock -File "$($Env:systemdrive)\temp\Hosts.lock" 
    Param ( 
        $File = "$($Env:systemdrive)\temp\Hosts.lock"
        , $TimeOut = 300
        ) # end param

    $TimeoutAfter = (Get-Date).AddSeconds($TimeOut)
    # get the file open and locked
    do {
        Try { 
            $Lock = [System.IO.File]::Open($File, "OpenOrCreate", "ReadWrite", "None")
            }
        catch {
            if ( $_.Exception.Message -imatch "Access to the path '[^']+' is denied" ) { 
                $AccessDenied = $true
                Throw "    Error 0151: $($_.Exception.Message)" 
                }
            if ( $TimeoutAfter -lt (Get-Date) ) { 
                throw "    Error 0152: Get-FileLock failed to get exclusive file lock on '$File' after '$Timeout' seconds" 
                }
            # wait a random length of time to prevent paralell collisions
            start-sleep -Milliseconds $(get-Random -Minimum 100 -Maximum 200)
            }
        } until ( ($Lock.CanRead -and $Lock.CanWrite) -or $AccessDenied )
    write-output $Lock 
    } # end funcion Get-FileLock


function Get-RandomCharacters {
    param (
        [array]$Strings = "a".."z" + "A".."Z" + 0..9
        , [int]$Count = 10
        ) # end param
    ( 1..$Count | %{ $Strings | get-random } ) -join ""
    } # end function Get-RandomCharacters


function Optimize-PackScript {
    # Sending scripts to remote workstations wont have all the necessary functions for them, or access to modules installed here.
    # The foreach-object -Parallel -AsJob creates a new instance and won't have a access to things defined in the local instance.
    # therefore all objects need to be included in the script block
    # this function automates the process of embeddeding objects into the a script block
    # The Using: construct has limitations, like you can't insert variables and objects into other preexisting functions
    # whereas this contruct can be embedded into an original function where it'll remain a comment until packed. 
    # once packed the comment will be replaced, This can be used to override function parameters
    #
    # Insert syntax:
    #   #Include-InsertFunctionsHere
    #       - Can only be declared once
    #       - is the location where all functions will be inserted so they're not nested inside other functions
    #       - if not included then functions will be inserted at the "#Include function <name>" is located
    #   #Include Variable [<Name>]
    #       - Variable is passed into Optimize-PackScript via -Variable param, this is a hash table without complex methods
    #       - Name is optional, 
    #           - if provided then $Variable.Name will be packed, and will be inserted with the name as the variable name
    #           - if not provided then the entire $Variable will be used, and will be inserted with "$Variable" as the variable name
    #   #Include Variable <FunctionName> <Name>
    #       - Variable is passed into Optimize-PackScript via -Variable param, this is a hash table without complex methods
    #       - FunctionName is a subkey from the -Variable param. This allows different values of the same name to be packed, and is useful if multipl functions are being included
    #   #Include Global <Name>
    #       - Insert a global variable as a global variable
    #       - Name will be used as the name of the global variable, example: "`$Global:<Name> = $Global:<Name> | ConvertTo-Json" will be inserted
    #   #Include Function <Name>
    #       - Inserts an already declaired function of the provided name. 
    #       - This should be limited to only functions defined in the script and not actual commandlets.
    #   #Include Class <Name>
    #       - Insert the Class source code, pulled from $Global:ClassLibrary[name]
    # Insert types: 
    # example
    #    if ( $PsVersiontable.PsVersion -le [system.version]"7.0" ) { throw "error 0298: Powershell version 7 is required. This is being run in powershell version '$($PsVersionTable.PsVersion)' on '$($Env:Computername)'" } # end if
    #    $global:Test = "this is a global test value"
    #    $script = {
    #        #Include Variable Bravo
    #        #Include Global Test
    #        #Include function Get-RandomCharacters
    #        #Include Variable
    #        #Include-InsertFunctionsHere
    #        write-host "username = '$($env:Username)'"
    #        foreach ( $Step in 1..5 ) {
    #            $Color = @{'1'='red';'2'='yellow';'3'='cyan';'4'='magenta';'5'='green'}
    #            write-host "Job $_" -ForegroundColor $Color[[string]$_] -NoNewLine
    #            write-host " Step $Step : " -ForegroundColor $Color[[string]$Step] -NoNewLine
    #            write-host $( Get-RandomCharacters ) -ForegroundColor $Color[[string]$(1..5 | get-random)] 
    #            sleep 0.1
    #            } # next step
    #        } # end script
    #    $Script = Optimize-PackScript -Script $Script -Variable @{a=1;b=2;c=3;Bravo="fourth"}
    #    $Job = 1..5 | ForEach-Object -Parallel $Script -ThrottleLimit 5 -AsJob 
    #    $job | Wait-Job | Receive-Job 

<#
            #Include function Open-PsSession
            #Include function Format-ComputerName
            #Include function Get-DeviceFromSccm
            #Include function Set-HostEntry
            #Include function Remove-HostEntry
            $Script = {
            #Include-InsertFunctionsHere
            #Include function Format-ComputerName
            #Include function Get-DeviceFromSccm
            #Include function Set-HostEntry
            #Include function Remove-HostEntry
                } # end script
Optimize-PackScript -Script $Script

    while ( $String -imatch "(?m)^[ \t]*(?<Entry>[#]Include[ \t]+(?:(?<Type>Function)[ \t]+(?<Name>[-_a-z0-9]+)|(?<Type>Variable)(?:[ \t]+(?<FunctionName>[-_a-z0-9]+)(?=[ \t]+[a-z0-9]))?(?:[ \t]+(?<Name>[a-z0-9].*?))?|(?<Type>Global)[ \t]+(?<Name>[-_a-z0-9]+)))[ \t]*$" ) {
    while ( $String -imatch "(?m)^[ \t]*(?<Entry>[#]Include[ \t]+(?:(?<Type>Function)[ \t]+(?<Name>[-_a-z0-9]+)))[ \t]*$" ) {
#Include-InsertFuctionsHere
#Include-InsertFunctionsHere
#>
    param (
        [scriptblock]$Script
        , [PSCustomObject]$Variable # provide a hashtable or pscustomobject, keep it simple since this won't support complex objects with methods
        , [switch]$Quiet
        ) # end param
    write-host "Optimize-PackScript for mulithreading" -ForegroundColor DarkGray
    $String = $Script.ToString()
    $JsonOptions = @{Compress=$True; Depth=50}

    # find includes https://regex101.com/r/pzu86H/2
    [hashtable]$DuplicateTracker = @{}
    while ( $String -imatch "(?m)^[ \t]*(?<Entry>[#]Include[ \t]+(?:(?<Type>Function|Class)[ \t]+(?<Name>[-_a-z0-9]+)|(?<Type>Variable)(?:[ \t]+(?<FunctionName>[-_a-z0-9]+)(?=[ \t]+[a-z0-9]))?(?:[ \t]+(?<Name>[a-z0-9].*?))?|(?<Type>Global)[ \t]+(?<Name>[-_a-z0-9]+)))[ \t]*(?=[\r\n]|$)" ) {
        $Include = $Matches
        switch ( $Include.Type ) {
            "Class" {
                if ( -not $Quiet ) {
                    write-host "  Adding '$($Include.Entry)'" -foregroundcolor DarkGray
                    } # end if
                $ReplaceWith = if ( $DuplicateTracker.$($Include.Entry) -lt 1 ) {
                    # read the source class
                    $ClassFile = $env:PSModulePath -split ";" | get-childitem -recurse -include "$($Include.Name).psm1" | select -first 1
                    if ( $ClassFile ) {
                        ($ClassFile | Get-Content) -join "`n"
                        } `
                    else {  
                        write-host "    Warning 1802: could not find $($Include.Type):$($Include.Name)"
                        # $String = $String.Replace($Include.Entry, "#ReplaceError:$($Include.Entry)"
                        "#ReplaceError 1802:$($Include.Entry)"
                        } # end if
                    }
                else {
                    # write-host "    Warning 1966: Duplicate entry '$($Include.Entry)' found, likely caused by a circular reference"
                    "#ReplaceError 1966:$($Include.Entry)"

                    } # end if
                $DuplicateTracker.$($Include.Entry) += 1
                if ( $String -imatch "(?m)^(?<Entry>[ \t]*#Include-InsertFunctionsHere[ \t]*(?:[\r\n]|$))" ) {
                    $InsertHere = $Matches
                    $ReplaceWith += "`n$($InsertHere.Entry)"
                    $String = $String.Replace($InsertHere.Entry, $ReplaceWith)
                    $String = $String.Replace($Include.Entry, "")
                    }
                else {
                    $String = $String.Replace($Include.Entry, $ReplaceWith)
                    } # end if
                break
                } # end function
            "Function" {
                if ( -not $Quiet ) {
                    write-host "  Adding '$($Include.Entry)'" -foregroundcolor DarkGray
                    } # end if
                $ReplaceWith = if ( $DuplicateTracker.$($Include.Entry) -lt 1 ) {
                    if ( $Insert = Get-Command -Name $Include.Name | select -ExpandProperty ScriptBlock ) {
                        # prevent recursion
                        $Insert = $Insert.ToString().Replace($Include.Entry, "")
                        # $String = $String.Replace($Include.Entry, "function $($Include.Name) { $($Insert) } # end function $($Include.Name)")
                        "function $($Include.Name) { $($Insert) } # end function $($Include.Name)"
                        }
                    else {  
                        write-host "    Warning 1802: could not find $($Include.Type):$($Include.Name)"
                        # $String = $String.Replace($Include.Entry, "#ReplaceError:$($Include.Entry)"
                        "#ReplaceError 1802:$($Include.Entry)"
                        } # end if
                    }
                else {
                    # write-host "    Warning 1966: Duplicate entry '$($Include.Entry)' found, likely caused by a circular reference"
                    "#ReplaceError 1966:$($Include.Entry)"

                    } # end if
                $DuplicateTracker.$($Include.Entry) += 1
                if ( $String -imatch "(?m)^(?<Entry>[ \t]*#Include-InsertFunctionsHere[ \t]*(?:[\r\n]|$))" ) {
                    $InsertHere = $Matches
                    $ReplaceWith += "`n" + $InsertHere.Entry
                    $String = $String.Replace($InsertHere.Entry, $ReplaceWith)
                    $String = $String.Replace($Include.Entry, "")
                    }
                else {
                    $String = $String.Replace($Include.Entry, $ReplaceWith)
                    } # end if
                break
                } # end function
            "Variable" {
                $ReplaceWith = if ( $Include.FunctionName ) {
                    if ( $Variable.ContainsKey($Include.FunctionName) ) {
                        if ( $Variable.$($Include.FunctionName).ContainsKey($Include.Name) ) {
                            if ( $Variable.$($Include.FunctionName).$($Include.Name) -is [CustomCredential] ) {
                                $Insert = $Variable.$($Include.FunctionName).$($Include.Name).ToPack()
                                "`$$($Include.Name) = $($Insert)"
                                }
                            elseif ( $Variable.$($Include.FunctionName).$($Include.Name) -is [scriptblock] ) {
                                $Insert = $Variable.$($Include.FunctionName).$($Include.Name).ToString()
                                "`$$($Include.Name) = [Scriptblock]::Create( @'`n$($Insert)`n'@ )"
                                }
                            else {
                                $Insert = $Variable.$($Include.FunctionName).$($Include.Name) | ConvertTo-Json @JsonOptions
                                "`$$($Include.Name) = ConvertFrom-Json -InputObject @'`n$($Insert)`n'@"
                                } # end if
                            } 
                        else {
                            write-host "    Warning 1907: '$($Include.Entry)' found but no matching value in `$Variable"
                            "#ReplaceError 1907:$($Include.Entry)"
                            } # end if
                        }
                    else {
                        write-host "    Warning 1912: '$($Include.Entry)' found but no matching value in `$Variable"
                        "#ReplaceError 1912:$($Include.Entry)"
                        } # end if 
                    }
                Elseif ( $Include.Name ) {
                    if ( $Variable.ContainsKey($Include.Name) ) {
                        if ( $Variable.$($Include.Name) -is [CustomCredential] ) {
                            $Insert = $Variable.$($Include.Name).ToPack()
                            "`$$($Include.Name) = $($Insert)"
                            }
                        elseif ( $Variable.$($Include.Name) -is [int] ) {
                            $Insert = $Variable.$($Include.Name)
                            "`$$($Include.Name) = $($Insert)"
                            }
                        elseif ( $Variable.$($Include.Name) -is [string] ) {
                            $Insert = $Variable.$($Include.Name)
                            "`$$($Include.Name) = ""$($Insert)"""
                            }
                        else {
                            $Insert = $Variable.$($Include.Name) | ConvertTo-Json @JsonOptions
                            "`$$($Include.Name) = ConvertFrom-Json -InputObject @'`n$($Insert)`n'@"
                            } # end if 
                        }
                    else {
                        write-host "    Warning 2000: '$($Include.Entry)' found but no matching value in `$Variable'"
                        "#ReplaceError 2000:$($Include.Entry)"
                        } # end if
                    }
                else {
                    if ( $Insert = $Variable | ConvertTo-Json @JsonOptions ) {
                        # prevent recursion
                        $Insert = $Insert.ToString().Replace($Include.Entry, "")
                        "`$Variable = ConvertFrom-Json -InputObject @'`n$($Insert)`n'@"
                        } `
                    else {
                        write-host "    Warning 2017: -Variable value was converted to a null string"
                        "#ReplaceError 2017:$($Include.Entry)"
                        } # end if 
                    } # end if
                if ( -not $Quiet ) {
                    write-host "  Adding '$($ReplaceWith -replace '`n','')'" -foregroundcolor DarkGray
                    } # end if
                $String = $String.Replace($Include.Entry, $ReplaceWith)
                break
                } # end Variable
            "Global" {
                $ReplaceWith = if ( Test-Path Variable:Global:$($Include.Name) ) {
                    $Value = Get-Variable -Scope Global -Name $Include.Name | select -ExpandProperty Value
                    if ( $Value -is [CustomCredential] ) {
                        $Insert = $Value.ToPack()
                        "`$Global:$($Include.Name) = $Insert"
                        }
                    else {
                        $Insert = $Value | ConvertTo-Json @JsonOptions
                        "`$Global:$($Include.Name) = ConvertFrom-Json -InputObject @'`n$($Insert)`n'@"
                        } # end if
                    }
                else {
                    write-host "  Warning 1941: '$($Include.Entry)' Refereced global but the actual global variable does not exist."
                    "#ReplaceError 1941:$($Include.Entry)"
                    } # end if
                if ( -not $Quiet ) {
                    write-host "  Adding '$($ReplaceWith -replace '`n','')'" -foregroundcolor DarkGray
                    } # end if
                $String = $String.Replace($Include.Entry, $ReplaceWith)
                break
                } # end Variable
            default { write-host "   Warning 1998: found '$($Include.Entry)' but couldn't process it" }
            } # end switch
        } # loop
    [Scriptblock]::Create($String)
    } # end function Optimize-PackScript



function Pluralize {
    # returns a singular or plural form of a string to improve readabilty
    # -Quantify  can be a number, hashtable, array, or list
    # if -quanfity is a string and contains one or more non-space characters then it is conisdered to be 1, if it contains zero non-space characters then it is zero
    # examples
    #   $a = -2..3 | get-random; write-host "$(Pluralize -Quantify $a -One '~~~Number~~~ record was' -Many '~~~Number~~~ records were') found"
    #        0 records were found
    #        1 record was found
    #        2 records were found
    #        3 records were found
    param (
        $Quantify
        , [string]$One = '~~~Number~~~ record was'
        , [string]$Many = '~~~Number~~~ records were'
        ) # end param
    [int]$Number = if ( $Quantify -is [array] -or $Quantify -is [System.Collections.Generic.List[System.Object]] ) { $Quantify.Count }
    elseif ( $Quantify -is [hashtable] ) { $Quantify.Keys.Count }
    elseif ( $Quantify -is [string] ) { if ( $Quantify -imatch '[^ \r\n\t]' ) { 1 } else { 0 } }
    else { $Quantify.count }
    $Output = if ( [math]::abs($Number) -eq 1 ) { $One } else { $Many }
    write-output $($Output -ireplace "~~~Number~~~", $Number)
    }  # end function Pluralize

function Set-HostEntry {
    # when running in parallel, simply modifying the hosts file could clobber settings via a race condition
    # create a lock file on a temporary file, not the real file you're looking to edit
    # 
    # examples
    #   Set-HostEntry -LockFile "$($Env:systemdrive)\temp\Hosts.lock" -Name B4565 -IP 10.184.169.12 -Note "Created for Open-PsSession, delete me"
    #
    # this function will:
    #   create a lock file
    #   if the file is already locked then wait until timeout for the file to be unlocked, if timeout reached then throw an error
    #   add the entry to the file
    #   unlock the file 
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name

        , [Parameter(Mandatory=$true)]
        [IpAddress]$IP 

        , [Parameter(Mandatory=$True)]
        [string]$Note

        , $HostsFile = "$($Env:windir)\System32\Drivers\etc\hosts"
        , $LockFile = "$($Env:systemdrive)\temp\Hosts.lock"
        , $TimeOut = 300
        ) # end param
    # skip Include Function Get-FileLock
    # write-host "    Inserting '$($IP)' = '$($Name)' into file '$($HostsFile)'" -ForegroundColor DarkGray

    # get the hosts file open and locked
    $Lock = Get-FileLock -File $LockFile

    try {
        if ( $Lock.CanRead -and $Lock.CanWrite ) {
            # create host entry
            $NewHostsEntry = "$IP   $Name   # $Note"

            # read the file contents
            $BeforeContent = Get-Content $HostsFile

            # remove any previous entries for this name from the file
            # add the entry to the hosts file
            $Hosts = ( $BeforeContent | Where-Object { $_ -inotmatch "^[ \t]*(?<ip>[0-9.]*)[ \t]+(?<name>$($Name))[ \t]+(?:#|$)" } ) + $NewHostsEntry

            # save the file
            $Hosts | Set-Content $HostsFile
            } # end if 
        }
    catch {
        write-error $_
        }
    finally {
        # release the file
        $Lock.Close()
        $Lock.Dispose()
        } # end try/catch
    } # end fucntion Set-HostEntry


function Invoke-SQL {
    # $a = Invoke-SQL
    #    $SqlStatment = "select  rSys.name0 as 'MachineName' , HINV.LastHardwareScan as 'SCCM_LastHWscan' , SINV.LastSoftwareScan as 'SCCM_LastSWscan' from CM_$($DatabaseName).dbo.v_R_System rSys left join CM_$($DatabaseName).dbo.vWorkstationStatus HINV on rSys.ResourceID = HINV.ResourceID left join CM_$($DatabaseName).dbo.vSoftwareInventoryStatus SINV on rSys.ResourceID = SINV.ResourceID ~~~Where~~~" 
    #    $SqlStatment -ireplace "~~~Where~~~", "where rSys.name0 = '~~~DeviceName~~~'"
    #    $SqlData = Invoke-SQL -SqlStatement $SqlStatement
    param(
        [string]$DataSource = @{""="ntdbph8012m00.nm.nmfco.com"; "NM"="ntdbph8012m00.nm.nmfco.com"; NMTEST="ntdbth7965m00"; NMDEV="ntapdh7589m00"}[[string]$env:UserDomain]
        , [string]$Database = @{""="CM_NM1"; "NM"="CM_NM1"; NMTEST="CM_NMT"; NMDEV="CM_NMD"}[[string]$env:UserDomain]

        # https://github.com/TheEmptyGarden/ConfigMgr/blob/master/ConfigMgr-MachineDetail.sql 
        , [string]$SqlStatement = @"
select 
	rSys.name0 as 'MachineName'
	, HINV.LastHardwareScan as 'SCCM_LastHWscan'
	, SINV.LastSoftwareScan as 'SCCM_LastSWscan'
from $($Database).dbo.v_R_System rSys
left join $($Database).dbo.vWorkstationStatus HINV on rSys.ResourceID = HINV.ResourceID
left join $($Database).dbo.vSoftwareInventoryStatus SINV on rSys.ResourceID = SINV.ResourceID
where rSys.name0 = 'rf830'
"@
        ) # end param

    # write-host "  Invoke-SQL: $($SqlStatement)"
    $ConnectionString = "Data Source=$DataSource; Integrated Security=SSPI; Initial Catalog=$Database"

    $Connection = New-Object System.Data.SqlClient.SqlConnection( $ConnectionString )
    $Command = New-Object System.Data.SqlClient.SqlCommand( $SqlStatement,$connection )
    $Connection.Open()
    
    $Adapter = New-Object System.Data.SqlClient.SqlDataAdapter $Command
    $Dataset = New-Object System.Data.DataSet
    $Adapter.Fill($DataSet) | Out-Null
    
    $Connection.Close()
    $DataSet.Tables
    } # end if Invoke-SQL




function Remove-HostEntry {
    # when running in parallel, simply modifying the hosts file could clobber settings
    # create a lock file on a temporary file, not the real file you're looking to edit
    # 
    # examples
    #   Remove-HostEntry -LockFile "$($Env:systemdrive)\temp\Hosts.lock" -Name B4565 -WithNote "Created for Open-PsSession, delete me"
    #
    # this function will:
    #   create a lock file
    #   if the file is already locked then wait until timeout for the file to be unlocked, if timeout reached then throw an error
    #   add the entry to the file
    #   unlock the file 
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name
        , $WithNote

        , $HostsFile = "$($Env:windir)\System32\Drivers\etc\hosts"
        , $LockFile = "$($Env:systemdrive)\temp\Hosts.lock"
        , $TimeOut = 300
        ) # end param
    # skip Include Function Get-FileLock
    # write-host "    Removing '$($IP)' = '$($Name)' from file '$($HostsFile)'" -ForegroundColor DarkGray

    # get the hosts file open and locked
    try {
        $Lock = Get-FileLock -File "$($Env:systemdrive)\temp\Hosts.lock"

        # read the file contents
        $BeforeContent = Get-Content $HostsFile

        # remove any previous entries for this name from the file
        # add the entry to the hosts file
        $Hosts = ( $BeforeContent | Where-Object { $_ -inotmatch "^[ \t]*(?<ip>[0-9.]*)[ \t]+(?<name>$($Name))[ \t]+(?:#[ \t]+$($WithNote)|$)" } )

        # save the file
        $Hosts | Set-Content $HostsFile

        }
    catch {
        throw $_
        }
    finally {
        # release the file
        $Lock.Close()
        $Lock.Dispose()
        } # end try/catch/finally
    } # end fucntion Remove-HostEntry


function UnpackZipFile {
    param (
        $ZipFile
        , $Destination
        ) # end param
    write-host "  Expand-Archive -Path ""$($ZipFile)"" -DestinationPath ""$($Destination)\"" -Force" -ForegroundColor DarkGray
    Expand-Archive -Path "$($ZipFile)" -DestinationPath "$($Destination)\" -Force
    } # end function UnpackZipFile

