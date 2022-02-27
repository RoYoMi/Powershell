
Class CustomFile {
    # Written by Roy Miller, 2021 Dec 17
    # This class lowers the barrier of entry for basic file operations by multiple threads via the .Net class System.IO.File. 
    # Commandlets like Out-File are designed for single threaded operations, and will throw errors if the file is already in use by another thread.
    # .Net offers several flavors of file interaction, and each has their own complexities and nuances. 
    #
    # Notes:
    #   File operations like: Read(), Append(), ClearConnents(), will check to see if the file is locked 
    #   If not locked then it will be locked during the operation and unlocked after the operation is complete
    #
    # class design requirements
    #   - can lock a file
    #   - can append data to the last line of a file
    #   - can append new lines to the end of a file
    #   - can unlock a file
    #   - can wait while a file is locked until the file is not locked before continuing
    #   - allows for a timeout while waiting, at timeout throw error
    #   - assume the last line of the file does not end in a new line character, this gives the option to append to the end of the last line or to add a new line 
    #   - if the file size is zero then append will always add start at line zero
    #
    # examples
    #   $VerbosePreference = 'Continue'
    #   $File = [CustomFile]::New("c:\temp\test.txt")
    #   
    #   Lock file
    #       $File.Lock()
    #   Read the contents of the file 
    #       $Data = $File.Read()
    #   Delete contents of the file 
    #       $File.ClearContents()
    #   Append new line to the end of the file
    #       $File.Append( @("$(Get-Date) New Line") )
    #   Append data to the end of the last line
    #       $File.Append( "--> $(Get-Date) added to the last Line", @() )
    #   Append data to the end of the last line, then add additional lines to the end of the file
    #       $File.Append( "--> $(Get-Date) added to the last Line", @( "$(Get-Date) line 1", "$(Get-Date) line 2") )
    #   Release file lock
    #       $File.Unlock()
    #
    #   These must be run in an elevated prompt, and on the machine with the locked file
    #       List all the locks on file
    #           $File.ListLocks()
    #       Force the file to be unlocked if you can't find the culprit
    #           $File.Unlock( $True )
    #
    #   $VerbosePreference = "SilentlyContinue"
    #
    #   Repack the chocolatey package
    #       choco pack X:\gitlab\dw-endpoint\Modules\Class_CustomFile\Class_CustomFile.nuspec --out \\nm.nmfco.com\dfs01\appls\sd\Chocolatey


    # Constructor
    #Requires -Version 5.0
    [string]$FullPath
    $Handle # do not cast this variable as a specific type, different versions of .net will either create a [system.io.file] or [system.io.FileStream] object, and hardcoding it here will lead to problems
    [string]$ShareType = "None" # can be: "None", "Read", "Write"
    [int]$Timeout = 10 * 60 # number of seconds to wait for a file to unlock
    [system.Text.Encoding]$DesiredEncoding = [system.Text.Encoding]::UTF8
    [string]$NewlineCharacter = "`n"

    CustomFile([string]$FullPath) {
        write-verbose "  CustomFile('$($FullPath))"
        $This.CustomFile( $FullPath, $This.Timeout )
#        $This.FullPath = $FullPath
        }
    CustomFile([string]$FullPath, [int]$Timeout) {
        write-verbose "  CustomFile('$($FullPath), $Timeout)"
        $This.FullPath = $FullPath
        $This.Timeout = $Timeout
        $This.DesiredEncoding = $This.GetEncoding()
        }


    [void] Append ([Array]$LinesToAppendToEndOfFile) {
        write-verbose "  Append( array of '$($LinesToAppendToEndOfFile.Count)' lines )"
        $WasLockedBefore = $This.IHaveTheLock()
        $This.Lock()
        # if the file is zero length
        if ( $This.Handle.Length -eq 0 ) { 
            # append the first line of input to the end of the first line in the file
            $FirstLine, $RestOfLines = $LinesToAppendToEndOfFile
            $This.Append( $FirstLine, $RestOfLines )
            }
        else {
            # assume the last line does not end in a new line character and append 'null`n' to the end of the last line in the file
            $This.Append("", [Array]$LinesToAppendToEndOfFile)
            } # end if 
        if ( -not $WasLockedBefore ) { $this.Unlock() }
        }
    [long] LengthExcludingBom () {
        write-verbose "  LengthExcludingBom()"
        $WasLockedBefore = $This.IHaveTheLock()
        $This.Lock()
        $BomByteLength = if ( $This.Handle.Length -eq 0 ) {
            0 + @{ "utf-8"=3; "utf-32"=4; "utf-7"=3; "unicode"=2; "BigEndianUnicode"=2; "us-ascii"=0 }[$This.DesiredEncoding.Bodyname] 
            }
        else {
            0 + @{ "utf-8"=3; "utf-32"=4; "utf-7"=3; "unicode"=2; "BigEndianUnicode"=2; "us-ascii"=0 }[$This.GetEncoding().Bodyname] 
            } # end if

        $Length = $This.Handle.Length - $BomByteLength
        if ( -not $WasLockedBefore ) { $this.Unlock() }
        return $Length
        } 
    [long] Length() {
        $WasLockedBefore = $This.IHaveTheLock()
        $This.Lock()
        $Length = $This.Handle.Length
        if ( -not $WasLockedBefore ) { $this.Unlock() }
        Return $Length
        }
    [void] Append ([string]$AppendToLastLine, [Array]$LinesToAppendToEndOfFile) {
        write-verbose "  Append( Line,  array of '$($LinesToAppendToEndOfFile.Count)' lines )"
        $WasLockedBefore = $This.IHaveTheLock()
        $This.Lock()
        [void]$This.Handle.Seek(0, [System.IO.SeekOrigin]::End)
        if ( $This.LengthExcludingBom() -le 0 ) {
            # Insert BOM
            write-verbose "  Setting BOM"
            if ( $This.DesiredEncoding -eq [system.Text.Encoding]::UTF8 )             { 0xef, 0xbb, 0xbf | %{ $This.Handle.WriteByte($_) } }
            if ( $This.DesiredEncoding -eq [system.Text.Encoding]::UTF7 )             { 0x2b, 0x2f, 0x76 | %{ $This.Handle.WriteByte($_) } }
            if ( $This.DesiredEncoding -eq [system.Text.Encoding]::UTF32 )            { 0x00, 0x00, 0xfe, 0xff | %{ $This.Handle.WriteByte($_) } }
            if ( $This.DesiredEncoding -eq [system.Text.Encoding]::Unicode )          { 0xff, 0xfe | %{ $This.Handle.WriteByte($_) } }
            if ( $This.DesiredEncoding -eq [system.Text.Encoding]::BigEndianUnicode ) { 0xfe, 0xff | %{ $This.Handle.WriteByte($_) } }
            } # end if
        if ( $AppendToLastLine ) {
            $DataToWrite = $This.DesiredEncoding.GetBytes( $AppendToLastLine ) 
            $This.Handle.Write($DataToWrite, 0, $DataToWrite.length)
            } # end if
        # add these lines to end of the file
        foreach ( $Line in $LinesToAppendToEndOfFile ) {
            $DataToWrite = $This.DesiredEncoding.GetBytes("$($This.NewlineCharacter)$($Line)") 
            $This.Handle.Write($DataToWrite, 0, $DataToWrite.length)
            } # next line
        # clear cache to commit data to file
        $This.Handle.Flush()
        if ( -not $WasLockedBefore ) { $this.Unlock() }
        }
    [void] ClearContents() {
        write-verbose "  ClearContents()"
        $WasLockedBefore = $This.IHaveTheLock()
        $This.Lock()
        if ( $This.Handle ) {
            # return to the beginnging of the file
            [void]$This.Handle.Seek(0, [System.IO.SeekOrigin]::Begin)
            # clear the file contents
            $This.Handle.SetLength(0)
            } 
        else {
            write-host "  error 0064: failed to clear contents"
            } # end if
        $This.Handle.Flush()
        if ( -not $WasLockedBefore ) { $this.Unlock() }
        }
    [bool] Exists() {
        write-verbose "  Exists() = $([bool](test-path $This.FullPath ))"
        return ( test-path $This.FullPath )
        }
    [Text.Encoding] GetEncoding() {
        write-verbose "  GetEncoding()"
        $WasLockedBefore = $This.IHaveTheLock()
        $This.Lock()
        $bom = New-Object -TypeName System.Byte[](4)
        $null = $This.handle.Read($bom,0,4)
        if ( -not $WasLockedBefore ) { $this.Unlock() }

        if ($bom[0] -eq 0x2b -and $bom[1] -eq 0x2f -and $bom[2] -eq 0x76)                       { return [System.Text.Encoding]::UTF7 }
        if ($bom[0] -eq 0xff -and $bom[1] -eq 0xfe)                                             { return [System.Text.Encoding]::Unicode }
        if ($bom[0] -eq 0xfe -and $bom[1] -eq 0xff)                                             { return [System.Text.Encoding]::BigEndianUnicode }
        if ($bom[0] -eq 0x00 -and $bom[1] -eq 0x00 -and $bom[2] -eq 0xfe -and $bom[3] -eq 0xff) { return [System.Text.Encoding]::UTF32 }
        if ($bom[0] -eq 0xef -and $bom[1] -eq 0xbb -and $bom[2] -eq 0xbf)                       { return [System.Text.Encoding]::UTF8 }
        return [System.Text.Encoding]::ASCII
        }
    [string] HandleExe() {
        [string]$HandleExe = if ( Test-Path x:\Tools\Sysinternals\Handle64.exe ) { "x:\Tools\Sysinternals\Handle64.exe" } else { Join-Path $env:TEMP "handle64.exe" }
        # get sysinternals handles program
        if ( -not (Test-Path $HandleExe -ErrorAction SilentlyContinue) ) {
            # download
            $handleZip = Join-Path $env:TEMP "handle.zip"
            Invoke-WebRequest "https://download.sysinternals.com/files/Handle.zip" -OutFile $handleZip -UseBasicParsing
            # extract
            Expand-Archive $handleZip $env:TEMP -Force
            } # end if 
        write-verbose "  HandleExe() = '$($HandleExe)'"
        Return $HandleExe
        }
    [bool] IHaveTheLock() {
        # if there is a handle and that handle is active
        write-verbose "  IHaveTheLock() = $( [bool]$This.Handle -and [bool]$This.Handle.Handle )"
        return [bool]$This.Handle -and [bool]$This.Handle.Handle
        } 
    [bool] IsElevated() {
        write-verbose "  IsElevated()"
        return $This.IsElevated( $False )
        }     
    [bool] IsElevated( [bool]$Required ) {
        $Elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        write-verbose "  IsElevated( $Required ) = '$($Elevated)'"
        if ( $Required -and -not $Elevated ) {
            # not running "as Administrator" - so relaunch as administrator
            throw "  Warning 0141: must run this with elevated rights"
            }
        Return $Elevated
        }
    [bool] IsLocked() {
        write-verbose "  IsLocked()"
        if ( -not $This.Exists() ) { Return $False }
        if ( $This.Handle ) { Return $True }
        Try { 
            $Lock = [System.IO.File]::Open($This.FullPath, "OpenOrCreate", "ReadWrite", $This.ShareType)
            $Lock.Close();
            $Lock.Dispose();
            $Lock = $null;
            Return $False
            }
        catch {
            Return $True
            }
        }
    [Array] ListLocks() {
        write-verbose "  ListLocks()"
        if ( $This.IsElevated($True) ) {
            write-host "  Getting handles for '$($This.FullPath)'" -ForegroundColor DarkGray
            $Handles = Invoke-Expression "& '$($This.HandleExe())' '$($This.FullPath)' -nobanner -accepteula"
            # $Handles = $This.HandleExe() "'$($This.FullPath)'" -nobanner -accepteula
            $Output = Foreach ( $Handle in $Handles | ?{ $_ } ) { 
                if ( $Handle -imatch "^(?<Process>.*?)\s+pid:\s+(?<PID>[0-9]+)\s+type:\s+(?<Type>.*?)\s+(?<HandleID>\w+):\s+(?<File>.*?)\s*$" ) { 
                    [PsCustomObject]@{
                        Process     = $Matches.Process
                        PID         = $Matches.PID
                        Type        = $Matches.Type
                        HandleID    = $Matches.HandleID
                        File        = $Matches.File
                        } # end hash
                    } # end if 
                } # next handle
            Return $Output
            } # end if 
        return @()
        }
    [Array] ListSmbLocks() {
        write-verbose "  ListSmbLocks()"
        $Output = if ( $This.IsElevated($True) ) {
            write-host "  Getting SMB handles for '$($This.FullPath)'" -ForegroundColor DarkGray
            Get-SmbOpenFile | ?{ $_.ShareRelativePath -and  $This.FullPath -ilike "\\$($Env:computername)*$($_.ShareRelativePath)" }
            } # end if 
        $Output 
        Return $Output
        }
    [void] Lock() {
        write-verbose "  Lock()"
        # if there is no handle or the handle was created but is lost then attempt to recreate it
        if ( -not $This.IHaveTheLock() ) { 
            $TimeoutAfter = (Get-Date).AddSeconds($This.TimeOut)
            # get the file open and locked
            write-verbose "  starting lock file process"
            do {
                Try { 
                    $This.Handle = [System.IO.File]::Open($This.FullPath, "OpenOrCreate", "ReadWrite", $This.ShareType)
                    }
                catch {
                    if ( $_ -imatch 'Cannot convert the.*value of type.*to type' ) { Throw "    Error 0095: It appears like `$this.Handle was cast as a specific type, remove this hard coded casting`n$_" }
                    if ( $TimeoutAfter -lt (Get-Date) ) { throw "    Error 0096: Get-FileLock failed to get exclusive file lock on '$($This.FullPath)' after '$This.Timeout' seconds" }
                    start-sleep -Milliseconds $(get-Random -Minimum 100 -Maximum 200)
                    } # end try/catch
                } until ( $This.Handle )
            write-verbose "  end lock file process"
            } # end if 
        }
    [array] Read() {
        write-verbose "  Read()"
        $WasLockedBefore = $This.IHaveTheLock()
        $This.Lock()
        [void]$This.Handle.Seek(0, [System.IO.SeekOrigin]::Begin)
        [System.IO.StreamReader] $SteamReader = [System.IO.StreamReader]::new($This.Handle,$This.DesiredEncoding)
        $Output = while (($Line = $SteamReader.ReadLine()) -ne $Null) { $Line }
        # issuing these commands will also unlock the file
        # $SteamReader.Close()
        # $SteamReader.Dispose()
        if ( -not $WasLockedBefore ) { 
            $this.Unlock() 
            $SteamReader.Close()
            }
        Return $Output
        } 
    [void] Unlock() {
        write-verbose "  Unlock()"
        if ( $This.IHaveTheLock() ) { 
            $This.Handle.Close()
            $This.Handle.Dispose()
            $This.Handle = $null
            }
        else {
            if ( $This.IsLocked() ) {
                write-host "  Warning 0239: File '$($This.FullPath)' could not be gracefully unlocked likely because it is in use elsewhere, try .Unlock( `$True ), or check the server hosting the file"
                } # end if 
            } # end if
        }
    [void] Unlock( [bool]$Force ) {
        write-verbose "  Unlock($($Force))"
        # Forces the file to be unlocked this is not advisable in most cases, and therefore will not be automated
        $This.Unlock()

        if ( $Force ) {
            $ErrorActionPreference = "Stop"
            foreach ( $Handle in $This.ListLocks() ) {
                $choice = ""
                while ($choice -inotmatch "^[Y|N]$") {
                    $choice = Read-Host "  Close handle for file '$($Handle.File)' for process '$($Handle.Process)' with PID '$($Handle.PID)'? (Y|N) "
                    } # Loop
                if ($choice -ieq "Y") {
                    if ( $Handle.PID -and $Handle.HandleID ) {
                        $result = Invoke-Expression "& '$($This.HandleExe())' -c $($Handle.HandleID) -y -p $($Handle.PID) -nobanner -accepteula"
                        # $result = $This.HandleExe() "-c $($Handle.HandleID) -y -p $($Handle.PID) -nobanner -accepteula"
                        if ( $result -imatch "Handle closed" ) {
                            Write-Host "  Handle for '$($Handle.File)' closed, process '$($Handle.Process)', PID '$($Handle.PID)'" -ForegroundColor DarkGreen
                            } `
                        else {
                            throw $result
                            } # end if 
                        } # end if 
                    } # end if Y
                } # next handle

            write-Verbose "  Closing SMB file locks"
            foreach ( $Handle in $This.ListSmbLocks() ) {
                $choice = ""
                while ($choice -inotmatch "^[Y|N]$") {
                    $choice = Read-Host "  Close handle for file '$($Handle.Path)' for client computer '$($Handle.ClientComputername)'? (Y|N) "
                    } # loop
                if ($choice -ieq "Y") {
                    $Handle | Close-SmbOpenFile -Confirm:$False
                    } # end if 
                } # next handle
            } # end if Force
        if ( $This.IsLocked() ) {
            write-host "  Warning 276: File '$($This.FullName)' could not be gracefully unlocked likely because it is in use elsewhere, try .Unlock( `$True ), or check the server hosting the file"
            } # end if 
        }
    } # end class
