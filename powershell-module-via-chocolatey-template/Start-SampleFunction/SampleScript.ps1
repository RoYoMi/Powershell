


function Start-SampleFunction {
    param ( 
        [string]$Message = "Hello world"
        ) # end param
    write-host "Start-SampleFunction says: $Message"
    } # end function Start-SampleFunction


function Get-SampleQuote {
    $Quote = invoke-restmethod http://numbersapi.com/random
    if ( $Quote -imatch "^(?<Number>[0-9]{6,})[ .]" ) {
        # if the number is 1m or larger than insert commas to make it more readable
        $Quote = $Quote.Replace( $Matches.Number, $([decimal]$Matches.Number).ToString('n0') )
        } # end if 
    $Quote

    $ScriptDirectory = $MyInvocation.MyCommand
    write-host "Script-Directory = '$ScriptDirectory'"

    } # end function Get-SampleQuote


function UnpackZipFile {
    # this function is not exported, but it can be used by other functions in this module
    param (
        $ZipFile
        , $Destination
        ) # end param
    write-host "  Expand-Archive -Path ""$($ZipFile)"" -DestinationPath ""$($Destination)\"" -Force" -ForegroundColor DarkGray
    Expand-Archive -Path "$($ZipFile)" -DestinationPath "$($Destination)\" -Force
    } # end function UnpackZipFile


function Get-OutDoNotRun {
    if($host.Name -ne "ConsoleHost") {
        Start-Process powershell -ArgumentList '-noprofile -noexit -command Get-OutDoNotRun'
        return
        } # end if 

    $TempFolder = "$($Env:Temp)\"
    UnpackZipFile -ZipFile "$($Env:UserProfile)\Documents\PowerShell\Modules\Start-SampleFunction\SampleData.zip" -Destination $TempFolder
    $SampleDataFile = "$TempFolder\SampleData.txt" | get-item 

    $Frames = [system.text.encoding]::Ascii.GetString([system.Convert]::FromBase64String(($SampleDataFile | Get-Content))) | ConvertFrom-Json

    ## Go through the frames, and re-scale them so that they have the
    ## proper aspect ratio in the console
    for($counter = 0; $counter -lt $Frames.Count; $counter++) {
        $frame = $Frames[$counter]
        $expansion = (@('$1') + (('$2','$3','$2','$3') | Get-Random -Count 4 | Sort-Object)) -join ''
        $frame = (($frame -split "`t") -replace '(.)(.)(.)',$expansion) -join "`t"
        $Frames[$counter] = $frame -split "`t"

        } # next frame
        
    ## Prepare the screen
    $counter = 0
    $maxCounter = $Frames.Count - 1
    $host.UI.RawUI.BackgroundColor = "White"
    $host.UI.RawUI.ForegroundColor = "Black"
    try {
        mode con:cols=138 lines=45
        $host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size 138,45
        }
    catch {}

    ## Open the background song
    $script = @'
    $player = New-Object -ComObject 'MediaPlayer.MediaPlayer'
    $player.Open("http://www.leeholmes.com/projects/ps_html5/background.mp3")
    $player
'@

    ## ... in a background MTA-threaded PowerShell because
    ## the MediaPlayer COM object doesn't like STA
    $runspace = [RunspaceFactory]::CreateRunspace()
    $runspace.ApartmentState = "MTA"
    $bgPowerShell = [PowerShell]::Create()
    $bgPowerShell.Runspace = $runspace
    $runspace.Open()
    $player = @($bgPowerShell.AddScript($script).Invoke())[0]

    try {
        ## Wait for it to buffer (or error out)
        
        while($true) {
            Start-Sleep -m 500
            if($player.HasError -or ($player.ReadyState -eq 4)) { break }
            }
        
        Start-Sleep -m 1600
        Clear-Host
        
        $host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 0,([Console]::WindowHeight - 1)
        Write-Host -NoNewLine 'Q or ESC to Quit'
        
        ## Loop through the frames and display them
        [Console]::TreatControlCAsInput = $true
        while($true) {
            if([Console]::KeyAvailable) {
                $key = [Console]::ReadKey()
                if(($key.Key -eq 'Escape') -or
                    ($key.Key -eq 'Q') -or
                    ($key.Key -eq 'C')) {
                    break
                    } # end if
                } # end if 
            
            if((-not $player.HasError) -and ($player.PlayState -eq 0)) { break }
            $host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 0,0
            Write-Host ($Frames[$counter] -join "`r`n")
            
            Start-Sleep -m 100
            $counter = ($counter + 1) % $maxCounter
            } # end while
        } # end try
    finally {
        ## Clean up, display exit screen
        Clear-Host
        $player.Stop()
        $bgPowerShell.Dispose()
        $SampleDataFile | Remove-Item -Force
        } # end try / catch
    } # end function Get-OutDoNotRun
