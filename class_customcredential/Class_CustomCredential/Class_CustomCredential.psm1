#Requires -Version 7.0
Class CustomCredential {
    # written by Roy Miller, 2021 Nov
    #   v1.1    -Add, allow headless update of credential files. This is really only useful for service accounts where it's a pain to create these files since we're not allowed to log in using the account.
    #   v2.0    -Change, split out chocolatey files to make package cleaner
    #   v2.1    -Change, not a functional change, but modifed script to deal with VSCode syntax checking
    #
    # This class automates the process storing, accessing, and testing credentials which can be tested against a credential manager like AD.
    # The idea is that some automation steps might accidently use an old/invalid password which could quickly lock an account if left unchecked.
    # 
    # class design requirements:
    #   - can work with other credential managers
    #   - supports powershell 7 
    #   - passwords stored in clixml files are only readable on the same computer and user who created them
    #   - can be extended to support powershell credential manager
    #   - never retain the password or credential in memory
    #   - credential is stored into a clixml file
    #   - everytime the credential is received it is pulled from the clixml file
    #   - if clixml object does not exist then create it, and test to ensure the created object is valid
    #   - if clixml object fails to validate against the athority then delete the clixml object to prevent it from being used/test and accidently locking the account
    #   - test password prior to building a Pack item
    #   - scripts running as service accounts will need a mechnism to update clixml file password if it changes
    # 
    #
    # examples
    #   $NonAdmin = [CustomCredential]::New("nm\mil1642")
    #   $Admin = [CustomCredential]::New("nm\mil1642-nm")
    #   $MyAccount = [CustomCredential]::New()
    #
    #   get credential which doesn't validate, this is used for things like tokens
    #       $TokenCredential = [CustomCredential]::New("d16b3b6cf3494b449b8135a92329df14", "NoValidation")
    #       $TokenCredential.Username, $TokenCredential.Credential($False).GetNetworkCredential().Password
    #
    #   Pass a PsCredential object to something
    #       $Credential = $Admin.Credential()
    #
    #   Delete the credential
    #       $TokenCredential = [CustomCredential]::New("d16b3b6cf3494b449b8135a92329df14", "NoValidation")
    #       $TokenCredential.Remove()
    #
    #   Override the credential object for service accounts
    #       # using an account with admin rights
    #       $TokenCredential = [CustomCredential]::New("d16b3b6cf3494b449b8135a92329df14", "NoValidation")
    #       $TokenCredential.CreateManualUpdateFile()
    #       Notepad $TokenCredential.ManualUpdateFile       # store the password in plain text and save the file
    #       # move the file to the user's Profile\Credential folder
    #       # trigger an action known to use this credential, like a scheduled task. The json file will automatically be deleted on use.
    #
    #   Repack the chocolatey package
    #       choco pack X:\gitlab\dw-endpoint\Modules\Class_CustomCredential\Package\Package.nuspec --out \\nm.nmfco.com\dfs01\appls\sd\Chocolatey

    [ValidateNotNullOrEmpty()][string]$Username = "$($Env:UserDomain)\$($Env:Username)"
    [ValidateNotNullOrEmpty()][string]$CredentialPath = "$($Env:UserProfile)\Credentials\"
    [ValidateNotNullOrEmpty()][string]$CheckAgainst = "ActiveDirectory"
    [string]$Prompt = "Please enter credentials"
    [datetime]$LastTested
    # [string]$ManualUpdateFile # path to the file used to manually update the credential. 
    # Constructor
    CustomCredential() {
        $This.CreateObject("$($Env:UserDomain)\$($Env:Username)")
        }
    CustomCredential([PsCredential]$PsCred){
        $This.Username = $PsCred.Username

        # create repository folder if it doesn't yet exist
        $This.CreateRepository()

        $This.Update($PsCred.Username, $PsCred.GetNetworkCredential().Password)
        }
    CustomCredential([string]$Username) {
        $This.CreateObject($Username, "ActiveDirectory")
        }
    CustomCredential([string]$Username, [string]$CheckAgainst) {
        $This.CreateObject($Username, $CheckAgainst)
        }
    CustomCredential([string]$Username, [string]$CheckAgainst, [string]$Message) {
        $This.Prompt = $Message
        $This.CreateObject($Username, $CheckAgainst)
        }
    [void] CreateObject([string]$Username = "$($Env:UserDomain)\$($Env:Username)", [string]$CheckAgainst) {
        $This.Username = $Username
        $This.CheckAgainst = $CheckAgainst

        # test to see if there is a raw file.
        # $This.ManualUpdateFile = $This.CredentialFile() -ireplace "\.clixml", ".json"
        # if the raw file exists
        $JsonFile = Get-Item $This.ManualUpdateFile() -ErrorAction SilentlyContinue
        if ( $JsonFile ) {
            # read the file 
            $RawData = $JsonFile | Get-Content | ConvertFrom-Json
            # delete the raw file
            $JsonFile | remove-item -Force
            # update the repository file
            $This.Update($RawData.Username, $RawData.Password)
            } # end if 

        # create repository folder if it doesn't yet exist
        $This.CreateRepository()

        if ( -not $This.TestFileExists() ) { $This.Update() }
        # confirm the credential is valid, if not then recreate it
        $This.UpdateIfNeeded()
        }
    [void] CreateRepository() {
        # create repository if it doesn't yet exist
        if ( -not (Test-Path -Path $This.CredentialPath) ) { 
            New-Item -ItemType Directory -Path $This.CredentialPath 
            Write-Host "  Created credential repository '$($This.CredentialPath)'" -ForegroundColor DarkGray
            } # end if 
        }
    [void] CreateManualUpdateFile() {
        @{Username=$This.Username; Password=""} | ConvertTo-Json | Out-File -path $This.ManualUpdateFile() -Force$ps
        }
    [pscredential] Credential() { # depreciated use PsCredential instead
        # confirm the credential is valid, if not then recreate it
        # then read the credential and return it
        return $This.Credential($True)
        }
    [pscredential] Credential([bool]$Validate=$True) { # depreciated use PsCredential instead
        # confirm the credential is valid, if not then recreate it
        # then read the credential and return it
        if ( $Validate ) { $This.UpdateIfNeeded() }
        return &$This.Scriptblock()
        }
    [pscredential] PsCredential() { 
        # confirm the credential is valid, if not then recreate it
        # then read the credential and return it
        return $This.PsCredential($True)
        }
    [pscredential] PsCredential([bool]$Validate=$True) { 
        # confirm the credential is valid, if not then recreate it
        # then read the credential and return it
        if ( $Validate ) { $This.UpdateIfNeeded() }
        return &$This.Scriptblock()
        }
    [string] CredentialFile() {
        # create a file path based on credential store path, username, and computername
        return "$($This.CredentialPath -replace '\\+\s*$','')\$($This.Username -replace '\\','_')_$($Env:Computername).clixml"
        }
    [string] ManualUpdateFile() {
        # create a file path based on credential store path, username, and computername
        # replace the file type .clixml with .json
        return $This.CredentialFile() -ireplace "\.clixml", ".json"
        }
    [string] Domain() {
        $Output = ""
        # https://regex101.com/r/CBDn0m/3 Pickout the username and domain names, differentiate between domain name alias and FQDN, Identfy type
        if ( $This.Username -imatch "^(?:(?<Account>(?<Domain>[a-z0-9_-]+)\\(?<Username>[a-z0-9._-]+))|(?<Account>(?<FQDN>(?=[^\\]+\.)[a-z0-9._-]+)\\(?<Username>[a-z0-9._-]+))|(?<Email>(?<Username>[a-z0-9._-]+)@(?<Domain>[a-z0-9_-]+))|(?<Email>(?<Username>[a-z0-9._-]+)@(?<FQDN>(?=[a-z0-9_-]+\.)[a-z0-9_.-]+)))$" ) {
            if ( $Output = $Matches.FQDN ) { }
            elseif ( $Output = @{""="nm.nmfco.com"; "NM"="nm.nmfco.com"; NMTEST="nmtest.nmfco.com"; NMDEV="nmdev.nmfco.com"}[$Matches.Domain] ) {}
            else { 
                # we should never get to this 
                $Output = ""
                write-host "warning 0087: '$($This.Username)' does not appear to have a domain name"
                } # end if
            } # end if 
        return $Output
        }   
    [void] Remove() {
        # delete the credential file
        Get-Item -path $This.CredentialFile() | Remove-Item
        write-host "  Removed credential file '$($This.CredentialFile())'"
        }
    [scriptblock] Scriptblock() {
        # create a script block object that when run will return the credential object from the file
        # &($This.Scriptblock())
        return [Scriptblock]::Create( "Import-Clixml -Path '$($This.CredentialFile())'" )
        }
    [bool] Test() {
        # test that the credential file exists and the embeded credential is valid
        if ( $This.CheckAgainst -ieq "ActiveDirectory" ) {
            Return $This.TestFileExists() -and $This.TestAD()
            } # end if 
        Return $True
        }
    [bool] TestAD() {
        # test the credential file to confirm its embedded credential is valid
        if ( $Global:PsVersionTable.PsVersion -lt [version]"7.0" ) {
            try {
                $Root = "LDAP://" + ([ADSI]'').distinguishedName
                $Validated = New-Object System.DirectoryServices.DirectoryEntry($Root,$This.Username,$This.Credential($False).GetNetworkCredential().password)
                }
            Catch {
                $_.Exception.Message
                Continue
                }
            $this.LastTested = get-date
            If ( -not $Validated ) {
                Write-Warning "  Failed to connect to the domain" -ForegroundColor Yellow
                return $False
                }
            elseif ( $null -ne $Validated.name ) { 
                return $True
                }
            else {
                write-host "  Credential for '$($This.Username)' is not valid" -ForegroundColor Yellow 
                $This.Remove()
                return $False
                } # end if
            }
        else {
            # $Cred = get-credential
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
            $Validated = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ContextType, $This.Domain(), $This.Username, $This.Credential($False).GetNetworkCredential().Password
            # $Validated = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ContextType, "nm.nmfco.com", $Cred.Username, $Cred.Credential($False).GetNetworkCredential().Password
            if ( -not $Validated.ConnectedServer -and [bool](Resolve-DnsName -Name $Env:UserDnsDomain) ) { 
                # write-host "0139 got here"
                # credential could not be validated but dns resolution is working which indirectly implies the network is up
                # confirm domain can be pinged then if so remove the credential, run the ping test a maximum of 4 times but stop testing on the first successful ping
                1..4 | ForEach-Object { if ( (Test-Connection $This.Domain() -count 1).Status -ieq 'Success' ) { $This.Remove(); break } }
                } # end if 
            return [bool]$Validated.ConnectedServer
            } # end if
        }
    [bool] TestFileExists() {
        # confirm the credential file exists, if not then report warning
        if ( -not ($Output = Test-Path -Path $This.CredentialFile()) ) {
            write-host "  Credential file '$($This.CredentialFile())' does not exist" -ForegroundColor Yellow
            } # end if 
        Return $Output
        }
    [string] ToPack() {
        # this generally means some multi parallel execution is going to be done. It's imparative the credential is validated to prevent accidental lockouts.
        # return an insert string used by Pack-Script to insert a variable value. This will be a scriptblock instruction to import the clixml file
        $This.UpdateIfNeeded()
        return $This.ToString()
        }
    [string] ToString() {
        # return the scriptblock as a string
        Return $This.Scriptblock().ToString()
        }
    [void] UpdateIfNeeded() {
        # tests the credential to ensure it's valid, if not then recreates the credential
        $Delay = $false
        while ( -not $This.Test() ) {
            # build in a delay to prevent getting locked into an unbreakable loop where you must kill powershell
            if ( $Global:PsVersionTable.PsVersion -lt [version]"7.0" -and $Delay ) {
                1..3 | ForEach-Object { Start-Sleep -Seconds 1; write-host "." -NoNewLine }; write-host
                } # end if
            $This.Update()
            $Delay = $True
            } # end while
        }
    [void] Update() {
        # recreates the credential regardless if is valid or not, and does not test the saved credential
        $Cred = Get-Credential -Username $This.Username -Message "$($This.Prompt)`nFor '$($This.Username)'"
        if ( $This.Username -ine $Cred.Username ) { write-host "  Username changed. Original was '$($This.Username)' is now '$($Cred.Username)'" -ForegroundColor Yellow } 
        $This.Username = $Cred.Username
        $Cred | Export-Clixml -Path $This.CredentialFile()
        }
    [void] Update($Username, $P) {
        # recreates the credential regardless if is valid or not, and does not test the saved credential
        # confirm the username and password values are populated
        if ( $Username -inotmatch "^[^ ]+$" -or $P -inotmatch "^[^ ]+$" ) {
            throw "0206:  Username or password were not populated, no change made"
            } # end if

        if ( $This.Username -ine $Username ) { 
            $This.Username = $Username
            write-host "  Username changed. Original was '$($This.Username)' is now '$($Username)'" -ForegroundColor Yellow
            } # end if
        # create the clixml file 
        $P = ConvertTo-SecureString $P -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $P)
        $Cred | Export-Clixml -Path $This.CredentialFile()
        write-host "  Updated credential file" -ForegroundColor darkgreen
        }
    } # end class CustomCredential
