#Requires -Version 7.0

using module Class_CustomCredential

if ( -not ( Get-Module -ListAvailable -Name PsFalcon ) ) {
    # Uninstall-Module -Name PSFalcon -AllVersions
    Install-Module -Name PSFalcon -RequiredVersion 1.4.2 -SkipPublisherCheck -Scope AllUsers
    } # end if

join-path $PsScriptRoot *.ps1 -resolve | %{ Import-Module $_ }


<#
$manifest = @{
    Path              = '.\Open-PsSession\Open-PsSession.psd1'
    RootModule        = 'Open-PsSession.psm1' 
    Author            = 'Roy Miller'
    FunctionsToExport = @(
        'Clear-CcmCache'
        , 'Get-CcmActualConfigMeteredNetworkUsage'
        , 'Get-CcmLogs'
        , 'Get-CcmNetworkCost'
        , 'Get-CcmVersion'
        , 'Get-DeviceFromSccm'
        , 'Get-EventLogFromSession'
        , 'Get-FileLock'
        , 'Get-FilesFromMultiPsSession'
        , 'Get-FilesFromSession'
        , 'Get-HostFromCrowdStrike'
        , 'Get-MeteredEthernetConnection'
        , 'Get-PendingRebootStatus'
        , 'Get-SccmCheckinDates'
        , 'Install-CcmAgent'
        , 'Install-CcmAgentMultiSession'
        , 'Open-MultiPsSession'
        , 'Open-PsSession'
        , 'Optimize-PackScript'
        , 'Read-CmLogs'
        , 'Remove-CcmAgent'
        , 'Remove-CcmAgentMultiSession'
        , 'Set-CcmGenerateNewGUID'
        , 'Set-CcmNetworkCost'
        , 'Set-CcmVerbosity'
        , 'Set-MeteredEthernetConnection'
        , 'Start-CcmAction'
        , 'Start-ServiceInSession'
        , 'Stop-ServiceInSession'
        , 'Test-ConnectionToSiteServer'
        , 'Test-PsSession'
        ) # end array
    } # end hashtable
New-ModuleManifest @manifest

#>