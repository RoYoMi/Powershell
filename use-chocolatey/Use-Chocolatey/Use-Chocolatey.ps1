
# to rebuild this package
#   ConvertTo-PsModuleChocolateyPackage -NuspecFiles X:\gitlab\dw-endpoint\Modules\use-chocolatey\Package\Package.nuspec
function Get-PsdVersion {
    # reads the psd file and retreives the version
    #
    # examples 
    #   $PsdVersion = Get-Item "X:\gitlab\dw-endpoint\Modules\$($ModuleName)\$($ModuleName)\$($ModuleName).psd1" | Get-PsdVersion
    Param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        $Item
        ) # end param
    Import-LocalizedData -BaseDirectory $Item.DirectoryName -FileName $Item.Name -BindingVariable Data
    [version]$($data.ModuleVersion)
    } # end Get-PsdVersion


function ConvertTo-PsModuleChocolateyPackage {
    # examples
    #   ConvertTo-PsModuleChocolateyPackage -NuspecFiles "X:\gitlab\dw-endpoint\Modules\Open-PsSession\Package\Package.nuspec"
    param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$True)]
        $NuspecFiles = "X:\gitlab\dw-endpoint\Modules\Open-PsSession\Package\Package.nuspec"
        , $Out = "\\nm.nmfco.com\dfs01\appls\sd\Chocolatey"
        ) # end param

    begin {}
    Process {
        foreach ( $NuspecFile in $NuspecFiles ) {
            write-host "Processing nuspec file $($NuspecFile)"
            if ( -not (Test-Path $NuspecFile) ) { 
                write-host "  NuspecFile not found" -ForegroundColor DarkYellow
                continue
                } # end if 

            # fetch the PSD version 
            $PsdFile = $(get-item "$NuspecFile\..\..\*\*.psd1" | Select-Object -ExpandProperty fullname)
            if ( Test-Path $PsdFile ) {
                [version]$PsdVersion = Get-Item $PsdFile | Get-PsdVersion
                write-host "  PsdFile version $($PsdVersion)"
                }
            else {
                write-host "  PsdFile not found" -ForegroundColor DarkYellow
                } # end if

            # fetch the nuspec version
            [xml]$XML = Get-Item $NuspecFile | Get-Content -Raw
            [version]$NuspecVersion = $xml.package.metadata.version
            write-host "  NuspecFile version $($NuspecVersion.ToString())"

            $UseVersion = if ( $PsdVersion -eq $NuspecVersion ) {
                # versions are in parity, increment the version number and use that
                [version]::New($PsdVersion.Major,$PsdVersion.Minor,$PsdVersion.Build+1)
                }
            else {
                # versions are not in parity, assume the developer updated one but not the other, and use the most mature version number
                if ( $PsdVersion -lt $NuspecVersion ) { $NuspecVersion } else { $PsdVersion }
                } # end if 

            Write-host "  UseVersion $($UseVersion.ToString())"

            # set the psd file version
            if ( $UseVersion -ne $PsdVersion -and (Test-Path $PsdFile) ) {
                $RawData = Get-Item $PsdFile | Get-Content
                $RawData -ireplace "^(\s*ModuleVersion = [""'])[^""']*([""'])", "`${1}$($UseVersion.ToString())`${2}" | Out-File $PsdFile -Force
                write-host "  Updated PsdFile" -ForegroundColor DarkGray
                } # end if

            # set the nuspec file version
            if ( $UseVersion -ne $NuspecVersion ) {
                $xml.package.metadata.version = $UseVersion.ToString()
                $XML.Save($NuspecFile)
                write-host "  Updated NuspecFile" -ForegroundColor DarkGray
                } # end if

            # Push package to chocolatey repository
            Invoke-Expression -command "choco pack $($NuspecFile) --out $($Out)"
            } # next nuspec file
        } # end process
    end {}
    } # end function ConvertTo-PsModuleChocolateyPackage


