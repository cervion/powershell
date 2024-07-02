﻿# Misc Utilities/Functions
Add-Type -AssemblyName Microsoft.VisualBasic

function Write-Log {
    [Alias('log')]
    param(
        [object[]] $InputObject,
        [ValidateSet('Cyan', 'Red', 'Orange', 'Green', 'Yellow', 'White', 'Magenta')][string] $Colour = "Cyan"
    )
    foreach ($item in $InputObject) {
        foreach ($line in ($item | Out-String)) {
            Write-Host ("{0} | {1}" -f (Get-Date -Format "dd/MM/yyyy HH:mm:ss"), $line) -ForegroundColor $Colour
        }
    }
}

function Set-TabName {
    [alias('tname')]param($TabName)
    $Host.UI.RawUI.WindowTitle = $TabName
}

function Get-CurrentContext {
    [Alias('isadmin')]
    param()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    Write-Log "IsAdministrator: $($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    $env:principalName = $currentPrincipal.Identities.Name
    Write-Log "PrincipalName: $env:principalName"
    if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $false
    }
    return $true
}

function Invoke-ElevateContext {
    [Alias('elevate')]
    param([Parameter(Mandatory = $true)]$ScriptPath)
    if (!(Get-CurrentContext)) {
        Write-Log "Elevating context"
        Start-Process cmd -ArgumentList "/c net localgroup Administrators /Add $env:principalName" -Verb RunAs -Wait
        Start-Process powershell -ArgumentList "& '$ScriptPath'" -Verb RunAs
        exit
    }
}

function Get-AllModuleFunctions {
    param(
        $File
    )
    Get-Content $File | Where-Object { $_ -match '^function .*' } | ForEach-Object { $_ -replace 'function ([^ ]+).*', 'Export-ModuleMember -Function $1' }
}

function Get-WlanSpeed {
    [alias('wlanspeed', 'wifispeed', 'wspeed')]
    param()
    Get-NetAdapter -Name Wi-Fi | Select-Object -exp linkspeed
}

function ConvertTo-NZT {
    # Converts input datetime to New Zealand Standard Time timezone
    [alias('tonzt')]
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)][datetime]$inputTime,
        [switch]$isVerbose
    )
    if ($isVerbose) { Write-Log "DEBUG: inputTime = '$(ConvertTo-DateString $inputTime)'" }    
    $toTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("New Zealand Standard Time")
    $convertedTime = [System.TimeZoneInfo]::ConvertTime($inputTime, $toTimeZone)
    if ($isVerbose) { Write-Log "DEBUG: convertedTime = '$(ConvertTo-DateString $convertedTime)'" }
    return $convertedTime
}

function ConvertTo-DateString {
    # Converts input datetime into a formatted string (eg. "Friday, 5 June 2019 5:43:27 PM")
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)][datetime]$inputTime,
        [string] $format = "dddd, d MMMM yyyy hh:mm:ss tt"
    )
    $convertedTimeString = $inputTime.ToString($format)
    #Write-Log "DEBUG: convertedTimeString = '$convertedTimeString'" -Verbose
    return $convertedTimeString
}

function New-Password {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $false)][ValidateRange(0, 32)] [int] $Length = 16,
        [Parameter(Mandatory = $false)] [switch] $SqlFriendly
    )
    If ($PSCmdlet.ShouldProcess("Creates a new random password")) {
        if ($SqlFriendly) {
            # Generates a complex password that has a limited set of special characters
            Write-Host "Generating a password with a limited set of special characters"
            $password = ([char[]]([char]33) + [char[]]([char]35..[char]38) + [char[]]([char]35..[char]38) + [char[]]([char]35..[char]38) + [char[]]([char]65..[char]90) + [char[]]([char]97..[char]122) + 0..9 | Sort-Object { Get-Random })[0..$Length] -join ''
            return $password
        }
        else {
            # Generates a complex password with a full set of special characters
            Write-Host "Generating a password with a full set of special characters"
            $password = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 | Sort-Object { Get-Random })[0..$Length] -join ''
            return $password
        }
    }
}

function Split-Array {
    [alias('split')]
    [cmdletbinding()]
    param(
        [Parameter(Position = 0)][Parameter(ValueFromPipeline, ParameterSetName = 'SplitByChunks')][Parameter(ParameterSetName = 'SplitBySizePer')][System.Object[]]$Array,
        [Parameter(Position = 1, ParameterSetName = 'SplitByChunks')][int32]$Chunks,
        [Parameter(Position = 1, ParameterSetName = 'SplitBySizePer')][int32]$SizePer
    )

    $outputArray = $null
    $arrayLength = $Array.Length
    $SizePer = if ($SizePer) { $SizePer }else { $arrayLength / $Chunks }
    $Chunks = if ($Chunks) { $Chunks }else { $arrayLength / $SizePer }
    Write-Host "Array Length = $arrayLength"
    Write-Host "Chunks = $Chunks"
    Write-Host "SizePer = $SizePer"
    Write-Host "ParameterSetName = '$($PSCmdlet.ParameterSetName)'"

    switch ($PSCmdlet.ParameterSetName) {
        'SplitByChunks' {
            $outputArray = for ($i = 0; $i -lt $arrayLength; $i += $SizePer) { , ($Array[$i .. ($i + $SizePer - 1)]) }
        }
        'SplitBySizePer' {
            $outputArray = for ($i = 0; $i -lt $arrayLength; $i += $SizePer) { , ($Array[$i .. ($i + $SizePer - 1)]) }
        }
    }

    return $outputArray
}

function Start-Countdown {
    [alias('countdown')]
    param([ValidateRange(1, 120)][int]$Count, [string]$Message = "Countdown: ")
    $Counter = $Count
    Write-Host $Message -NoNewline
    while ($Counter -gt 0) {
        Write-Host "$Counter.." -NoNewline
        Start-Sleep 1
        $Counter--
    }
    Write-Host "Done"
}

function Confirm-IsNullOrEmpty {
    [alias('IsNull', 'NullOrEmpty')]
    param(
        [Parameter(Mandatory)][AllowNull()] $InputItem
    )

    if ($InputItem -is [string]) {
        return [string]::IsNullOrEmpty($InputItem)
    }
    else {
        return ($null -eq $InputItem -or $InputItem.Count -le 0)
    }
}

function ConvertTo-UrlEncoded { [alias('encode')]param($UrlToEncode) Add-Type -AssemblyName System.Web; [System.Web.HttpUtility]::UrlEncode($UrlToEncode) }

function ConvertFrom-UrlEncoded { [alias('decode')]param($UrlToDecode) Add-Type -AssemblyName System.Web; [System.Web.HttpUtility]::UrlDecode($UrlToDecode) }

function xx { if ((Read-Host "Are you sure you want to exit? Y/N").ToUpper() -eq 'Y') { exit }else { Write-Output "Exit cancelled" } }

function Disable-Accessibility {
    <#
	    .SYNOPSIS
		    Disable those annoying Accessibility Keys.
	    .DESCRIPTION
		    Disable Filter Keys, Sticky Keys and/or Toggle Keys.
	    .PARAMETER Option
		    Select which individual option to disable. Leave out this param to disable ALL.
	    .NOTES
		    Version:        1.00
		    Author:         Steven Messenger
		    Creation Date:  16/09/2019 10:21:10 AM
	    .EXAMPLE
            Disable-Accessibility
        .EXAMPLE
            Disable-Accessibility -Option 'Sticky Keys'
    #>
    [alias('dacc')]
    param([ValidateSet("Filter Keys", "Sticky Keys", "Toggle Keys")][string] $Option = "All")

    switch ($Option) {
        "Filter Keys" {
            Write-Host "Disabled Filter Keys" -ForegroundColor Yellow -BackgroundColor Black
            Set-ItemProperty "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" 122
        }
        "Sticky Keys" {
            Write-Host "Disabled Sticky Keys" -ForegroundColor Yellow -BackgroundColor Black
            Set-ItemProperty "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" 506
        }
        "Toggle Keys" {
            Write-Host "Disabled Toggle Keys" -ForegroundColor Yellow -BackgroundColor Black
            Set-ItemProperty "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" 58
        }
        default {
            # Disable ALL
            Write-Host "Disabled Filter Keys, Sticky Keys AND Toggle Keys" -ForegroundColor Yellow -BackgroundColor Black
            Set-ItemProperty "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" 122
            Set-ItemProperty "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" 506
            Set-ItemProperty "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" 58
        }
    }
    Pause
}

function Copy-Object {
    [alias('co')]
    param(
        [alias('o')][Parameter(ValueFromPipeline, Mandatory)][object] $Object
    )
    return $Object.PsObject.Copy()
}

function Measure-Count {
    # Counts the amount of items/objects in the $inputObject.
    [Alias('ct', 'Count')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][object]$inputObject
    )
    Process {
        $PipeCount++
    }
    End {
        Write-Output $PipeCount
    }
}


function Measure-TimeTaken {
    # Used to output the time taken to run a $scriptBlock/command
    [Alias('tt', 'timetaken')]
    [CmdletBinding()]
    param(
        [alias('s')][Parameter(ValueFromPipeline)][scriptblock]$ScriptBlock
    )
    $script:startTime = Get-Date
    $scriptBlock.Invoke()
    $script:endTime = Get-Date
    $script:timeTaken = New-TimeSpan $startTime $endTime

    $returnMessage = "Time Taken: "
    $returnMessage += switch ($timeTaken.TotalSeconds) {
        { $_ -ge 60 } { "{0:n2} Second(s)." -f $timeTaken.TotalSeconds; break }
        { $_ -ge 1 -and $_ -lt 60 } { "{0} Minute(s), {1} Second(s)." -f $timeTaken.Minutes, $timeTaken.Seconds; break }
        { $_ -lt 1 } { "{0} Milliseconds" -f $timeTaken.TotalMilliseconds; break }
    }
    Write-Host $returnMessage
}

function Test-FileLock {
    # Returns $true if a file is in use/locked. Can be used in a loop to write over a file once it's no longer in use.
    param (
        [parameter(Mandatory = $true)][string]$Path
    )

    $oFile = New-Object System.IO.FileInfo $Path

    if ((Test-Path -Path $Path) -eq $false) {
        return $false
    }

    try {
        $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    
        if ($oStream) {
            $oStream.Close()
        }
        return $false
    }
    catch {
        # file is locked by another process.
        return $true
    }
}


function Update-File {
    # Uses the Test-FileLock function within a loop to replace destinationFile with sourceFile and will attempt every $retryTimeInSeconds value.
    [Alias('rf', 'Replace-File')]
    param(
        [parameter(Mandatory)][string]$sourceFile,
        [parameter(Mandatory)][string]$destinationFile,
        [int]$retryTimeInSeconds = 60
    )

    $sourceFilePath = (Get-Item $sourceFile).FullName
    $destinationFilePath = (Get-Item $destinationFile).FullName

    $script:isLocked = $true
    do {
        $isLocked = Test-FileLock $destinationFilePath
        if ($isLocked) {
            Write-Log "File locked, trying again in $retryTimeInSeconds seconds."
            Start-Sleep $retryTimeInSeconds
        }
    }while ($isLocked)

    Write-Log "File no longer locked. Copying" Green
    Copy-Item -Path $sourceFilePath -Destination $destinationFilePath
}


function Remove-FileFolder {
    # Uses the Test-FileLock function within a loop to delete targetFile/folder and will attempt every $retryTimeInSeconds value.
    [Alias('df')]
    param(
        [parameter(Mandatory)][string]$target,
        [int]$retryTimeInSeconds = 60
    )

    $targetItem = Get-Item $target
    $targetPath = $targetItem.FullName

    $type = if ($targetItem.PSIsContainer) { "Folder" }else { "File" }

    $script:isLocked = $true
    do {
        if ($type -eq "Folder") {
            foreach ($item in Get-ChildItem $targetPath -Recurse) {
                $isLocked = Test-FileLock $item.FullName
                if ($isLocked) {
                    $type = $type = if ($item.PSIsContainer) { "Folder" }else { "File" }
                    Write-Log "$type ($($item.FullName)) locked, trying again in $retryTimeInSeconds seconds."
                    Start-Sleep $retryTimeInSeconds
                }
            }
        }
        else {
            $isLocked = Test-FileLock $targetPath
            if ($isLocked) {
                Write-Log "$type ($($targetPath)) locked, trying again in $retryTimeInSeconds seconds."
                Start-Sleep $retryTimeInSeconds
            }
        }        
    }while ($isLocked)

    Write-Log "$type ($($targetPath)) not locked. Deleting." Green
    if ($type -eq "Folder") {
        Remove-Item -Path $targetPath -Recurse    
    }
    else {
        Remove-Item -Path $targetPath
    }
}


function Get-FolderSize {
    # This returns a list of all files/folders within the $path (default is current folder) and adds the total size up into human readable format.
    [Alias('fs', 'folderscan', 'Scan-Folder', 'size')]
    param(
        [parameter(ValueFromPipeline)][string]$path = ".\",
        [switch]$descending,
        [ValidateSet("Auto", "KB", "MB", "GB", "TB")][string]$sizeFormat = "Auto"
    )    
    
    $sortOptions = @{
        Property   = "Size"
        Descending = $descending
    }
    
    $results = Get-ChildItem $path | Select-Object Name, @{N = "Type"; E = { if ($_.PSIsContainer) { "Folder" }else { "File" } } }, @{N = "Size"; E = { if ($_.PSIsContainer) { ((Get-ChildItem $_ -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum) }else { (($_ | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum) } } }
    $totalSize = ($results | Measure-Object -Sum Size).Sum
    Write-Output ($results | Sort-Object @sortOptions | Select-Object -ExcludeProperty Size *, @{N = "Size"; E = { ConvertBytes $_.Size $sizeFormat } } | Out-String).Trim()
    Write-Output "`nTotal Size: $(ConvertBytes $totalSize $sizeFormat)"
}


function Get-ObjectProperties {
    # Used to get all properties of an input object, can be useful for finding all properties of an object that match a name or part-of. (ie. '*ipaddress*')
    <#
        .SYNOPSIS
        Returns a list of all properties of the input object

        .DESCRIPTION
        Recursively 

        .PARAMETER Object
        Mandatory - The object to list properties of

        .PARAMETER MaxLevels
        Specifies how many levels deep to list

        .PARAMETER PathName
        Specifies the path name to use as the root. If not specified, all properties will start with "."

        .PARAMETER Level
        Specifies which level the function is currently processing. Should not be used manually.

        .EXAMPLE
        $v = Get-View -ViewType VirtualMachine -Filter @{"Name" = "MyVM"}
        Get-Properties $v | ? {$_ -match "Host"}

        .NOTES
            FunctionName : 
            Created by   : KevinD
            Date Coded   : 02/19/2013 12:54:52
        .LINK
            http://stackoverflow.com/users/1298933/kevind
     #>

    param(
        [parameter(mandatory, ValueFromPipeline)]$Object,
        [int]$MaxLevels = 5,
        [string]$PathName = "`$_",
        [int]$Level = 0
    )

    if ($Level -eq 0) { 
        $oldErrorPreference = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
    }

    #Initialize an array to store properties
    $props = @()

    # Get all properties of this level
    $rootProps = $Object | Get-Member -ErrorAction SilentlyContinue | Where-Object { $_.MemberType -match "Property" } 

    # Add all properties from this level to the array.
    $rootProps | ForEach-Object { $props += "$PathName.$($_.Name)" }

    # Make sure we're not exceeding the MaxLevels
    if ($Level -lt $MaxLevels) {

        # We don't care about the sub-properties of the following types:
        $typesToExclude = "System.Boolean", "System.String", "System.Int32", "System.Char"

        #Loop through the root properties
        $props += $rootProps | ForEach-Object {

            #Base name of property
            $propName = $_.Name;

            #Object to process
            $obj = $($Object.$propName)

            # Get the type, and only recurse into it if it is not one of our excluded types
            $type = ($obj.GetType()).ToString()

            # Only recurse if it's not of a type in our list
            if (!($typesToExclude.Contains($type) ) ) {

                #Path to property
                $childPathName = "$PathName.$propName"

                # Make sure it's not null, then recurse, incrementing $Level                        
                if ($null -eq $obj) {
                    Get-Properties -Object $obj -PathName $childPathName -Level ($Level + 1) -MaxLevels $MaxLevels 
                }
            }
        }
    }

    if ($Level -eq 0) { $ErrorActionPreference = $oldErrorPreference }
    $props
}

function Convert-Bytes {
    # Converts input number (bytes) into human readable format, up to Petabytes.
    [Alias('2b', 'convertbytes')]
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipeline)]$int,
        [ValidateSet("Auto", "KB", "MB", "GB", "TB")][string]$format = "Auto",
        [ValidateRange(0, 4)][ValidateSet(0, 1, 2, 3, 4)][int]$decimalPlaces = 2
    )

    switch ($format) {
        "KB" { "{0:n$decimalPlaces} KB" -f ($int / 1KB) }
        "MB" { "{0:n$decimalPlaces} MB" -f ($int / 1MB) }
        "GB" { "{0:n$decimalPlaces} GB" -f ($int / 1GB) }
        "TB" { "{0:n$decimalPlaces} TB" -f ($int / 1TB) }
        "Auto" {
            switch -Regex ([math]::truncate([math]::log($int, 1024))) {
                '^0' { "$int Bytes" }
                '^1' { "{0:n$decimalPlaces} KB" -f ($int / 1KB) }
                '^2' { "{0:n$decimalPlaces} MB" -f ($int / 1MB) }
                '^3' { "{0:n$decimalPlaces} GB" -f ($int / 1GB) }
                '^4' { "{0:n$decimalPlaces} TB" -f ($int / 1TB) }
                Default { "{0:n$decimalPlaces} PB" -f ($int / 1pb) }
            }
        }
    }
}


function Get-UserVariables {
    # User-Defined Variables.
    [Alias('guv')]
    param()
    Get-Variable | Where-Object { (@(
                "FormatEnumerationLimit",
                "MaximumAliasCount",
                "MaximumDriveCount",
                "MaximumErrorCount",
                "MaximumFunctionCount",
                "MaximumVariableCount",
                "PGHome",
                "PGSE",
                "PGUICulture",
                "PGVersionTable",
                "PROFILE",
                "PSSessionOption",
                "psISE",
                "psUnsupportedConsoleApplications"
            ) -notcontains $_.name) -and `
        (([psobject].Assembly.GetType('System.Management.Automation.SpecialVariables').GetFields('NonPublic,Static') | Where-Object FieldType -EQ ([string]) | ForEach-Object GetValue $null)) -notcontains $_.name
    }
}


function Clear-UserVariables {
    # This will get all User-Defined variables within the PowerShell session and delete them.
    [Alias('cuv')]
    param()

    $userVars = Get-UserVariables | Select-Object Name

    for ($i = 0; $i -lt $userVars.Count; $i++) {
        $var = $userVars[$i].Name
        Write-Output "Removing Variable: $var"
        Remove-Variable $var -Scope Global
    }
}

function Repeat {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)][scriptblock] $ScriptBlock,
        [int] $Sleep = 10,
        [int] $Count = 0
    )

    $IsInfinite = $false
    
    if ($Count -eq 0) {
        $IsInfinite = $true
        $Count = 1
    }

    do {
        if (!$IsInfinite) { $Counter-- }

        Invoke-Command $ScriptBlock -Verbose:$Verbose

        Start-Sleep $Sleep

    }while ($Count -gt 0)
}

function Get-MD5 {
    [alias("MD5")]
    param([alias("FullName")][Parameter(ValueFromPipeline)][string]$Path)
    (Get-FileHash -Path $Path -Algorithm MD5).Hash
}

function Find-Item {
    [alias('Find')]
    param([Parameter(Mandatory = $true)][string]$SearchString, [ValidateSet('Any', 'All')][string]$SearchType = "All", [int]$Depth = [int]::MaxValue)
    
    $SearchSegments = ($SearchString -replace "\W", "|").Split("|")
    $SearchResults = foreach ($Segment in $SearchSegments) { Get-ChildItem . -Recurse -Depth $Depth -Filter "*$Segment*" }
    
    if ($SearchType -eq "Any") {
        Write-Host "Searching for files matching Any of the following words:" -ForegroundColor Cyan
        Write-Host $SearchSegments
        $global:MatchedResults = $SearchResults
    }

    if ($SearchType -eq "All") {
        Write-Host "Searching for files matching All of the following words:" -ForegroundColor Cyan
        Write-Host $SearchSegments
        $global:MatchedResults = foreach ($Result in $SearchResults) {
            $IsMatch = $true
            for ($i = 0; $i -lt $SearchSegments.Count; $i++) {
                if ($Result.Name -notlike "*$($SearchSegments[$i])*") { $IsMatch = $false }
            }
            if ($IsMatch) { $Result }
        }
    }    

    if ($MatchedResults.Count -gt 0) {
        $FilteredResults = @()
        foreach ($MatchedResult in $MatchedResults) { if ($FilteredResults.FullName -notcontains $MatchedResult.FullName) { $FilteredResults += $MatchedResult } }
        Write-Host "Found the below [$($FilteredResults.Count)] result(s) for [$SearchSegments]:" -ForegroundColor Green
        Write-Host ($FilteredResults | Select-Object Name, @{N = "Type"; E = { if ($_.PSIsContainer) { "Folder" }else { $_.Extension } } }, @{N = "Directory"; E = { $_.Directory } }, FullName | Out-String).Trim() -ForegroundColor Cyan
    }
    else {
        Write-Host "No results for [$SearchSegments]." -ForegroundColor Yellow
    }
}

function Add-GuidToCsProj {
    foreach ($pathobject in (Get-ChildItem -Include *.csproj -Recurse)) {
        $path = $pathobject.fullname
        $doc = New-Object System.Xml.XmlDocument
        $doc.Load($path)
        $child = $doc.CreateElement("ProjectGuid")
        $child.InnerText = "{" + [guid]::NewGuid().ToString().ToUpper() + "}"
        $node = $doc.SelectSingleNode("//Project/PropertyGroup")
        $node.AppendChild($child)
        $doc.Save($path)
    }
}

function Get-DownloadViaBits {
    [Alias('dbits', 'dld', 'download')]
    param(
        [Parameter(Mandatory = $true)]$From,
        [Parameter(Mandatory = $false)]$To,
        [Parameter(Mandatory = $false)]$ProgressDelayMs = 1000
    )
    $ProgressDelaySeconds = $ProgressDelayMs / 1000
    $SourceFileName = $From.Split("/")[-1]
    $DestinationFilePath = if (![string]::IsNullOrEmpty($To)) {
        $To
    }
    else {
        "$PWD\$SourceFileName"
    }
    Write-Host "Downloading [$SourceFileName] from [$From] and saving to [$DestinationFilePath]"
    try {
        $startTime = (Get-Date)
        $downloadJob = Start-BitsTransfer -Source $From -Destination $DestinationFilePath -Asynchronous -TransferType Download
        [nullable[double]]$secondsRemaining = $null
        while (($downloadJob.JobState -eq "Transferring") -or ($downloadJob.JobState -eq "Connecting")) {
            $downloaded = $downloadJob.BytesTransferred
            $percentage = ($downloaded / $downloadJob.BytesTotal) * 100
            $downloadSpeed = if ($previousDownloaded -gt 0) { (($downloaded - $previousDownloaded) * $ProgressDelaySeconds) }else { 0 }
            $progressParams = @{
                Activity         = "Downloading [$SourceFileName] to '$DestinationFilePath'"
                CurrentOperation = "Downloaded [$(2b $downloaded)/$(2b $downloadJob.BytesTotal)] ($($percentage.ToString("n2"))%): $(Convert-Bytes $downloadSpeed)/s"
                PercentComplete  = $percentage
            }

            if ($secondsRemaining) { $progressParams.SecondsRemaining = $secondsRemaining }

            Write-Progress @progressParams
            Start-Sleep -Seconds $ProgressDelaySeconds
                    
            $elapsedTime = New-TimeSpan $downloadJob.CreationTime (Get-Date)
            if ($downloaded -gt 0 -and $elapsedTime.TotalMilliseconds -ge $ProgressDelayMs) {
                $previousDownloaded = $downloaded
                $secondsRemaining = (($elapsedTime.TotalMilliseconds / $downloaded) * (($downloadJob.BytesTotal - $downloaded))) / 1000
            }
        }
        $endTime = $downloadJob.TransferCompletionTime
        $downloadJob | Complete-BitsTransfer
        Write-Log "Time Taken: $((New-TimeSpan $startTime $endTime).ToString("mm\:ss\.ms")) (mm:ss.ms)"
        return Get-Item $DestinationFilePath
    }
    catch {
        $downloadJob | Remove-BitsTransfer
        throw $_.Exception.Message
    }
}

class DeleteBuffer {
    [System.Collections.ArrayList]$DeletedItems
    [System.Collections.ArrayList]$BinItems
    [int]$Count

    DeleteBuffer() {
        $this.DeletedItems = New-Object System.Collections.ArrayList
        $this.BinItems = New-Object System.Collections.ArrayList
    }

    DeleteBuffer([bool]$IncludeRecycleBinItems) {
        $this.DeletedItems = New-Object System.Collections.ArrayList
        $this.BinItems = New-Object System.Collections.ArrayList
        $this.AddRecyleBinItems()
    }

    AddRecyleBinItems() {
        foreach ($item in Get-RecycleBinItems | Where-Object { -not $_.IsFolder }) {
            $itemDetails = Get-RecycleBinItemDetails $item
            $this.AddItem($itemDetails.Name, $itemDetails.OriginalFullName, "SendToRecycleBin", $itemDetails.Modified)
        }
        $this.UpdateCount()
    }

    ClearBuffer() {
        Write-Log "Clearing Full Delete Buffer"
        $this.DeletedItems.Clear()
        $this.BinItems.Clear()
        $this.UpdateCount()
    }

    ClearDeletedItems() {
        Write-Log "Clearing Deleted Items"
        $this.DeletedItems.Clear()
        $this.UpdateCount()
    }

    ClearBinItems() {
        Write-Log "Clearing Bin Items"
        $this.BinItems.Clear()
        $this.UpdateCount()
    }

    [DeleteBufferItem[]] GetItems() {
        $items = @()
        foreach ($item in $this.BinItems) { $items += $item }
        foreach ($item in $this.DeletedItems) { $items += $item }
        return $items
    }

    [DeleteBufferItem] GetLatestRecycledItem() {
        return $this.BinItems | Sort-Object -Property DeletedTime -Descending | Select-Object -First 1
    }

    hidden UpdateCount() {
        $this.Count = $this.BinItems.Count + $this.DeletedItems.Count
    }

    AddItem($Name, $Path, $DeleteMode) {
        switch ($DeleteMode) {
            "SendToRecycleBin" { $this.BinItems.Add([DeleteBufferItem]::new($Name, $Path, $DeleteMode)) >$null }
            "DeletePermanently" { $this.DeletedItems.Add([DeleteBufferItem]::new($Name, $Path, $DeleteMode)) >$null }
        }
        $this.UpdateCount()
    }

    AddItem($Name, $Path, $DeleteMode, $DeletedTime) {
        switch ($DeleteMode) {
            "SendToRecycleBin" { $this.BinItems.Add([DeleteBufferItem]::new($Name, $Path, $DeleteMode, $DeletedTime)) >$null }
            "DeletePermanently" { $this.DeletedItems.Add([DeleteBufferItem]::new($Name, $Path, $DeleteMode, $DeletedTime)) >$null }
        }
        $this.UpdateCount()
    }

    RemoveItem([DeleteBufferItem]$Item) {
        switch ($Item.DeleteMode) {
            "SendToRecycleBin" { $this.BinItems.Remove($Item) >$null }
            "DeletePermanently" { $this.DeletedItems.Remove($Item) >$null }
        }
        $this.UpdateCount()
    }

    Undo() {
        $deletedItem = $this.BinItems | Sort-Object -Property DeletedTime -Descending | Select-Object -First 1
        if ($deletedItem) {
            try {
                $deletedItem.Restore()
            }
            catch {
                Write-Error "Failed to Undo"
            }
        }
        else {
            Write-Log "Nothing to Undo"
        }
        $this.UpdateCount()
    }
}

class DeleteBufferItem {
    [string]$Name
    [string]$Path
    [string]$DeleteMode
    [datetime]$DeletedTime
    [pscustomobject]$BinItem

    DeleteBufferItem ([string]$Name, [string]$Path, [string]$DeleteMode) {
        $this.Name = $Name
        $this.Path = $Path
        $this.DeleteMode = $DeleteMode
        $this.DeletedTime = (Get-Date)
        $this.BinItem = if ($DeleteMode -eq "SendToRecycleBin") { Get-RecycleBinItemDetails (Get-RecycleBinItem -Name $this.Name) }
    }

    DeleteBufferItem ([string]$Name, [string]$Path, [string]$DeleteMode, [datetime]$DeletedTime) {
        $this.Name = $Name
        $this.Path = $Path
        $this.DeleteMode = $DeleteMode
        $this.DeletedTime = $DeletedTime
        $this.BinItem = if ($DeleteMode -eq "SendToRecycleBin") { Get-RecycleBinItemDetails (Get-RecycleBinItem -Name $this.Name) }
    }

    Restore() {
        if ($this.DeleteMode -eq "SendToRecycleBin") {
            if (Restore-RecycleBinItem -Name $this.Name) {
                $global:DeleteBuffer.RemoveItem($this)
            }
        }
        else {
            Write-Log ("This file '{0}' is permanently deleted and cannot be restored." -f $this.Name)
        }
    }

    Restore([bool]$Overwrite) {
        if ($this.DeleteMode -eq "SendToRecycleBin") {
            if (Restore-RecycleBinItem -Name $this.Name -Overwrite) {
                $global:DeleteBuffer.RemoveItem($this)
            }
        }
        else {
            Write-Log ("This file '{0}' is permanently deleted and cannot be restored." -f $this.Name)
        }
    }

    Restore([string]$DestinationPath) {
        if ($this.DeleteMode -eq "SendToRecycleBin") {
            if (Restore-RecycleBinItem -Name $this.Name -DestinationPath $DestinationPath) {
                $global:DeleteBuffer.RemoveItem($this)
            }
        }
        else {
            Write-Log ("This file '{0}' is permanently deleted and cannot be restored." -f $this.Name)
        }
    }

    Restore([string]$DestinationPath, [bool]$Overwrite) {
        if ($this.DeleteMode -eq "SendToRecycleBin") {
            if (Restore-RecycleBinItem -Name $this.Name -DestinationPath $DestinationPath -Overwrite) {
                $global:DeleteBuffer.RemoveItem($this)
            }
        }
        else {
            Write-Log ("This file '{0}' is permanently deleted and cannot be restored." -f $this.Name)
        }
    }
}

function Get-RecycleBinItems {
    $shell = New-Object -com shell.application
    $rb = $shell.Namespace(10)

    return $rb.Items()
}

function Get-RecycleBinItem {
    [alias('bin')]
    param(
        [Parameter(Mandatory = $false)]$Name = "ALL"
    )

    $BinItems = Get-RecycleBinItems

    if ($Name -eq "ALL") {
        return $BinItems
    }
    else {
        return $BinItems | Where-Object { $_.Name -eq $Name } | Sort-Object ModifyDate -Descending | Select-Object -First 1
    }
}

function Get-RecycleBinItemDetails {
    [alias('parseitem')]
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Item
    )
    #this function relies variables set in a parent scope
    Process {
        # Write-Log "[ PROCESS ] Processing $($item.path)"
        
        # uncomment for troubleshooting
        # $global:raw += $item
        if ($item.IsFolder -AND ($item.type -notmatch "ZIP")) {
            Write-Log "Enumerating $($item.name)"
            Try {
                #track the path name through each child object
                if ($fldpath) {
                    $fldpath = Join-Path -Path $fldPath -ChildPath $item.GetFolder.Title
                }
                else {
                    $fldPath = $item.GetFolder.Title
                }
                #recurse through child items
                $item.GetFolder().Items() | ParseItem
                Remove-Variable -Name fldpath
            }
            Catch {
                # Uncomment for troubleshooting
                # $global:rbwarn += $item
                Write-Warning ($item | Out-String)
                Write-Warning $_.exception.message
            }
        }
        else {
            #sometimes the original location is stored in an extended property
            $data = $item.ExtendedProperty("infotip").split("`n") | Where-Object { $_ -match "Original location" }
            if ($data) {
                $origPath = $data.split(":", 2)[1].trim()
                $full = Join-Path -Path $origPath -ChildPath $item.name -ErrorAction stop
                Remove-Variable -Name data
            }
            else {
                #no extended property so use this code to attemp to rebuild the original location
                if ($item.parent.title -match "^[C-Zc-z]:\\") {
                    $origPath = $item.parent.title
                }
                elseif ($fldpath) {
                    $origPath = $fldPath
                }
                else {
                    $test = $item.parent
                    Write-Host "searching for parent on $($test.self.path)" -ForegroundColor cyan
                    do { $test = $test.parentfolder; $save = $test.title } until ($test.title -match "^[C-Zc-z]:\\" -OR $test.title -eq $save)
                    $origPath = $test.title
                }

                $full = Join-Path -Path $origPath -ChildPath $item.name -ErrorAction stop
            }

            [pscustomobject]@{
                PSTypename       = "DeletedItem"
                Name             = $item.name
                Path             = $item.Path
                Modified         = $item.ModifyDate
                OriginalPath     = $origPath
                OriginalFullName = $full
                Size             = $item.Size
                IsFolder         = $item.IsFolder
                Type             = $item.Type
            }
        }
    } #process
}

function Remove-ItemCustom {
    [alias('rm', 'rmf')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][object[]]$Paths,
        [Parameter(Mandatory = $false)][switch]$Force
    )
    if ($MyInvocation.Line -match 'rmf' -or $Force) { $FileMessage = "Permanently deleting '{0}'."; $DeleteMode = "DeletePermanently" }else { $FileMessage = "Sending '{0}' to Recycle Bin."; $DeleteMode = "SendToRecycleBin" }
    foreach ($path in $Paths) {
        $item = Get-Item -Path $path -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            Write-Error ("'{0}' not found" -f $Path)
        }
        else {
            $fullpath = $item.FullName
            Write-Log ($FileMessage -f $fullpath)
            if (Test-Path -Path $fullpath -PathType Container) {
                [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($fullpath, 'OnlyErrorDialogs', $DeleteMode)
            }
            else {
                [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($fullpath, 'OnlyErrorDialogs', $DeleteMode)
            }
            $global:DeleteBuffer.AddItem($item.Name, $fullpath, $DeleteMode)
        }
    }
}

function Undo-RemoveItemToRecycleBin {
    [alias('undo')]
    param()
    try {
        $global:DeleteBuffer.Undo()
    }
    catch {
        Write-Error "Failed to Undo delete operation.`n$($_.Exception.Message)"
    }
}

Function Restore-RecycleBinItem {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)][string]$DestinationPath,
        [Parameter(Mandatory = $false)][switch]$Overwrite
    )
    try {
        Write-Log ("Restoring '{0}' from Recycle Bin." -f $Name)
        $binItem = Get-RecycleBinItemDetails (Get-RecycleBinItem $Name)
        if ($binItem.IsFolder) {
            [Microsoft.VisualBasic.FileIO.FileSystem]::MoveDirectory($binItem.Path, $binItem.OriginalFullName)
        }
        else {
            $destination = if ([string]::IsNullOrEmpty($DestinationPath)) {
                $binItem.OriginalFullName
            }
            else {
                if ($DestinationPath -match "\.*\.[a-zA-Z]+$") {
                    $DestinationPath
                }
                else {
                    Join-Path -Path (Resolve-Path $DestinationPath).Path -ChildPath $binItem.Name
                }
            }
            [Microsoft.VisualBasic.FileIO.FileSystem]::MoveFile($binItem.Path, $destination, $Overwrite.IsPresent)
        }
        Write-Log ("Restored '{0}' to '{1}'." -f $binItem.Name, $destination)
        return $true
    }
    catch {
        Write-Error ("Failed to restore file '{0}' from Recycle Bin.`n{1}" -f $Item.Name, $_.Exception.Message)
    }
}

function Install-ChocoApp {
    [Alias('chocoinstall')]
    param(
        [Parameter(Mandatory = $true)][string]$App
    )
    Write-Host "#---   $App   ---------------------------------------------------------------#" -ForegroundColor Cyan
    try {
        choco install $App -y
    }
    catch {
        Write-Error "Failed to install app [$App]. $($_.Exception.Message)"
    }
    Write-Output "`n`n"
}

function Uninstall-ChocoApp {
    [Alias('chocouninstall')]
    param(
        [Parameter(Mandatory = $true)][string]$App,
        [Alias('r')][Parameter(Mandatory = $true)][switch]$Reinstall
    )
    Write-Host "#---   $App   ---------------------------------------------------------------#" -ForegroundColor Cyan
    try {
        choco uninstall $App -y
        if ($Reinstall) {
            choco install $App -y
        }
    }
    catch {
        if ($Reinstall) {
            Write-Error "Failed to re-install app [$App]. $($_.Exception.Message)"
        }
        else {
            Write-Error "Failed to un-install app [$App]. $($_.Exception.Message)"
        }
        
    }
    Write-Output "`n`n"
}

function Update-ChocoApp {
    [Alias('chocoupdate', 'chocoupgrade')]
    param(
        [Parameter(Mandatory = $true)][string]$App
    )
    Write-Host "#---   $App   ---------------------------------------------------------------#" -ForegroundColor Cyan
    try {
        choco upgrade $App -y
    }
    catch {
        Write-Error "Failed to update/upgrade app [$App]. $($_.Exception.Message)"
    }
    Write-Output "`n`n"
}

function Get-PropertyTree {
    param(
        [Parameter(Mandatory = $true)][object]$InputObject,
        [Parameter(Mandatory = $false)][string]$ParentId
    )
    Write-Verbose "$($MyInvocation | Select-Object * | Out-String)" -Verbose
    $InputObjectProperties = $InputObject.psobject.properties | Where-Object MemberType -EQ NoteProperty
    if ($null -eq $script:PropertyTree) {
        $script:PropertyTree = New-Object System.Collections.ArrayList
        $script:RootPropertyCount = $InputObjectProperties.Count
        $script:RootCounter = 0
    }
    # $CurrentParentId = if($InputObject -eq $PropertyTreeRoot.Object){$script:PropertyTreeRoot.ID}else{$ParentId}
    for ($i = 0; $i -lt $InputObjectProperties.Count; $i++) {
        $script:RootCounter++
        # $Property = $InputObjectProperties[$i]
        $PropertyName = $Property.Name
        $CurrentObjectId = (New-Guid).Guid
        $ObjectProperties = $InputObject.($PropertyName).psobject.properties | Where-Object MemberType -EQ NoteProperty
        # $script:PropertyTree +=
        $script:PropertyTree.Add( 
            [pscustomobject]@{
                Name   = $PropertyName
                ID     = $CurrentObjectId
                Object = $InputObject.($PropertyName)
                Parent = $ParentId
            }) >$null

        foreach ($SubProperty in $ObjectProperties) {
            # $SubProperty = $ObjectProperties[0]
            Get-PropertyTree -InputObject $InputObject.($PropertyName).($SubProperty.Name) -ParentId $CurrentObjectId
        }
    }
    if ($script:RootCounter -eq $script:RootPropertyCount) {
        return $script:PropertyTree
    }
}

function Merge-ObjectProperties {
    param(
        [Parameter(Mandatory = $true)][object]$FirstObject,
        [Parameter(Mandatory = $false)][object]$SecondObject,
        [Parameter(Mandatory = $false)][hashtable]$Replacements,
        [Parameter(Mandatory = $false, DontShow)][object]$ParentObject
    )
    # Write-Host $FirstObject
    # Write-Host $SecondObject
    if ($null -eq $script:BaseObject) { $script:BaseObject = $FirstObject }
    $CurrentObject = [pscustomobject]@{
        Name         = ""
        Properties   = $FirstObject.PsObject.Properties | Where-Object MemberType -EQ NoteProperty | Select-Object @{N = "Name"; E = { $_.Name } }, @{N = "Value"; E = { $_.Value } }, @{N = "Type"; E = { $FirstObject.($_.Name).GetType().Name } } | Format-List
        Object       = $FirstObject
        ParentObject = $ParentObject
    }
    $IsBaseProperty = (($script:BaseObject | Get-Member -MemberType NoteProperty).Name -contains $CurrentObject.Name)
    if ($IsBaseProperty) { $script:PropertyChain = @() }
    $ObjectProperties = $FirstObject | Get-Member -MemberType NoteProperty
    if ($ObjectProperties.Count -gt 0) {
        foreach ($Property in $ObjectProperties) {
            $PropertyName = $Property.Name
            $FirstObjectProp = $FirstObject.($PropertyName)
            $SecondObjectProp = $SecondObject.($PropertyName)
            
            $OutputObject = [pscustomobject]@{Property = $null; BaseType = $FirstObjectProp.GetType().Name; BaseValue = $FirstObjectProp; SecondValue = $SecondObjectProp }
            if ($FirstObjectProp -is [pscustomobject]) {
                $script:PropertyChain += "{$PropertyName}"
                if ($null -ne $SecondObjectProp) {
                    Merge-ObjectProperties -FirstObject $FirstObject.($PropertyName) -SecondObject $SecondObject.($PropertyName)
                }
                else {
                    Merge-ObjectProperties -FirstObject $FirstObject.($PropertyName)
                }
            }
            elseif ($FirstObjectProp -is [array]) {
                $script:PropertyChain += "[$PropertyName]"
                for ($i = 0; $i -lt $FirstObjectProp.Count; $i++) {
                    if ($null -ne $SecondObjectProp) {
                        Merge-ObjectProperties -FirstObject $FirstObjectProp[$i] -SecondObject $SecondObjectProp[$i]
                    }
                    else {
                        Merge-ObjectProperties -FirstObject $FirstObjectProp[$i]
                    }
                }
            }
            else {
                $script:PropertyChain += "$PropertyName"
                $OutputObject.Property = $script:PropertyChain -join "."
                Write-Host "$(($OutputObject | Out-String).Trim())`n"
                $RegexPattern = "\{\{([^\}]+)\}\}"
                $FirstObjectProp = $FirstObjectProp -replace $RegexPattern, '$1'
                $Replacement = if ($null -ne $Replacements) {
                    $Replacements.GetEnumerator() | Where-Object { $_.Key -eq $FirstObjectProp } | Select-Object -exp Value
                }
                if (![string]::IsNullOrEmpty($Replacement)) {
                    $FirstObject.($PropertyName) = $Replacement
                    Write-Host "Updated Property [$($OutputObject.Property) = $Replacement] via Replacement"
                }
                else {
                    if ($null -ne $SecondObjectProp) {
                        if ($null -eq $FirstObjectProp -or $FirstObjectProp.Count -le 0 -or [string]::IsNullOrEmpty($FirstObjectProp)) {
                            Write-Host "Updated Property [$($OutputObject.Property) = $($SecondObjectProp)] from SecondObject"
                            $FirstObject.($PropertyName) = $SecondObjectProp
                        }
                    }
                }
            }
        }
    }
}

function Get-FileFromZip {
    param(
        [Parameter(Mandatory = $true)]$ZipFilePath,
        [Parameter(Mandatory = $true)]$FileName
    )
    $zipFile = [System.IO.Compression.ZipFile]::Open("$ZipFilePath", "Update")
    $entry = $zipFile.Entries.Where({ $_.name -eq $FileName })
    $file = [System.IO.StreamReader]($entry).Open()
    $content = $file.ReadToEnd()
    $file.Close()
    $zipFile.Dispose()

    return $content
}

function Update-FileInZip {
    param(
        [Parameter(Mandatory = $true)]$ZipFilePath,
        [Parameter(Mandatory = $true)]$FileName,
        [Parameter(Mandatory = $true)]$Content
    )
    $zipFile = [System.IO.Compression.ZipFile]::Open("$ZipFilePath", "Update")
    $entry = $zipFile.Entries.Where({ $_.name -eq $FileName })
    $file = [System.IO.StreamWriter]($entry).Open()
    $file.BaseStream.SetLength(0)
    $file.Write($Content)
    $file.Flush()
    $file.Close()
    Write-Output "Updated [$FileName] in zip file."
    $zipFile.Dispose()
}

function Get-ReverseString {
    [cmdletbinding()]
    [alias('gr')]
    param(
        [Parameter(Mandatory = $true)][string]$InputString
    )
    $CharArray = [char[]]$InputString
    $CharArray = $InputString.ToCharArray()
    [array]::Reverse($CharArray)
    $OutputString = -join ($CharArray)
    return $OutputString
}

function ConvertTo-Base64 {
    [cmdletbinding()]
    [alias('tobase64')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)][string]$InputString
    )
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $Base64String = [Convert]::ToBase64String($Bytes)
    return $Base64String
}

function ConvertFrom-Base64 {
    [cmdletbinding()]
    [alias('frombase64')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)][string]$InputString
    )
    $DecodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($InputString))
    return $DecodedText
}

$global:DeleteBuffer = [DeleteBuffer]::new()
# $global:DeleteBuffer = [DeleteBuffer]::new($true)


Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Imported Miscellaneous Utilities Module" -ForegroundColor Cyan