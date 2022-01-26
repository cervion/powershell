# Azure DevOps Utilities

Set-Alias tfs "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\TF.exe"

function Get-AdoApprovedPrs {
    [Alias('adoprs')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 4)]$Project,
        [Parameter(Mandatory = $true, Position = 5)]$AdoPatToken,
        [ValidateRange(0, 30)][Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Days')]$LengthDays = 0,
        [ValidateRange(1, 72)][Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Hours')]$LengthHours = 1,
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Days')][switch]$Days,
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Hours')][switch]$Hours,
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Date')][datetime]$Date,
        [Parameter(Mandatory = $false, Position = 2)][switch]$ToClipboard,
        [Parameter(Mandatory = $false, Position = 3)][switch]$FullDetail
    )
    $TimeSpanType = $PSCmdlet.ParameterSetName
    $Length = switch ($TimeSpanType) {
        'Hours' { $LengthHours }
        'Days' { $LengthDays }
        'Date' { 24 }
    }

    if ($TimeSpanType -eq 'Days' -and $Length -eq 0) {
        Write-Host "Checking for Approved PRs for Today ($(Get-Date -Format "dd/MM/yyyy"))."
    }
    elseif ($TimeSpanType -ne 'Date') {
        Write-Host "Checking for Approved PRs for the past $Length $TimeSpanType"
    }
    else {
        Write-Host "Checking for Approved PRs for $Date"
    }

    function GetDateTimeStart {
        param(
            [Parameter(Mandatory = $true)]$InputDateTime
        )
        switch ($TimeSpanType) {
            'Hours' { return $InputDateTime -ge (Get-Date).AddHours(-$Length) }
            'Days' { return $InputDateTime.Date -ge (Get-Date).AddDays(-$Length).Date }
            'Date' { return $InputDateTime }
        }
    }

    tt {
        try {
            $topAmount = switch ($TimeSpanType) {
                'Hours' { 100 }
                'Days' { 999 }
                'Date' { 999 }
            }

            $adoCredentials = [convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f , "", $AdoPatToken)))

            $header = @{Authorization = "Basic $adoCredentials" }

            $prResponse = Invoke-AzCliCommand repos pr list -p $Project --status completed --target-branch refs/heads/master --top $topAmount
            #$prResponse = Invoke-RestMethod -Method Get -Uri $url -Headers $header
            $completedPRs = foreach ($pr in $prResponse) {
                #$pr = $prResponse[0]
                [pscustomobject]@{
                    Repo         = [pscustomobject]@{
                        Name = $pr.repository.name
                        Id   = $pr.repository.id
                    }
                    Id           = $pr.pullRequestId
                    SourceBranch = $pr.sourceRefName
                    Title        = $pr.title
                    Description  = $pr.description
                    CreatedDate  = Get-Date $pr.creationDate
                    ClosedDate   = Get-Date $pr.closedDate
                    CreatedBy    = [pscustomobject]@{
                        Name = $pr.createdBy.displayName
                        Id   = $pr.createdBy.id
                    }
                    Approver     = $null
                }
            }
            $completedPRs = $completedPRs | Where-Object { GetDateTimeStart $_.ClosedDate } | Sort-Object ClosedDate
            #$prResponse.value[5].reviewers | ? {$_.vote -gt 0 -and $_.displayname -notmatch '\\'}

            $approvers = @()

            foreach ($prObject in $completedPRs) {
                #$prObject = $completedPRs[0]
                $threads = (Invoke-RestMethod -Method Get -Uri "https://dev.azure.com/$env:AZURE_DEVOPS_ORG/$Project/_apis/git/repositories/$($prObject.Repo.Id)/pullRequests/$($prObject.Id)/threads?api-version=6.0-preview.1" -Headers $header).value.comments | Select-Object @{n = "date"; e = { (Get-Date $_.publishedDate) } }, @{n = "user"; e = { $_.author.displayName } }, content | Sort-Object date
                $votes = $threads | Where-Object { $_.content -match "voted 10" }
                $prObject.Approver = ($votes | Where-Object { $_.user -notmatch '\\' -and $_.user -ne $prObject.CreatedBy.Name } | Select-Object -First 1).user
                $approver = $approvers | Where-Object { $_.Name -eq $prObject.Approver }
                if ($approver) {
                    $approver.ApprovedPrs += $prObject
                    $approver.Count = $approver.ApprovedPrs.Count
                }
                else {
                    $approvers += [pscustomobject]@{
                        Name        = $prObject.Approver
                        Count       = 1
                        ApprovedPrs = @($prObject)
                    }
                }
            }

            $approversOutput = if ($FullDetail) {
                $approvers | Sort-Object Count -Descending
            }
            else {
                $approvers | Sort-Object Count -Descending | Format-Table Name, @{N = "ApprovedPRs"; E = { $_.Count } } -AutoSize
            }

            if ($ToClipboard) {
                ($approversOutput | Out-String).Trim() | Set-Clipboard
            }
            else {
                return $approversOutput
            }
        
        }
        catch {
            throw $_.Exception.Message
        }
    }
}

function Get-ADOPipelineVariable {
    param(
        [Parameter(Mandatory = $false, Position = 2)][string]$Project = $env:AZURE_DEVOPS_DEFAULT_PROJECT,
        [Parameter(Mandatory = $true, Position = 0)][string]$Pipeline,
        [Parameter(Mandatory = $false, Position = 1)][string]$Name = "All"
    )

    if ([string]::IsNullOrEmpty($Project)) {
        throw "Parameter Project is NULL or Empty. Please pass Project or set `$env:AZURE_DEVOPS_DEFAULT_PROJECT"
    }

    $pipelineCheck = Invoke-AzureCliCommand pipelines variable list -p $Project --pipeline-name $Pipeline --only-show-errors
    $pipelineVariables = @()
    
    foreach ($variable in $pipelineCheck.PsObject.Properties) {
        $pipelineVariables += [pscustomobject]@{
            Name          = $variable.Name
            Value         = $variable.Value.value
            AllowOverride = $variable.Value.allowOverride
            IsSecret      = $variable.Value.isSecret
        }
    }

    if ($pipelineVariables.Count -gt 0) {
        if ($Name -eq "All" -or $Name -eq "*") {
            Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Pipeline: $Pipeline (Variable: All)"
            foreach ($variable in $pipelineVariables) {
                Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "$($variable.Name) = $($variable.Value)"
            }
            return $pipelineVariables
        }
        else {
            $variable = $pipelineVariables | Where-Object { $_.Name -eq $Name }
            if ($variable) {
                Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Pipeline: $Pipeline (Variable: $Name)"
                Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "$($variable.Name) = $($variable.Value)".Trim()
                return $variable
            }
        }
    }
    else {
        Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Pipeline: $Pipeline has no variables set"
    }

    return $null
}

function Set-ADOPipelineVariable {
    [Alias('Add-ADOPipelineVariable', 'Remove-ADOPipelineVariable')]
    param(
        [Parameter(Mandatory = $false, Position = 3)][string]$Project = $env:AZURE_DEVOPS_DEFAULT_PROJECT,
        [Parameter(Mandatory = $true, Position = 0)][string]$Pipeline,
        [Parameter(Mandatory = $true, Position = 1)][string]$Name,
        [Parameter(Mandatory = $false, Position = 2)][string]$Value
    )

    $RemoveVariable = $MyInvocation.Line -match 'Remove'
    $ExistingVariable = Get-ADOPipelineVariable -Project $Project -Pipeline $Pipeline -Name $Name

    try {
        if ($RemoveVariable) {
            if ($ExistingVariable) {
                Invoke-AzureCliCommand pipelines variable delete -p $Project --pipeline-name $Pipeline --name $Name -y --only-show-errors >$null
                Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Removed variable [$Name] from pipeline [$Pipeline] in project [$Project]"
            }
        }
        else {
            if ($ExistingVariable) {
                if ($ExistingVariable.value -ne $Value) {
                    Invoke-AzureCliCommand pipelines variable update -p $Project --pipeline-name $Pipeline --name $Name --value "$Value" --only-show-errors >$null
                    Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Updated value for variable [$Name=$($ExistingVariable.value)] to [$Value] for pipeline [$Pipeline] in project [$Project]"
                }
            }
            else {
                Invoke-AzureCliCommand pipelines variable create -p $Project --pipeline-name $Pipeline --name $Name --value "$Value" --only-show-errors >$null
                Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Created variable [$Name=$Value)] for pipeline [$Pipeline] in project [$Project]"
            }
        }
    }
    catch {
        if ($RemoveVariable) {
            throw "Failed to remove/delete variable [$Name] for pipeline [$Pipeline] in project [$Project]."
        }
        else {
            throw "Failed to create/update variable [$Name=$Value] for pipeline [$Pipeline] in project [$Project]."
        }
    }
}

Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Imported Azure DevOps Module" -ForegroundColor Cyan