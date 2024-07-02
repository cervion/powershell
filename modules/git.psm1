# Git Utilities/Functions

function Get-GitStatus { [alias('status')]param()& git status }

function Get-GitBranchList {
    $branchList = foreach ($branch in ((& git branch -a).Split("`n"))) { $branch.Substring(2) }
    return $branchList | Where-Object { $_ -notmatch "HEAD" -and $_ -notmatch "origin/master" }
}
function Set-GitBranch {
    [alias('checkout')]
    [cmdletbinding()]
    param(
        [switch]$Pull
    )
    DynamicParam {
        if ((status) -match 'fatal') { break }
        $branches = Get-GitBranchList
        New-DynamicParam -Name branchName -ValidateSet $branches -Position 0 -Mandatory
    }
    begin {
        $branchName = $PSBoundParameters.branchName
    }
    process {
        if ((status) -match 'fatal') { break }
        Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Checkout - $branchName"
        $branchName = $branchName -replace 'remotes/origin/', ''
        & git checkout $branchName
        if($Pull){Invoke-GitPull}
        Set-Directory
    }
}

function Confirm-IsGitRepo { [alias('isrepo')]param()if ((Get-GitStatus) -match 'fatal') { return $false }else { return $true } }

function Set-Directory {
    [alias('cd')]
    param([string] $Path = '.')
    Set-Location $Path
    $FullPath = (Get-Item .).FullName
    if (Confirm-IsGitRepo) {
        Set-GitMainBranch
        Set-TabName "$(GitRepo)/$(GitBranch) > $FullPath"
    }
    else {
        Set-TabName $FullPath
    }
}

function Invoke-GitFetch { [alias('fetch')]param()Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Fetch"; Write-Output (& git fetch -p) }

function Invoke-GitClone {
    [alias('clone')]
    param(
        [Parameter(Mandatory = $false, Position = 1)][string]$Org = $env:AZURE_DEVOPS_ORG,
        [Parameter(Mandatory = $false, Position = 2)][string]$Project = $env:AZURE_DEVOPS_DEFAULT_PROJECT,
        [Parameter(Mandatory = $true, Position = 0)][string]$Repo
    )
    Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Clone"
    & git clone "https://$($Org)@dev.azure.com/$($Org)/$($Project)/_git/$($Repo)"
}

function Invoke-GitPull { [alias('pull')]param()Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Pull"; & git pull $args }

function Invoke-GitPush { [alias('push')]param()if ($args.Count -gt 0) { Invoke-GitCommit @args }; Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Push"; if ((& git push) -ilike '*has no upstream branch*') { $branch = Get-GitBranch; & git push -u origin $branch } }
function Invoke-GitPushForced { [alias('pushf')]param()if ($args.Count -gt 0) { Invoke-GitCommit @args -Force }; Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Push"; if ((& git push -f) -ilike '*has no upstream branch*') { $branch = Get-GitBranch; & git push -u origin $branch -f } }

function Get-GitBranches { [alias('list')]param([Alias('f')][switch]$Fetch)if ($Fetch) { Invoke-GitFetch }; Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - List All Branches"; Write-Output (& git branch -a) }

function Invoke-GitTerraformFmt { param()if ((Get-ChildItem -File -Recurse -Depth 3 -Filter '*.tf').Count -gt 0) { fmt -r } }

function Invoke-GitCommit { [alias('commit')]param()if ($args.Count -gt 0) { Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Commit - [$args]"; Invoke-GitTerraformFmt; & git add -A; & git commit -m "$args" }else { throw "Error: No args/message supplied" } }

function Invoke-GitCommitAndPush { [alias('pushm')]param()if ($args.Count -gt 0) { Invoke-GitCommit @args; Invoke-GitPush }else { throw "Error: No args/message supplied" } }

function Set-GitMainBranch { $env:GIT_MAIN_BRANCH = [regex]::Match((& git branch -a), "remotes/origin/HEAD -> [^ ]+").Value -replace '.*-> origin/(.*)', '$1' }

function Get-GitMainBranch { Set-GitMainBranch; Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Main Branch is ($env:GIT_MAIN_BRANCH)" }

function Set-GitMain { [alias('main')]param()Set-GitBranch $env:GIT_MAIN_BRANCH; Invoke-GitPull }

function New-GitBranch { [alias('branch')]param([parameter(Mandatory)]$branchName)Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Checkout New Branch - $branchName"; & git checkout -b $branchName; Set-Directory }

function Remove-GitBranch {
    [alias('delete')]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$false, Position=0)][string]$DefaultBranch = "main",
        [Parameter(Mandatory=$false, Position=2)][ValidateSet('Local', 'Remote', 'Full')][string]$scope = "Local", [switch]$Force
    )
    DynamicParam {
        if ((status) -match 'fatal') { break }
        $branches = Get-GitBranchList
        New-DynamicParam -Name branchName -ValidateSet $branches -Position 1 -Mandatory
    }
    begin {
        $branchName = $PSBoundParameters.branchName
    }
    process {
        if ((status) -match 'fatal') { break }
        Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Git - Delete Branch - $branchName"
        if ((GitBranch) -ine $DefaultBranch) { Set-GitBranch $DefaultBranch -Pull }
        if ($scope -ieq 'Full' -or $scope -ieq 'Remote' -and ($Force -or (Read-Host "Are you sure you want to delete REMOTE branch for $branchName`?") -ieq 'Y')) { & git push origin -d $branchName }
        if ($scope -ieq 'Full' -or $scope -ieq 'Local' -and ($Force -or (Read-Host "Are you sure you want to delete LOCAL branch for $branchName`?") -ieq 'Y')) { & git branch -D $branchName }
        Invoke-GitFetch
        Get-GitBranches
    }
}

function Update-GitBranches {
    [alias('clean', 'cleanf')]
    param(
        [Parameter(Mandatory=$false)][string]$DefaultBranch,
        [switch]$Force
    )
    $TargetBranch = if(![string]::IsNullOrEmpty($DefaultBranch)){$DefaultBranch}else{$env:GIT_MAIN_BRANCH}
    Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") | Git - Checking Branches to Cleanup";
    if ($MyInvocation.Line -match 'cleanf') { $Force = $true }
    if ($Force) { Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") | Force Clean" -ForegroundColor Yellow }
    Set-GitBranch $TargetBranch -Pull
    Invoke-GitFetch
    Get-GitBranches
    $localBranches = (& git branch).Split("`n").Trim() | Where-Object { $_ -inotlike "*$TargetBranch" }
    $remoteBranches = (& git branch -a).Split("`n").Trim() | Where-Object { $_ -ilike 'remotes/origin/*' -and $_ -inotlike "*$TargetBranch" }
    $hasDeletedBranches = $false
    foreach ($branch in $localBranches) {
        if ($remoteBranches -inotcontains "remotes/origin/$branch") {
            Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") | Local Branch $branch does not have remote branch" -ForegroundColor Yellow
            if ($Force -or (Read-Host "Delete? Y/N").ToUpper() -eq 'Y') { & git branch -D $branch; Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") | Local branch $branch deleted." -ForegroundColor Red; $hasDeletedBranches = $true }
        }
    }
    if ($hasDeletedBranches) {
        Invoke-GitFetch
        Get-GitBranches
    }
}

function New-AdoPullRequest { 
    [alias('pr')]
    param(
        [Parameter(Mandatory = $false)]$TargetBranch
    )
    if (Confirm-IsGitRepo) {
        $TargetRef = if(![string]::IsNullOrEmpty($TargetBranch)){$TargetBranch}else{$env:GIT_MAIN_BRANCH}
        Start-Process "https://dev.azure.com/$(Get-GitOrg)/$(Get-GitProject)/_git/$(Get-GitRepo)/pullrequestcreate?sourceRef=$(ConvertTo-UrlEncoded (Get-GitBranch))&targetRef=$TargetRef"
    }
    else {
        Write-Host "Not a Git Repo"
    }
}

function Get-GitProject { return (git remote get-url origin) -replace '.*\.com/[^/]+/([^/]+).*','$1' }

function Get-GitOrg { return (git remote get-url origin) -replace '.*\.com/([^/]+)/.*','$1' }

function Get-GitRepo { return (git remote get-url origin).Split('/')[-1] }

function Get-GitBranch { return ((git status) -split '`n')[0].Substring(10).Trim() }

function Search-Git { [alias('gits')]param([parameter(Mandatory = $true)][string]$SearchString)$cd = Get-Item . | Select-Object -exp fullname; git rev-list --all | Invoke-Parallel -ImportVariables -ScriptBlock { Set-Directory $cd; git grep -F "$SearchString" $_ } }


Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Imported Git Module" -ForegroundColor Cyan