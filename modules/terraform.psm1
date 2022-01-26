# Terraform Utilities/Functions

function Invoke-Terraform {
    [alias('tf')]
    param()
    terraform $($args)
}

function Set-Backend {
    [alias('tfb')]
    param(
        [alias('p')][parameter(Mandatory = $false)][string]$Project,
        [alias('t')][parameter(Mandatory = $false)][ValidateSet("DEVTEST", "TESTDEV", "UATPREPROD", "PRODUAT", "PROD")][string]$Type,
        [alias('e')][parameter(Mandatory = $false)][string]$Environment,
        [alias('k')][parameter(Mandatory = $false)][string]$Key
    )
    $existingConfig = (Get-Content backend.tf -Raw -ErrorAction SilentlyContinue).Split("`n")
    
    if ($existingConfig) {
        if ([string]::IsNullOrEmpty($Project)) {
            $Project = [regex]::Match($existingConfig[2], '".*"').Value.Trim('"').Split('-')[1]
        }
        if ([string]::IsNullOrEmpty($Type)) {
            $Type = [regex]::Match($existingConfig[2], '".*"').Value.Trim('"').Split('-')[2]
        }
        if ([string]::IsNullOrEmpty($Environment)) {
            $Environment = [regex]::Match($existingConfig[4], '(-[^"]+)"').Value.Trim(@('"', '-'))
        }
        if ([string]::IsNullOrEmpty($Key)) {
            $Key = [regex]::Match($existingConfig[5], '"([^"]+)"').Value.Trim('"')
        }
    }
    $Prefix = switch -Regex ($Type) { "DEV|TEST" { "MATA" }"UAT|PROD" { "MAPA" }"PROD" { "MAPA" } }
    $ResourceGroup = "$Prefix-$Project-$Type-TFSTATE"
    $StorageAccountName = $ResourceGroup.ToLower().Replace('-', '')
    $ContainerName = "tfstate-$Environment".ToLower()
    $backendConfigApp = @"
terraform {
  backend "azurerm" {
    resource_group_name  = "$ResourceGroup"
    storage_account_name = "$StorageAccountName"
    container_name       = "$ContainerName"
    key                  = "$Key"
  }
}
"@
    Write-Host "Backend Config =`n$($backendConfigApp | Out-String)"
    $backendConfigApp | Out-File "backend.tf" -Encoding default -Force
}

function Format-Terraform { [alias('fmt')]param([alias('r')][switch]$Recursive)if ($Recursive) { Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Terraform: fmt -recursive"; terraform fmt -recursive }else { Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Terraform: fmt"; terraform fmt } }

function Remove-TFState { [alias('tfr')]param()Get-ChildItem -Recurse -Filter '*.tfstate' | Remove-Item -Force }

function Initialize-TFState { [alias('tfi')]param()Remove-TFState; terraform init }

function Set-TerraformEnvironment { [alias('tfe')]param([alias('e')][string]$Environment)$env:TF_VAR_environment = $Environment }

function Invoke-TerraformApply { [alias('apply', 'atf')]param()terraform apply "plan" }

function Update-Terraform {
    param(
        [string]$TargetVersion = "latest", # Must follow format like '1.1.4', default value looks for latest.
        [switch]$Force
    )
    
    try {
        $TerraformFolder = "C:\terraform"
        $MachinePath = [environment]::GetEnvironmentVariable('Path', 'Machine')
        if ($MachinePath -notmatch 'terraform') { [environment]::SetEnvironmentVariable('Path', ($MachinePath + ";$TerraformFolder"), 'Machine') }
        Update-PathVariable
        if (!(Test-Path $TerraformFolder)) { mkdir $TerraformFolder -Force }
        $TerraformExePath = "$TerraformFolder\terraform.exe"
        $CurrentVersion = if ((Test-Path $TerraformExePath)) {
            (terraform version -json | ConvertFrom-Json).terraform_version
        }

        try {
            if ($TargetVersion.ToLower() -eq "latest") {
                $TargetVersion = Invoke-RestMethod 'https://checkpoint-api.hashicorp.com/v1/check/terraform' | Select-Object -exp current_version
            }
        }
        catch {
            Write-Error "Failed to check version. Try connecting to another network and try again."
        }

        $url = "https://releases.hashicorp.com/terraform/$($TargetVersion)/terraform_$($TargetVersion)_windows_amd64.zip"
        
        $TargetZip = "$TerraformFolder\terraform_$($TargetVersion)_windows_amd64.zip"

        Write-Host "Checking for version [$TargetVersion]." -ForegroundColor Cyan

        # Check current installed version
        if ($CurrentVersion -eq $TargetVersion) {
            Write-Host "Version [$TargetVersion] already installed." -ForegroundColor Green
        }
        else {
            if ([string]::IsNullOrEmpty($CurrentVersion)) {
                Write-Host "Terraform is not currently installed." -ForegroundColor Yellow
            }
            else {
                Write-Host "Current Version [$CurrentVersion] installed." -ForegroundColor Cyan
            }

            if (!$Force -and (Read-Host "Do you want to install version $($TargetVersion)? (Y/N)").ToLower() -ne 'y') {
                Write-Host "Update/Install cancelled..."
                break
            }
            

            # Check if already have downloaded zip
            if (Get-ChildItem -Path $terraformFolder -Filter "*$TargetVersion*") {
                Write-Host "Version [$TargetVersion] already downloaded. Installing..." -ForegroundColor Cyan
            }
            else {
                Get-DownloadViaBits -From $url -To $TargetZip
            }

            Expand-Archive -Path $TargetZip -DestinationPath "$terraformFolder\temp" -Force
            Move-Item -Path "$terraformFolder\temp\terraform.exe" -Destination "$terraformFolder\terraform.exe" -Force
            Remove-Item -Path "$terraformFolder\temp" -Recurse -Force
            $MachinePath = [environment]::GetEnvironmentVariable('Path', 'Machine')
            if ($MachinePath -notmatch 'terraform') { [environment]::SetEnvironmentVariable('Path', ($MachinePath + ";$TerraformFolder"), 'Machine') }
            Update-PathVariable
            $InstalledVersion = (terraform version -json | ConvertFrom-Json).terraform_version
            Write-Host "Version Installed: $InstalledVersion" -ForegroundColor Green
        }
    }
    catch {
        Write-Error $_.EXCEPTION.MESSAGE
    }
}





Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Imported Terraform Module" -ForegroundColor Cyan