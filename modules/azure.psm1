# Azure/DevOps Utilities/Functions

function Set-AzSubscription {
    [alias('azsub')]
    [cmdletbinding()]
    param()
    DynamicParam {
        $azSubscriptionsPs = Get-AzSubscription
        $subscriptionNamesAndIds = $azSubscriptionsPs | ForEach-Object { $_.Name; $_.Id }
        New-DynamicParam -Name Subscription -ValidateSet $subscriptionNamesAndIds -Position 0 -Mandatory
    }
    begin {
        $Subscription = $PSBoundParameters.Subscription
    }
    process {
        Select-AzSubscription $Subscription
    }
}

function Set-AzCliSubscription {
    [Alias('azset')]
    [cmdletbinding()]
    param()
    DynamicParam {
        $azSubscriptionsCli = az account list --query '[].{Name: name, Id: id}' | Out-String | ConvertFrom-Json
        $subscriptionNamesAndIds = $azSubscriptionsCli | ForEach-Object { $_.Name; $_.Id }
        New-DynamicParam -Name Subscription -ValidateSet $subscriptionNamesAndIds -Position 0 -Mandatory
    }
    begin {
        $Subscription = $PSBoundParameters.Subscription
    }
    process {
        az account set -s $Subscription
        Write-Output "Loaded Subscription: $Subscription"
    }
}

function Connect-MSGraph {
    # Sets up the global variable $ApiAccessHeaders used for Invoke-RestMethod calls to Microsoft/Azure APIs.
    [alias('Login-MSGraph')]
    param(
        [PSCredential]$ClientCredentials,
        [parameter(Mandatory = $true)][ValidateSet("https://graph.microsoft.com/", "https://graph.windows.net/", "https://management.azure.com", "https://management.core.windows.net/", "https://storage.azure.com/", "https://vault.azure.net", "https://database.windows.net")][string]$ResourceUrl,
        [string]$TenantId,
        [object]$ExtraHeaders = $null,
        [switch]$Force
    )
    #Connect-Azure
    if ( $ApiAccessHeaders.TokenExpiry -le (Get-Date) -or $ApiAccessHeaders.Resource -ine $ResourceUrl -or $Force) {
        $ClientCredentials = if ($null -eq $ClientCredentials) { $ApiCredential }else { $ClientCredentials } # ApiCredential comes from Connect-Azure if parameters and keyVault/Secret is valid.

        if ([string]::IsNullOrEmpty($TenantId)) { $TenantId = (Get-AzContext).Tenant.Id }

        $LoginUrl = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        $LoginParams = @{'grant_type' = 'client_credentials'; 'client_id' = $($ClientCredentials.UserName); 'client_secret' = $($ClientCredentials.GetNetworkCredential().Password); 'resource' = $ResourceUrl }

        $Response = Invoke-RestMethod -Method POST -ContentType 'application/x-www-form-urlencoded' -Body $LoginParams -Uri $LoginUrl
        $global:ApiAccessHeaders = @{'Authorization' = "$($Response.token_type) $($Response.access_token)"; 'Resource' = $ResourceUrl; "TokenExpiry" = (Get-Date).AddSeconds(3600); 'TenantId' = $TenantId }
        if ($null -ne $ExtraHeaders) { $global:ApiAccessHeaders += $ExtraHeaders }
        Write-Output "API Access Token for $ResourceUrl saved to `$ApiAccessHeaders variable."
    }
}

function Invoke-AzureCliCommand {
    [alias('azj')]
    param()

    $azOutput = az.cmd $args | Out-String
    [console]::ResetColor()
    try {
        $azOutput | ConvertFrom-Json
    }
    catch {
        $azOutput
    }
    [console]::ResetColor() # Some times console colours are changed to what is in the output so this resets it.
}



Write-Host "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss") |" "Imported Azure Module" -ForegroundColor Cyan