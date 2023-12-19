#Param
param ($au2matorhook)
$jsondata = $au2matorhook | ConvertFrom-Json
$jsondata | Out-File -FilePath "C:\_SCOworkingDir\TFS\PS-Services\AZURE - Assign Role to Azure Resource Group\out.txt"

$c_Subscription=$jsondata.c_Subscription

#Environment
[string]$CredentialStorePath = "C:\_SCOworkingDir\TFS\PS-Services\CredentialStore" #see for details: https://click.au2mator.com/PSCreds/?utm_source=github&utm_medium=social&utm_campaign=PS_Template&utm_content=PS1
[string]$LogPath = "C:\_SCOworkingDir\TFS\PS-Services\AZURE - Assign Role to Azure Resource Group"
[string]$LogfileName = "Question-GetSubscriptions"


$AzureRestAPICred_File = "AzureRestCreds.xml"
$AzureRestAPICred = Import-CliXml -Path (Get-ChildItem -Path $CredentialStorePath -Filter $AzureRestAPICred_File).FullName
$AzureRestAPI_clientId = $AzureRestAPICred.clientId
$AzureRestAPI_clientSecret = $AzureRestAPICred.clientSecret
$AzureRestAPI_tenantID = $AzureRestAPICred.tenantID

$apiversion = "2021-04-01"


#region Functions
function Write-au2matorLog {
    [CmdletBinding()]
    param
    (
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
        [string]$Type,
        [string]$Text
    )

    # Set logging path
    if (!(Test-Path -Path $logPath)) {
        try {
            $null = New-Item -Path $logPath -ItemType Directory
            Write-Verbose ("Path: ""{0}"" was created." -f $logPath)
        }
        catch {
            Write-Verbose ("Path: ""{0}"" couldn't be created." -f $logPath)
        }
    }
    else {
        Write-Verbose ("Path: ""{0}"" already exists." -f $logPath)
    }
    [string]$logFile = '{0}\{1}_{2}.log' -f $logPath, $(Get-Date -Format 'yyyyMMdd'), $LogfileName
    $logEntry = '{0}: <{1}> <{2}> <{3}> {4}' -f $(Get-Date -Format dd.MM.yyyy-HH:mm:ss), $Type, $RequestId, $Service, $Text
    Add-Content -Path $logFile -Value $logEntry
}

#endregion Functions

try {
    Write-au2matorLog -Type INFO -Text "Try to connect to Azure Rest API"
    
    $param = @{
        Uri    = "https://login.microsoftonline.com/$AzureRestAPI_tenantID/oauth2/token?api-version=$apiversion";
        Method = 'Post';
        Body   = @{ 
            grant_type    = 'client_credentials'; 
            resource      = 'https://management.core.windows.net/'; 
            client_id     = $AzureRestAPI_clientId; 
            client_secret = $AzureRestAPI_clientSecret
        }
    }
      
    $result = Invoke-RestMethod @param
    $token = $result.access_token
          
      
    $headers = @{
        "Authorization" = "Bearer $($token)"
        "Content-type"  = "application/json"
    }
    
    try {
        Write-au2matorLog -Type INFO -Text "Try to get Resource Groups"

        $URL = "https://management.azure.com/subscriptions/$c_Subscription/resourceGroups?api-version=$apiversion"
        
        $ResourceGroups = Invoke-RestMethod -Method GET -URI $URL -headers $headers 
        $ResList = @()

        foreach ($Res in $ResourceGroups.value) {
            $PSObject = New-Object -TypeName PSObject
            $PSObject | Add-Member -MemberType NoteProperty -Name Name -Value $Res.name
            $PSObject | Add-Member -MemberType NoteProperty -Name location -Value $Res.location
                        
            $ResList += $PSObject
        }
    }
    catch {
        Write-au2matorLog -Type ERROR -Text "Error to get Subscriptions"
        Write-au2matorLog -Type ERROR -Text $Error
    
        $au2matorReturn = "Error to get Subscriptions, Error: $Error"
        $TeamsReturn = "Error to get Subscriptions" #No Special Characters allowed
        $AdditionalHTML = "Error to get Subscriptions
        <br>
        Error: $Error
            "
        $Status = "ERROR"
    }
}
catch {
    Write-au2matorLog -Type ERROR -Text "Failed to connect to Azure Rest API"
    Write-au2matorLog -Type ERROR -Text $Error

    $au2matorReturn = "Failed to connect to Azure Rest API, Error: $Error"
    $TeamsReturn = "Failed to connect to Azure Rest API" #No Special Characters allowed
    $AdditionalHTML = "Failed to connect to Azure Rest API
    <br>
    Error: $Error
        "
    $Status = "ERROR"
}

return $ResList