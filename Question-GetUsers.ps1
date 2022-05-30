#Param
param ($au2matorhook)
$jsondata = $au2matorhook | ConvertFrom-Json
$jsondata | Out-File -FilePath "C:\_SCOworkingDir\TFS\PS-Services\AZURE - Assign Role to Azure Resource Group\out.txt"

#Environment
[string]$CredentialStorePath = "C:\_SCOworkingDir\TFS\PS-Services\CredentialStore" #see for details: https://au2mator.com/documentation/powershell-credentials/?utm_source=github&utm_medium=social&utm_campaign=PS_Template&utm_content=PS1
[string]$LogPath = "C:\_SCOworkingDir\TFS\PS-Services\AZURE - Assign Role to Azure Resource Group"
[string]$LogfileName = "Question-GetUsers"


$MSGraphAPICred_File = "MSGraphAPICred.xml"
$MSGraphAPICred = Import-CliXml -Path (Get-ChildItem -Path $CredentialStorePath -Filter $MSGraphAPICred_File).FullName
$MSGraphAPI_clientId = $MSGraphAPICred.clientId
$MSGraphAPI_clientSecret = $MSGraphAPICred.clientSecret
$MSGraphAPI_tenantID = $MSGraphAPICred.tenantName



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
    Write-au2matorLog -Type INFO -Text "Try to connect to MSGraph  API"
    
    $tokenBody = @{  
        Grant_Type    = "client_credentials"  
        Scope         = "https://graph.microsoft.com/.default"  
        Client_Id     = $MSGraphAPI_clientId  
        Client_Secret = $MSGraphAPI_clientSecret  
    }   
  
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$MSGraphAPI_tenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody  

    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }
    
    try {
        Write-au2matorLog -Type INFO -Text "Try to get USers"
        $URL = "https://graph.microsoft.com/v1.0/users"
        
        $UserList = Invoke-RestMethod -Method GET -URI $URL -headers $headers 
        $ReturnList = @()

        foreach ($User in $UserList.value) {
            $PSObject = New-Object -TypeName PSObject
            $PSObject | Add-Member -MemberType NoteProperty -Name UPN -Value $User.userPrincipalName
            $PSObject | Add-Member -MemberType NoteProperty -Name Name -Value $User.displayName
            $ReturnList += $PSObject
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



return $ReturnList