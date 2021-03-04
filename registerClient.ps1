if (-not (Get-Module -ListAvailable -Name Az.Resources)) 
{     
    Write-Host "Az.Resources Module is required but it does not exist. Trying to install..."

    if ($null -eq (Get-Command "Install-Module" -CommandType Function -errorAction SilentlyContinue))
    {
        Write-Host -ForegroundColor Red "Cannot install required Powershell Module 'Az.Resources'."
        Write-Host -ForegroundColor Red "Please, update Powershell, install Windows Management Framework 5.1 or install the 'Az.Resources' module manually."
        Remove-Variable EXCHANGE_CHANNEL_APP_NAME -Force
        Exit
    }

    # Script needs to be executed with administrator privileges
    #
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    { 
        Start-Process powershell.exe "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; 
        exit 
    }

    Install-Module -Name Az.Resources -ErrorAction Stop
} 

Import-Module Az.Resources # Imports the PSADPasswordCredential object

$AppNameAzure = "AzureMonitor Client for Enterprise Alert"
$AzureRoleName = "Azure Monitor access for 3rd party systems";

$config = [pscustomobject]@{
SubscriptionId = ''
TenantId = ''
ClientId = ''
ClientSecret = ''
}

# Login to Azure
Connect-AzAccount

# Read and display all subscriptions
$subscriptions = Get-AzSubscription
$subscriptions | Format-Table -Property SubscriptionId,Name,State,TenantId

$subIndex = Read-Host -Prompt "Please enter row number of subscription to use (starting from 1)"


# Sets the tenant, subscription, and environment for cmdlets to use in the current session
Set-AzContext -SubscriptionId $subscriptions[$subIndex-1].SubscriptionId

$config.SubscriptionId = $subscriptions[$subIndex-1].SubscriptionId
$config.TenantId = $subscriptions[$subIndex-1].TenantId


$subScope = "/subscriptions/" + $config.SubscriptionId


# Create the SPN in the sub
$spnPwd = New-Guid
$date = Get-Date 
$credentials = New-Object Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential -Property @{ StartDate=Get-Date; EndDate=Get-Date -Year ($date.Year + 1); Password=$spnPwd}
$spn = New-AzADServicePrincipal -DisplayName $AppNameAzure -PasswordCredential $credentials


Write-Output "SPN created in Azure:"
$spn | Format-Table -Property ApplicationId,DisplayName,Id,ServicePrincipalNames

$config.ClientId = $spn.ApplicationId
$config.ClientSecret = $spnPwd #$spn.Secret | ConvertFrom-SecureString



# Remove contributor role from the SPN which is added by deefault :-S
$roles = Get-AzRoleAssignment -ObjectId $config.ClientId
foreach ($role in $roles) 
{
    Write-Output "Removing following role from the SPN that was added by default: " + $role.RoleDefinitionName
    Remove-AzRoleAssignment -ObjectId $spn.Id -RoleDefinitionName $role.RoleDefinitionName -Scope $role.Scope
}


# Create new Role
$role = Get-AzRoleDefinition -Name "Contributor"
$role.Id = $null
$role.Name = $AzureRoleName
$role.Description = "Can only access Azure Monitor alerts"
$role.Actions.RemoveRange(0,$role.Actions.Count)
$role.Actions.Add("Microsoft.AlertsManagement/alerts/*")
$role.Actions.Add("Microsoft.AlertsManagement/alertsSummary/*")
$role.Actions.Add("Microsoft.Insights/activityLogAlerts/*")
$role.Actions.Add("Microsoft.Insights/components/*")
$role.Actions.Add("Microsoft.Insights/eventtypes/*")
$role.Actions.Add("Microsoft.Insights/metricalerts/*")
$role.AssignableScopes.Clear()
$role.AssignableScopes.Add($subScope)


Write-Output "Creating new role in Azure, which may take some seconds..."
New-AzRoleDefinition -Role $role

# Sleep a little while and wait until the new role is completely populated and available in Azure. Otherwise consider adding the role assignment manually in Azure Portal. The SPN shows up for assignement..
Start-Sleep -s 30

# Assign SPN to that role
Write-Output "Role created in Azure, adding SPN to that role..."
New-AzRoleAssignment -ObjectId $spn.Id -RoleDefinitionName $AzureRoleName -Scope $subScope

Write-Output ""
Write-Output ""
Write-Output ""
Write-Output "*** All set, please enter these details in the Enterprise Alert AzureMonitor App config... ***"
$config | Format-List -Property SubscriptionId,TenantId,ClientId,ClientSecret