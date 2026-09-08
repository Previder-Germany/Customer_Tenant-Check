<#
.SYNOPSIS
    Previder_TenantCheck - Modular setup assistant for the tenant check app registration.

.DESCRIPTION
    Interactive, modular script for the complete setup of the "Previder_TenantCheck" app registration
    including all permissions needed for the various tenant check test categories:

      1) Entra app registration + Microsoft Graph application permissions (+ delegated User.Read)
      2) Exchange Online API permission (Graph) + Exchange RBAC role assignment
      3) Teams Reader directory role
      4) Azure RBAC (Reader on root scope, Microsoft.aadiam, Microsoft.Intune)
      5) Dataverse / Copilot Studio application user + security role - including an automatic
         scan of all Power Platform environments to check whether Copilot Studio agents are even in use
      6) Certificate-based authentication (generate a self-signed cert + attach it to the app registration)
      7) Decommissioning - roll back all or individual modules 1-6, including an optional complete
         deletion of the app registration

    Each block is a self-contained function and can be run individually, in any combination, or via
    the interactive menu at the end of the script - not every tenant needs every block (e.g. no Azure
    subscription, no Copilot Studio in use, etc.).

.NOTES
    Required roles (depending on the chosen module):
      - Global Administrator (recommended for all modules, mandatory for admin consent, the Teams
        Reader role assignment, and the Azure root-scope elevation)
      - Exchange Administrator (module 2, EXO RBAC part)
      - System Administrator in the respective Dataverse environment OR Power Platform admin rights (module 5)

    Required PowerShell modules (installed automatically if needed):
      - Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Authentication
      - Az.Accounts, Az.Resources
      - ExchangeOnlineManagement (module 2b only)
      - PKI (included in Windows PowerShell/PowerShell 7 on Windows, for module 6)

.EXAMPLE
    # Start the interactive menu
    .\New-PreviderTenantCheckApp.ps1

.EXAMPLE
    # Use an individual function directly (after dot-sourcing the script)
    . .\New-PreviderTenantCheckApp.ps1 -NoMenu
    $reg = New-TenantCheckAppRegistration
    Grant-AzureReaderAccess -SpObjectId $reg.SpObjectId
#>

[CmdletBinding()]
param(
    # If set, only dot-sources the functions without starting the interactive menu.
    [switch] $NoMenu
)

# ======================================================================================
# Configuration
# ======================================================================================

$script:AppDisplayName = "Previder_TenantCheck"
$script:GraphAppId     = "00000003-0000-0000-c000-000000000000"
$script:ExoAppId       = "00000002-0000-0ff1-ce00-000000000000"

# Application permissions (app roles) on Microsoft Graph
$script:GraphAppRoles = @(
    'AccessReview.Read.All',
    'AuditLog.Read.All',
    'DeviceManagementApps.Read.All',
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'DeviceManagementRBAC.Read.All',
    'DeviceManagementServiceConfig.Read.All',
    'Directory.Read.All',
    'DirectoryRecommendations.Read.All',
    'EntitlementManagement.Read.All',
    'IdentityRiskEvent.Read.All',
    'OnPremDirectorySynchronization.Read.All',
    'OrgSettings-AppsAndServices.Read.All',
    'OrgSettings-Forms.Read.All',
    'Policy.Read.All',
    'Policy.Read.ConditionalAccess',
    'PrivilegedAccess.Read.AzureAD',
    'Reports.Read.All',
    'ReportSettings.Read.All',
    'RoleEligibilitySchedule.Read.Directory',
    'RoleManagement.Read.All',
    'SecurityEvents.Read.All',
    'SecurityIdentitiesHealth.Read.All',
    'SecurityIdentitiesSensors.Read.All',
    'ServiceHealth.Read.All',
    'ServiceMessage.Read.All',
    'SharePointTenantSettings.Read.All',
    'ThreatHunting.Read.All',
    'User.Read.All',
    'UserAuthenticationMethod.Read.All'
)

# Delegated permissions on Microsoft Graph
$script:GraphDelegatedScopes = @('User.Read')

# Application permissions on Office 365 Exchange Online
$script:ExoAppRoles = @('Exchange.ManageAsApp', 'Exchange.ManageAsAppV2')

# GUID of the built-in Azure role "User Access Administrator" (for cleaning up the root-scope elevation)
$script:UserAccessAdminRoleId = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'

# Directory roles typically required for each module (for the pre-flight permission check in
# Invoke-TenantCheckStep - just a hint, not a guarantee, since consent policies can differ per
# tenant and PIM-eligible roles are not detected).
$script:RolesAppAdmin      = @('Global Administrator', 'Privileged Role Administrator', 'Application Administrator', 'Cloud Application Administrator')
$script:RolesPrivRole      = @('Global Administrator', 'Privileged Role Administrator')
$script:RolesExchange      = @('Global Administrator', 'Exchange Administrator')
$script:RolesGlobalOnly    = @('Global Administrator')
$script:RolesPowerPlatform = @('Global Administrator', 'Power Platform Administrator', 'Dynamics 365 Administrator')

# ======================================================================================
# Shared helper functions
# ======================================================================================

function Confirm-RequiredModules {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]] $ModuleNames)

    foreach ($m in $ModuleNames) {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            Write-Host "Installing module '$m'..." -ForegroundColor Yellow
            Install-Module $m -Scope CurrentUser -Force -AllowClobber
        }
    }
}

function Connect-GraphForSetup {
    [CmdletBinding()]
    param()

    Confirm-RequiredModules -ModuleNames @(
        'Microsoft.Graph.Applications',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Authentication'
    )

    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes @(
            'Application.ReadWrite.All',
            'AppRoleAssignment.ReadWrite.All',
            'DelegatedPermissionGrant.ReadWrite.All',
            'RoleManagement.ReadWrite.Directory',
            'Directory.Read.All'
        ) -NoWelcome
    }
}

function Connect-AzForSetup {
    [CmdletBinding()]
    param()

    Confirm-RequiredModules -ModuleNames @('Az.Accounts', 'Az.Resources')

    # By default, Az.Accounts uses the WAM broker for interactive sign-in, whose Azure.Identity
    # assembly collides with the version already loaded by Microsoft.Graph.Authentication as soon
    # as both modules (Graph and Azure steps) are used in the same session - this shows up as
    # "Method not found: ...SharedTokenCacheCredentialBrokerOptions..." or, misleadingly, as
    # "credentials have not been set up or have expired". -Scope Process only applies to this run
    # and does not change any persistent Az configuration.
    try {
        Update-AzConfig -EnableLoginByWam $false -Scope Process -ErrorAction Stop | Out-Null
    } catch {
        Write-Verbose "Could not disable the WAM broker (possibly an older Az.Accounts version): $($_.Exception.Message)"
    }

    if (-not (Get-AzContext)) {
        Connect-AzAccount | Out-Null
    }
}

function Get-CurrentUserActiveDirectoryRoles {
    <#
    .SYNOPSIS
        Determines the directory roles currently ACTIVELY assigned to the signed-in user, for the
        pre-flight permission check of the individual setup/decommissioning steps.
    .DESCRIPTION
        Returns $null if the roles could not be determined (e.g. missing Directory.Read.All
        permission) - the calling check then simply allows the step instead of incorrectly
        blocking it.

        Only detects ACTIVELY assigned roles. Roles that are only "eligible" via PIM must be
        activated manually before the respective step, since they are not visible here. The result
        is cached per script run - after activating a PIM role during the run, set
        $script:CurrentUserRoleCache = $null if you need to re-check.
    #>
    [CmdletBinding()]
    param()

    if ($script:CurrentUserRoleCache) { return $script:CurrentUserRoleCache }

    Connect-GraphForSetup

    try {
        $memberOf = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?`$select=displayName"
        $script:CurrentUserRoleCache = @($memberOf.value | ForEach-Object { $_.displayName })
    } catch {
        Write-Verbose "Could not determine current directory roles: $($_.Exception.Message)"
        $script:CurrentUserRoleCache = $null
    }

    return $script:CurrentUserRoleCache
}

function Test-TenantCheckRequiredRole {
    <#
    .SYNOPSIS
        Checks whether the signed-in user has at least one of the directory roles required for a
        step ACTIVELY assigned. Does not block anything, only prints a warning - the final decision
        (proceed/cancel) stays with the user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $RequiredRoles,
        [Parameter(Mandatory)] [string] $StepName
    )

    $currentRoles = Get-CurrentUserActiveDirectoryRoles
    if ($null -eq $currentRoles) {
        Write-Host "  [?] Could not check roles for '$StepName' - continuing." -ForegroundColor DarkGray
        return $true
    }

    $match = @($RequiredRoles | Where-Object { $_ -in $currentRoles })
    if ($match.Count -gt 0) {
        Write-Host "  [ok] Required role for '$StepName' present ('$($match[0])')." -ForegroundColor DarkGray
        return $true
    }

    Write-Host ""
    Write-Warning "No sufficient role appears to be actively assigned for '$StepName' (required: $($RequiredRoles -join ' / '))."
    Write-Host "  Note: only ACTIVELY assigned roles are detected - a role that is only 'eligible' via PIM must be activated first. Consent policies may also differ." -ForegroundColor DarkGray
    return $false
}

function Invoke-TenantCheckStep {
    <#
    .SYNOPSIS
        Runs a single setup/decommissioning step in a fault-tolerant way.
    .DESCRIPTION
        Optionally checks upfront for the presumably required role (a hint only, not a hard gate)
        and catches errors from the actual step (e.g. missing Exchange admin rights) instead of
        aborting the entire script. Control ALWAYS returns to the calling menu afterwards, so that
        other steps (e.g. attaching the certificate) can still be run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $StepName,
        [Parameter(Mandatory)] [scriptblock] $Action,
        [string[]] $RequiredRoles = @()
    )

    if ($RequiredRoles.Count -gt 0 -and -not (Test-TenantCheckRequiredRole -RequiredRoles $RequiredRoles -StepName $StepName)) {
        $proceed = Read-Host "Try anyway? (y/N)"
        if ($proceed -ne 'y') {
            Write-Host "  [-] '$StepName' skipped." -ForegroundColor DarkGray
            return $false
        }
    }

    try {
        & $Action
        return $true
    } catch {
        Write-Host ""
        Write-Warning "Error in '$StepName': $($_.Exception.Message)"
        Write-Host "  Step skipped - other steps (e.g. the certificate) can still be run." -ForegroundColor Yellow
        return $false
    }
}

# ======================================================================================
# Module 1: App registration + Microsoft Graph permissions
# ======================================================================================

function New-TenantCheckAppRegistration {
    <#
    .SYNOPSIS
        Creates (or updates) the "Previder_TenantCheck" app registration including all required
        Microsoft Graph application permissions and the delegated User.Read permission.
    #>
    [CmdletBinding()]
    param(
        [string] $DisplayName = $script:AppDisplayName
    )

    Connect-GraphForSetup

    $existing = @(Get-MgApplication -Filter "displayName eq '$DisplayName'")
    if ($existing.Count -gt 0) {
        $app = $existing[0]
        Write-Host "Application '$DisplayName' already exists (AppId: $($app.AppId))." -ForegroundColor Green
    } else {
        Write-Host "Creating app registration '$DisplayName'..." -ForegroundColor Yellow
        $app = New-MgApplication -DisplayName $DisplayName -SignInAudience "AzureADMyOrg" `
            -Description "Previder Tenant Check - security assessment application"
        Write-Host "Application created: AppId $($app.AppId)" -ForegroundColor Green
    }

    $spList = @(Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'")
    if ($spList.Count -gt 0) {
        $sp = $spList[0]
        Write-Host "Service principal already exists: $($sp.Id)" -ForegroundColor Green
    } else {
        $sp = New-MgServicePrincipal -AppId $app.AppId
        Write-Host "Service principal created: $($sp.Id)" -ForegroundColor Green
    }

    $graphSp = @(Get-MgServicePrincipal -Filter "appId eq '$script:GraphAppId'")[0]
    if (-not $graphSp) {
        throw "Microsoft Graph service principal not found."
    }

    # --- Set RequiredResourceAccess in the manifest (Graph block; other resource blocks are kept) ---
    $graphResourceAccess = @()
    foreach ($roleName in $script:GraphAppRoles) {
        $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $roleName -and $_.AllowedMemberTypes -contains 'Application' }
        if (-not $role) {
            Write-Warning "App role '$roleName' not found in Microsoft Graph - skipped."
            continue
        }
        $graphResourceAccess += @{ Id = $role.Id; Type = 'Role' }
    }
    foreach ($scopeName in $script:GraphDelegatedScopes) {
        $scope = $graphSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $scopeName }
        if ($scope) {
            $graphResourceAccess += @{ Id = $scope.Id; Type = 'Scope' }
        }
    }

    $currentApp = Get-MgApplication -ApplicationId $app.Id
    $otherResourceBlocks = @($currentApp.RequiredResourceAccess | Where-Object { $_.ResourceAppId -ne $script:GraphAppId })
    $newRequiredResourceAccess = $otherResourceBlocks + @(
        @{ ResourceAppId = $script:GraphAppId; ResourceAccess = $graphResourceAccess }
    )
    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $newRequiredResourceAccess
    Write-Host "Manifest updated with $($graphResourceAccess.Count) Graph permissions." -ForegroundColor Green

    # --- Grant application permissions (app role assignments = admin consent for app permissions) ---
    $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
    foreach ($roleName in $script:GraphAppRoles) {
        $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $roleName -and $_.AllowedMemberTypes -contains 'Application' }
        if (-not $role) { continue }

        $already = $existingAssignments | Where-Object { $_.AppRoleId -eq $role.Id -and $_.ResourceId -eq $graphSp.Id }
        if ($already) {
            Write-Host "  [ok] $roleName already granted" -ForegroundColor DarkGray
        } else {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $role.Id | Out-Null
            Write-Host "  [+] $roleName granted" -ForegroundColor Yellow
        }
    }

    # --- Admin-consent the delegated permission (User.Read) ---
    $delegatedScopeString = $script:GraphDelegatedScopes -join ' '
    $existingGrants = @(Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and resourceId eq '$($graphSp.Id)'")
    if ($existingGrants.Count -gt 0) {
        $grant = $existingGrants[0]
        $currentScopes = @($grant.Scope -split ' ' | Where-Object { $_ })
        $missing = $script:GraphDelegatedScopes | Where-Object { $_ -notin $currentScopes }
        if ($missing.Count -gt 0) {
            $newScope = (($currentScopes + $missing) | Sort-Object -Unique) -join ' '
            Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id -BodyParameter @{ scope = $newScope } | Out-Null
            Write-Host "  [+] Delegated scope added: $($missing -join ', ')" -ForegroundColor Yellow
        } else {
            Write-Host "  [ok] Delegated scope 'User.Read' already granted" -ForegroundColor DarkGray
        }
    } else {
        New-MgOauth2PermissionGrant -BodyParameter @{
            clientId    = $sp.Id
            consentType = 'AllPrincipals'
            resourceId  = $graphSp.Id
            scope       = $delegatedScopeString
        } | Out-Null
        Write-Host "  [+] Delegated scope 'User.Read' granted (admin consent for all users)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "App registration '$DisplayName' set up." -ForegroundColor Green
    Write-Host "   AppId (Client ID): $($app.AppId)"
    Write-Host "   Object ID (App):   $($app.Id)"
    Write-Host "   Object ID (SP):    $($sp.Id)"

    return [PSCustomObject]@{
        AppId       = $app.AppId
        AppObjectId = $app.Id
        SpObjectId  = $sp.Id
        DisplayName = $DisplayName
    }
}

# ======================================================================================
# Module 2: Exchange Online (Graph permission + EXO RBAC role)
# ======================================================================================

function Add-ExchangeOnlineGraphPermission {
    <#
    .SYNOPSIS
        Adds the Exchange Online application permissions (Exchange.ManageAsApp,
        Exchange.ManageAsAppV2) to the app registration and grants them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $SpObjectId,
        [Parameter(Mandatory)] [string] $AppObjectId
    )

    Connect-GraphForSetup

    $exoSp = @(Get-MgServicePrincipal -Filter "appId eq '$script:ExoAppId'")
    if ($exoSp.Count -eq 0) {
        throw "Office 365 Exchange Online service principal not found - is Exchange Online active in this tenant?"
    }
    $exoSp = $exoSp[0]

    $exoResourceAccess = @()
    foreach ($roleName in $script:ExoAppRoles) {
        $role = $exoSp.AppRoles | Where-Object { $_.Value -eq $roleName }
        if (-not $role) {
            Write-Warning "App role '$roleName' not found on Exchange Online - skipped."
            continue
        }
        $exoResourceAccess += @{ Id = $role.Id; Type = 'Role' }
    }

    $currentApp = Get-MgApplication -ApplicationId $AppObjectId
    $otherResourceBlocks = @($currentApp.RequiredResourceAccess | Where-Object { $_.ResourceAppId -ne $script:ExoAppId })
    $newRequiredResourceAccess = $otherResourceBlocks + @(
        @{ ResourceAppId = $script:ExoAppId; ResourceAccess = $exoResourceAccess }
    )
    Update-MgApplication -ApplicationId $AppObjectId -RequiredResourceAccess $newRequiredResourceAccess
    Write-Host "Manifest updated with Exchange Online permissions." -ForegroundColor Green

    $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpObjectId -All
    foreach ($roleName in $script:ExoAppRoles) {
        $role = $exoSp.AppRoles | Where-Object { $_.Value -eq $roleName }
        if (-not $role) { continue }

        $already = $existingAssignments | Where-Object { $_.AppRoleId -eq $role.Id -and $_.ResourceId -eq $exoSp.Id }
        if ($already) {
            Write-Host "  [ok] $roleName already granted" -ForegroundColor DarkGray
        } else {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpObjectId -PrincipalId $SpObjectId -ResourceId $exoSp.Id -AppRoleId $role.Id | Out-Null
            Write-Host "  [+] $roleName granted" -ForegroundColor Yellow
        }
    }
    Write-Host "Exchange Online Graph permissions set." -ForegroundColor Green
}

function Set-ExchangeOnlineRbacRole {
    <#
    .SYNOPSIS
        Registers the app as a service principal in Exchange Online and assigns the RBAC role
        "View-Only Configuration". Requires an interactive sign-in with Exchange admin rights.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AppId,
        [Parameter(Mandatory)] [string] $SpObjectId,
        [string] $DisplayName = $script:AppDisplayName
    )

    Confirm-RequiredModules -ModuleNames @('ExchangeOnlineManagement')
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
        Connect-ExchangeOnline -ShowBanner:$false
    }

    $existingSp = Get-ServicePrincipal -Identity $AppId -ErrorAction SilentlyContinue
    if ($existingSp) {
        Write-Host "  [ok] EXO service principal already exists." -ForegroundColor DarkGray
    } else {
        New-ServicePrincipal -AppId $AppId -ObjectId $SpObjectId -DisplayName $DisplayName | Out-Null
        Write-Host "  [+] EXO service principal created." -ForegroundColor Yellow
    }

    $existingRoleAssignment = Get-ManagementRoleAssignment -RoleAssignee $DisplayName -Role "View-Only Configuration" -ErrorAction SilentlyContinue
    if ($existingRoleAssignment) {
        Write-Host "  [ok] Role 'View-Only Configuration' already assigned." -ForegroundColor DarkGray
    } else {
        try {
            New-ManagementRoleAssignment -Role "View-Only Configuration" -App $DisplayName -ErrorAction Stop | Out-Null
            Write-Host "  [+] Role 'View-Only Configuration' assigned." -ForegroundColor Yellow
        } catch {
            if ($_.Exception.Message -notmatch 'Enable-OrganizationCustomization') { throw }

            Write-Host ""
            Write-Warning "This tenant has not enabled Exchange organization customization yet - this is required for an RBAC role assignment."
            $runEnable = Read-Host "Run 'Enable-OrganizationCustomization' now? This is a ONE-TIME, tenant-wide change that is effectively irreversible (y/N)"
            if ($runEnable -ne 'y') { throw }

            Enable-OrganizationCustomization -ErrorAction Stop
            Write-Host "  [+] Organization customization enabled - retrying the role assignment." -ForegroundColor Yellow
            New-ManagementRoleAssignment -Role "View-Only Configuration" -App $DisplayName -ErrorAction Stop | Out-Null
            Write-Host "  [+] Role 'View-Only Configuration' assigned." -ForegroundColor Yellow
        }
    }
    Write-Host "Exchange Online RBAC set up." -ForegroundColor Green
}

# ======================================================================================
# Module 2b: Security & Compliance PowerShell RBAC (for Connect-IPPSSession)
# ======================================================================================

function Add-SecurityComplianceRoleAssignment {
    <#
    .SYNOPSIS
        Assigns the app (service principal) the built-in Entra directory role "Security Reader".
    .DESCRIPTION
        Exchange Online PowerShell and Security & Compliance PowerShell (Connect-IPPSSession) are
        TWO SEPARATE RBAC systems. The EXO role assignment from module 2 ("View-Only Configuration")
        does NOT cover Security & Compliance PowerShell - without this role, Connect-IPPSSession
        with app-only auth fails with "Could not find the organization container". According to
        Microsoft's documentation, "Security Reader" covers BOTH Exchange Online PowerShell AND
        Security & Compliance PowerShell read access:
        https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2#option-1-assign-microsoft-entra-roles-to-the-application
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SpObjectId)

    Connect-GraphForSetup

    $roleName = "Security Reader"
    $role = @(Get-MgDirectoryRole -Filter "displayName eq '$roleName'")

    if ($role.Count -eq 0) {
        Write-Verbose "Role '$roleName' is not activated yet - activating from template."
        $template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $roleName }
        if (-not $template) {
            throw "Directory role template '$roleName' not found."
        }
        $roleObj = New-MgDirectoryRole -RoleTemplateId $template.Id -ErrorAction Stop
    } else {
        $roleObj = $role[0]
    }

    $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $roleObj.Id -All)
    if ($members.Id -contains $SpObjectId) {
        Write-Host "  [ok] Service principal is already a member of '$roleName'." -ForegroundColor DarkGray
    } else {
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $roleObj.Id -BodyParameter @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$SpObjectId"
        }
        Write-Host "  [+] Service principal added to '$roleName' (active, permanent)." -ForegroundColor Yellow
    }
    Write-Host "Security Reader role assigned (Exchange Online + Security & Compliance PowerShell)." -ForegroundColor Green
}

# ======================================================================================
# Module 3: Teams Reader directory role
# ======================================================================================

function Add-TeamsReaderRoleAssignment {
    <#
    .SYNOPSIS
        Assigns the app (service principal) the built-in Entra directory role "Teams Reader"
        (active, permanent - equivalent to "Active" + "Permanently assigned" in the portal).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SpObjectId)

    Connect-GraphForSetup

    $roleName = "Teams Reader"
    $role = @(Get-MgDirectoryRole -Filter "displayName eq '$roleName'")

    if ($role.Count -eq 0) {
        Write-Verbose "Role '$roleName' is not activated yet - activating from template."
        $template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $roleName }
        if (-not $template) {
            throw "Directory role template '$roleName' not found."
        }
        $roleObj = New-MgDirectoryRole -RoleTemplateId $template.Id -ErrorAction Stop
    } else {
        $roleObj = $role[0]
    }

    $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $roleObj.Id -All)
    if ($members.Id -contains $SpObjectId) {
        Write-Host "  [ok] Service principal is already a member of '$roleName'." -ForegroundColor DarkGray
    } else {
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $roleObj.Id -BodyParameter @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$SpObjectId"
        }
        Write-Host "  [+] Service principal added to '$roleName' (active, permanent)." -ForegroundColor Yellow
    }
    Write-Host "Teams Reader role assigned." -ForegroundColor Green
}

# ======================================================================================
# Module 4: Azure RBAC (Reader: root scope, Entra diagnostics, Intune)
# ======================================================================================

function Grant-AzureReaderAccess {
    <#
    .SYNOPSIS
        Briefly elevates access on the root scope and assigns the app (service principal) the
        Reader role on "/", "/providers/Microsoft.aadiam" and "/providers/Microsoft.Intune".
        Afterwards only removes its own elevation, not the app's assignments.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SpObjectId)

    Connect-AzForSetup

    Write-Host "Elevating access on the root scope (only for the currently signed-in admin)..." -ForegroundColor Yellow
    Invoke-AzRestMethod -Path "/providers/Microsoft.Authorization/elevateAccess?api-version=2015-07-01" -Method POST | Out-Null

    function Set-RoleAssignmentIfMissing {
        param($ObjectId, $Scope, $RoleName)
        $existing = Get-AzRoleAssignment -ObjectId $ObjectId -Scope $Scope -RoleDefinitionName $RoleName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Host "  [ok] '$RoleName' on '$Scope' already present." -ForegroundColor DarkGray
        } else {
            New-AzRoleAssignment -ObjectId $ObjectId -Scope $Scope -RoleDefinitionName $RoleName -ObjectType "ServicePrincipal" | Out-Null
            Write-Host "  [+] '$RoleName' assigned on '$Scope'." -ForegroundColor Yellow
        }
    }

    Set-RoleAssignmentIfMissing -ObjectId $SpObjectId -Scope "/" -RoleName "Reader"
    Set-RoleAssignmentIfMissing -ObjectId $SpObjectId -Scope "/providers/Microsoft.aadiam" -RoleName "Reader"
    Set-RoleAssignmentIfMissing -ObjectId $SpObjectId -Scope "/providers/Microsoft.Intune" -RoleName "Reader"

    $assignment = Get-AzRoleAssignment -RoleDefinitionId $script:UserAccessAdminRoleId |
        Where-Object { $_.Scope -eq "/" -and $_.SignInName -eq (Get-AzContext).Account.Id }
    if ($assignment) {
        Invoke-AzRestMethod -Path "$($assignment.RoleAssignmentId)?api-version=2018-07-01" -Method DELETE | Out-Null
        Write-Host "Own root-scope elevation removed." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "--- Current role assignments for the service principal ---" -ForegroundColor Cyan
    Get-AzRoleAssignment -ObjectId $SpObjectId |
        Where-Object { $_.Scope -in @("/", "/providers/Microsoft.aadiam", "/providers/Microsoft.Intune") } |
        Select-Object DisplayName, RoleDefinitionName, Scope | Format-Table -AutoSize

    Write-Host "Azure RBAC (including Intune) set up." -ForegroundColor Green
}

# ======================================================================================
# Module 5: Dataverse / Copilot Studio - environment scan + permission assignment
# ======================================================================================

function Find-CopilotStudioEnvironments {
    <#
    .SYNOPSIS
        Scans all Power Platform environments in the tenant and checks whether Copilot Studio is
        even installed and whether active agents (bots) exist. Only environments with actually
        existing agents are relevant for the Copilot Studio tests.

    .OUTPUTS
        PSCustomObject[] with EnvironmentName, EnvironmentUrl, HasCopilotStudio, AgentCount, InUse, Status
    #>
    [CmdletBinding()]
    param()

    Connect-AzForSetup

    Write-Host "Determining Power Platform environments (requires Power Platform admin or Global Admin rights)..." -ForegroundColor Yellow

    try {
        $bapTokenObj = Get-AzAccessToken -ResourceUrl "https://service.powerapps.com/" -AsSecureString -ErrorAction Stop
        $bapToken = $bapTokenObj.Token | ConvertFrom-SecureString -AsPlainText
        $bapHeaders = @{ Authorization = "Bearer $bapToken"; Accept = 'application/json' }

        $envResponse = Invoke-RestMethod -Uri "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01" -Headers $bapHeaders -ErrorAction Stop
    } catch {
        Write-Warning "Could not list Power Platform environments via the admin API (account may not be a Power Platform admin). Error: $($_.Exception.Message)"
        Write-Warning "Check manually in the Power Platform admin center (admin.powerplatform.microsoft.com) which environments use Copilot Studio."
        return @()
    }

    $dataverseEnvs = $envResponse.value | Where-Object { $_.properties.linkedEnvironmentMetadata }
    Write-Host "Found: $($dataverseEnvs.Count) environment(s) with Dataverse. Checking for Copilot Studio agents..." -ForegroundColor Yellow

    $results = foreach ($env in $dataverseEnvs) {
        $metadata = $env.properties.linkedEnvironmentMetadata
        $envName = $env.properties.displayName

        $rawUrl = if ($metadata.instanceApiUrl) { $metadata.instanceApiUrl } else { $metadata.instanceUrl }
        $rawUrl = $rawUrl.TrimEnd('/')
        if ($rawUrl -notmatch '^https?://') { $rawUrl = "https://$rawUrl" }
        if ($rawUrl -notmatch '\.api\.') {
            # Same normalization used: <org>.crm.dynamics.com -> <org>.api.crm.dynamics.com
            $rawUrl = $rawUrl -replace '(https://[^.]+)\.', '$1.api.'
        }
        $envUrl = $rawUrl

        try {
            $envTokenObj = Get-AzAccessToken -ResourceUrl $envUrl -AsSecureString -ErrorAction Stop
            $envToken = $envTokenObj.Token | ConvertFrom-SecureString -AsPlainText
            $envHeaders = @{
                Authorization      = "Bearer $envToken"
                Accept             = 'application/json'
                'OData-MaxVersion' = '4.0'
                'OData-Version'    = '4.0'
            }

            $botsResponse = Invoke-RestMethod -Uri "$envUrl/api/data/v9.2/bots?`$filter=ismanaged eq false&`$select=botid&`$top=5" -Headers $envHeaders -ErrorAction Stop
            $agentCount = @($botsResponse.value).Count

            [PSCustomObject]@{
                EnvironmentName  = $envName
                EnvironmentUrl   = $envUrl
                HasCopilotStudio = $true
                AgentCount       = $agentCount
                InUse            = ($agentCount -gt 0)
                Status           = 'OK'
            }
        } catch {
            $statusCode = $null
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }

            if ($statusCode -eq 404) {
                [PSCustomObject]@{
                    EnvironmentName  = $envName
                    EnvironmentUrl   = $envUrl
                    HasCopilotStudio = $false
                    AgentCount       = 0
                    InUse            = $false
                    Status           = 'Copilot Studio not installed'
                }
            } elseif ($statusCode -in @(401, 403)) {
                [PSCustomObject]@{
                    EnvironmentName  = $envName
                    EnvironmentUrl   = $envUrl
                    HasCopilotStudio = $null
                    AgentCount       = $null
                    InUse            = $false
                    Status           = 'No access - check manually'
                }
            } else {
                [PSCustomObject]@{
                    EnvironmentName  = $envName
                    EnvironmentUrl   = $envUrl
                    HasCopilotStudio = $null
                    AgentCount       = $null
                    InUse            = $false
                    Status           = "Error: $($_.Exception.Message)"
                }
            }
        }
    }

    Write-Host ""
    $results | Format-Table EnvironmentName, InUse, AgentCount, Status, EnvironmentUrl -AutoSize

    $noAccess = @($results | Where-Object { $_.Status -eq 'No access - check manually' })
    if ($noAccess.Count -gt 0) {
        Write-Warning "$($noAccess.Count) environment(s) could not be checked (no access). Consider checking these manually in the Power Platform admin center before classifying them as 'not in use'."
    }

    return $results
}

function Grant-DataverseCopilotStudioAccess {
    <#
    .SYNOPSIS
        Creates the application user for a specific Dataverse environment and assigns either the
        built-in "Basic User" role or a least-privilege custom role.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $EnvironmentUrl,
        [Parameter(Mandatory)] [string] $AppClientId,
        [ValidateSet('BasicUser', 'CustomRole')] [string] $RoleMode = 'CustomRole',
        [string] $BusinessUnitName = $null
    )

    Connect-AzForSetup

    $tokenObj = Get-AzAccessToken -ResourceUrl $EnvironmentUrl -AsSecureString
    $token = $tokenObj.Token | ConvertFrom-SecureString -AsPlainText
    $headers = @{
        Authorization      = "Bearer $token"
        Accept             = 'application/json'
        'OData-MaxVersion' = '4.0'
        'OData-Version'    = '4.0'
        'Content-Type'     = 'application/json'
    }
    $apiBase = "$EnvironmentUrl/api/data/v9.2"

    if ($BusinessUnitName) {
        $bu = Invoke-RestMethod -Uri "$apiBase/businessunits?`$filter=name eq '$BusinessUnitName'&`$select=businessunitid,name" -Headers $headers
    } else {
        $bu = Invoke-RestMethod -Uri "$apiBase/businessunits?`$filter=parentbusinessunitid eq null&`$select=businessunitid,name" -Headers $headers
    }
    if ($bu.value.Count -eq 0) { throw "Business unit not found in '$EnvironmentUrl'." }
    $businessUnitId = $bu.value[0].businessunitid
    Write-Host "Business unit: $($bu.value[0].name) ($businessUnitId)"

    $existingUser = Invoke-RestMethod -Uri "$apiBase/systemusers?`$filter=applicationid eq $AppClientId&`$select=systemuserid" -Headers $headers
    if ($existingUser.value.Count -gt 0) {
        $appUserId = $existingUser.value[0].systemuserid
        Write-Host "  [ok] Application user already exists: $appUserId" -ForegroundColor DarkGray
    } else {
        $body = @{
            applicationid               = $AppClientId
            "businessunitid@odata.bind" = "/businessunits($businessUnitId)"
        } | ConvertTo-Json
        $createResponse = Invoke-WebRequest -Uri "$apiBase/systemusers" -Headers $headers -Method POST -Body $body
        $appUserId = ($createResponse.Headers['OData-EntityId'] -replace '.*systemusers\(([0-9a-fA-F-]+)\).*', '$1')
        Write-Host "  [+] Application user created: $appUserId" -ForegroundColor Yellow
    }

    if ($RoleMode -eq 'BasicUser') {
        $role = Invoke-RestMethod -Uri "$apiBase/roles?`$filter=name eq 'Basic User' and _businessunitid_value eq $businessUnitId&`$select=roleid" -Headers $headers
        if ($role.value.Count -eq 0) { throw "Role 'Basic User' not found in business unit '$businessUnitId'." }
        $roleId = $role.value[0].roleid
    } else {
        $roleName = "Previder TenantCheck Security Reader"
        $existingRole = Invoke-RestMethod -Uri "$apiBase/roles?`$filter=name eq '$roleName' and _businessunitid_value eq $businessUnitId&`$select=roleid" -Headers $headers
        if ($existingRole.value.Count -gt 0) {
            $roleId = $existingRole.value[0].roleid
            Write-Host "  [ok] Role '$roleName' already exists: $roleId" -ForegroundColor DarkGray
        } else {
            $roleBody = @{
                name                         = $roleName
                "businessunitid@odata.bind" = "/businessunits($businessUnitId)"
            } | ConvertTo-Json
            $createRoleResponse = Invoke-WebRequest -Uri "$apiBase/roles" -Headers $headers -Method POST -Body $roleBody
            $roleId = ($createRoleResponse.Headers['OData-EntityId'] -replace '.*roles\(([0-9a-fA-F-]+)\).*', '$1')
            Write-Host "  [+] Role '$roleName' created: $roleId" -ForegroundColor Yellow
        }

        $privilegeNames = @('prvReadbot', 'prvReadbotcomponent', 'prvReadsystemuser', 'prvReadconnectionreference')
        $privileges = @(
            foreach ($name in $privilegeNames) {
                $priv = Invoke-RestMethod -Uri "$apiBase/privileges?`$filter=name eq '$name'&`$select=privilegeid,name" -Headers $headers
                if ($priv.value.Count -eq 0) {
                    Write-Warning "Privilege '$name' not found - this entity may not exist in this environment (version?)."
                    continue
                }
                @{ PrivilegeId = $priv.value[0].privilegeid; Depth = 'Global' }
            }
        )
        if ($privileges.Count -gt 0) {
            $addPrivBody = @{ Privileges = $privileges } | ConvertTo-Json -Depth 5
            Invoke-RestMethod -Uri "$apiBase/roles($roleId)/Microsoft.Dynamics.CRM.AddPrivilegesRole" -Headers $headers -Method POST -Body $addPrivBody | Out-Null
            Write-Host "  [+] Privileges (organization-level read) assigned." -ForegroundColor Yellow
        }
    }

    $assocBody = @{ "@odata.id" = "$apiBase/roles($roleId)" } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri "$apiBase/systemusers($appUserId)/systemuserroles_association/`$ref" -Headers $headers -Method POST -Body $assocBody | Out-Null
        Write-Host "  [+] Role assigned." -ForegroundColor Yellow
    } catch {
        if ($_.Exception.Response.StatusCode -eq 'Conflict') {
            Write-Host "  [ok] Role already assigned." -ForegroundColor DarkGray
        } else {
            throw
        }
    }

    Write-Host "Dataverse permission for '$EnvironmentUrl' set up." -ForegroundColor Green
}

function Invoke-DataverseCopilotStudioSetup {
    <#
    .SYNOPSIS
        Runs the environment scan and sets up the Dataverse permission only for environments where
        Copilot Studio agents are actually in use.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AppClientId,
        [ValidateSet('BasicUser', 'CustomRole')] [string] $RoleMode = 'CustomRole'
    )

    $envs = Find-CopilotStudioEnvironments
    $active = @($envs | Where-Object { $_.InUse })

    if ($active.Count -eq 0) {
        Write-Host ""
        Write-Host "No environment with active Copilot Studio agents found. Dataverse permissions will not be set (a check here would be pointless)." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "$($active.Count) environment(s) with active Copilot Studio agents found:" -ForegroundColor Cyan
    $active | ForEach-Object { Write-Host "  - $($_.EnvironmentName): $($_.AgentCount) agent(s) - $($_.EnvironmentUrl)" }

    if ($active.Count -gt 1) {
        Write-Warning "Tenant Check currently only supports ONE 'DataverseEnvironmentUrl' in config.json. Choose the most relevant environment below, or run separate test passes per environment."
    }

    foreach ($env in $active) {
        Write-Host ""
        Write-Host "--- Setting up permission for: $($env.EnvironmentName) ---" -ForegroundColor Cyan
        Grant-DataverseCopilotStudioAccess -EnvironmentUrl $env.EnvironmentUrl -AppClientId $AppClientId -RoleMode $RoleMode
    }

    Write-Host ""
    Write-Host "Add the chosen environment to config.json under GlobalSettings, e.g.:" -ForegroundColor Cyan
    Write-Host "  { `"GlobalSettings`": { `"DataverseEnvironmentUrl`": `"$($active[0].EnvironmentUrl)`" } }"

    return $active
}

# ======================================================================================
# Module 6: Certificate-based authentication
# ======================================================================================

function Get-TenantCheckCustomerTag {
    <#
    .SYNOPSIS
        Determines a customer-specific tag for the certificate (CN, file name, FriendlyName), so
        that certificates for multiple customers can be told apart in the same local certificate
        store (e.g. Cert:\CurrentUser\My on a shared admin machine).
    .DESCRIPTION
        Suggests the organization name from Get-MgOrganization. An empty entry accepts the
        suggestion, any other entry freely overrides it. Cached per script run.
    #>
    [CmdletBinding()]
    param()

    if ($script:CurrentCustomerTag) { return $script:CurrentCustomerTag }

    Connect-GraphForSetup

    $suggestion = $null
    try {
        $org = Get-MgOrganization -Property DisplayName -ErrorAction Stop | Select-Object -First 1
        if ($org -and $org.DisplayName) { $suggestion = $org.DisplayName }
    } catch {
        Write-Verbose "Could not determine the organization name: $($_.Exception.Message)"
    }

    if ($suggestion) {
        $userInput = Read-Host "Customer/tenant label for the certificate [suggestion: '$suggestion'] - press Enter to accept the suggestion, or type your own name"
    } else {
        $userInput = Read-Host "Customer/tenant label for the certificate (no automatic suggestion available - please enter one)"
    }

    $chosen = if ($userInput) { $userInput } else { $suggestion }
    if (-not $chosen) {
        throw "A unique certificate cannot be created without a customer/tenant label."
    }

    # Remove characters that are not allowed in a CN or file name
    $sanitized = ($chosen -replace '[\\/:*?"<>|]', '').Trim()
    $script:CurrentCustomerTag = $sanitized
    return $sanitized
}

function New-TenantCheckCertificate {
    <#
    .SYNOPSIS
        Creates a self-signed certificate for certificate-based app authentication. CN,
        FriendlyName, and export files include a customer tag so that certificates for multiple
        customers stay distinguishable in the same local certificate store.
    #>
    [CmdletBinding()]
    param(
        [string] $CustomerTag,
        [int] $ValidYears = 2,
        [string] $ExportPath
    )

    if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
        throw "New-SelfSignedCertificate is not available. This module requires Windows PowerShell/PowerShell on Windows (PKI module)."
    }

    if (-not $CustomerTag) { $CustomerTag = Get-TenantCheckCustomerTag }
    $subjectName = "$($script:AppDisplayName)-$CustomerTag"

    if (-not $ExportPath) { $ExportPath = "C:\Scripts\$subjectName-Cert" }
    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    $cert = New-SelfSignedCertificate `
        -Subject "CN=$subjectName" `
        -FriendlyName $subjectName `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears($ValidYears)

    $cerPath = Join-Path $ExportPath "$subjectName.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-Host "Certificate created for '$subjectName'. Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
    Write-Host "   Public key exported: $cerPath" -ForegroundColor Cyan

    $pfxPassword = Read-Host "Password for the PFX export (private key, for other machines/backup) - leave empty to skip" -AsSecureString
    if ($pfxPassword -and $pfxPassword.Length -gt 0) {
        $pfxPath = Join-Path $ExportPath "$subjectName.pfx"
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword | Out-Null
        Write-Host "   Private key exported (PFX): $pfxPath - keep it safe!" -ForegroundColor Yellow
    }

    return $cert
}

function Set-TenantCheckAppCertificate {
    <#
    .SYNOPSIS
        Attaches the public certificate as a KeyCredential to the app registration (existing
        certificates/client secrets are kept).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AppObjectId,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    Connect-GraphForSetup

    $app = Get-MgApplication -ApplicationId $AppObjectId
    $existingKeys = @($app.KeyCredentials)

    $certLabel = if ($Certificate.FriendlyName) { $Certificate.FriendlyName } else { $script:AppDisplayName }
    $newKey = @{
        Type          = "AsymmetricX509Cert"
        Usage         = "Verify"
        Key           = $Certificate.GetRawCertData()
        DisplayName   = "$certLabel-Cert-$($Certificate.Thumbprint.Substring(0, 8))"
        StartDateTime = $Certificate.NotBefore
        EndDateTime   = $Certificate.NotAfter
    }

    $allKeys = @($existingKeys) + @($newKey)
    Update-MgApplication -ApplicationId $AppObjectId -KeyCredentials $allKeys
    Write-Host "Certificate '$($newKey.DisplayName)' added to the app registration." -ForegroundColor Green

    Write-Host ""
    Write-Host "Connection examples for automated/non-interactive runs:" -ForegroundColor Cyan
    Write-Host "  Connect-MgGraph -ClientId '<AppId>' -TenantId '<TenantId>' -CertificateThumbprint '$($Certificate.Thumbprint)'"
    Write-Host "  Connect-AzAccount -ServicePrincipal -ApplicationId '<AppId>' -TenantId '<TenantId>' -CertificateThumbprint '$($Certificate.Thumbprint)'"
    Write-Host "  Connect-ExchangeOnline -AppId '<AppId>' -Organization '<tenant>.onmicrosoft.com' -CertificateThumbprint '$($Certificate.Thumbprint)'"
    Write-Host "  Invoke the Tenant Check"
}

# ======================================================================================
# Module 7: Decommissioning (rollback)
# ======================================================================================

function Resolve-TenantCheckApp {
    <#
    .SYNOPSIS
        Looks up the app registration by DisplayName in Entra and returns the AppId/ObjectIds.
        Returns $null if no app with this name is found.
    #>
    [CmdletBinding()]
    param([string] $DisplayName = $script:AppDisplayName)

    Connect-GraphForSetup

    $apps = @(Get-MgApplication -Filter "displayName eq '$DisplayName'")
    if ($apps.Count -eq 0) { return $null }
    $app = $apps[0]

    $spList = @(Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'")
    $sp = if ($spList.Count -gt 0) { $spList[0] } else { $null }

    return [PSCustomObject]@{
        AppId       = $app.AppId
        AppObjectId = $app.Id
        SpObjectId  = if ($sp) { $sp.Id } else { $null }
        DisplayName = $app.DisplayName
    }
}

function Remove-TenantCheckAppRegistration {
    <#
    .SYNOPSIS
        Removes the Microsoft Graph and Exchange Online permissions (app role assignments, OAuth2
        permission grants, RequiredResourceAccess) of the app. The app itself (object + service
        principal) is kept by default, so that the AppId and any attached certificates remain
        valid. With -DeleteApplication, the entire app including the service principal is deleted
        irrevocably (confirmed by typing the app name).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AppObjectId,
        [Parameter(Mandatory)] [string] $SpObjectId,
        [switch] $DeleteApplication
    )

    Connect-GraphForSetup

    if ($DeleteApplication) {
        $app = Get-MgApplication -ApplicationId $AppObjectId
        Write-Host ""
        Write-Warning "This IRREVOCABLY deletes the entire app registration '$($app.DisplayName)' (AppId: $($app.AppId)) including its service principal, certificates, and all permissions."
        $confirm = Read-Host "To confirm, type the exact app name ('$($app.DisplayName)')"
        if ($confirm -ne $app.DisplayName) {
            Write-Host "Cancelled - the input did not match the app name." -ForegroundColor Yellow
            return
        }
        Remove-MgApplication -ApplicationId $AppObjectId
        Write-Host "App registration '$($app.DisplayName)' deleted (including the service principal)." -ForegroundColor Green
        return
    }

    $assignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpObjectId -All)
    foreach ($a in $assignments) {
        Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpObjectId -AppRoleAssignmentId $a.Id
        Write-Host "  [-] App role assignment removed: $($a.Id)" -ForegroundColor DarkGray
    }

    $grants = @(Get-MgOauth2PermissionGrant -Filter "clientId eq '$SpObjectId'")
    foreach ($g in $grants) {
        Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $g.Id
        Write-Host "  [-] Delegated permission grant removed: $($g.Id)" -ForegroundColor DarkGray
    }

    Update-MgApplication -ApplicationId $AppObjectId -RequiredResourceAccess @()
    Write-Host "  [-] Manifest (RequiredResourceAccess) cleared." -ForegroundColor DarkGray

    Write-Host "All Graph/Exchange permissions of the app removed. The app registration itself remains." -ForegroundColor Green
}

function Remove-ExchangeOnlineRbacRole {
    <#
    .SYNOPSIS
        Removes the Exchange Online RBAC role assignment ("View-Only Configuration") and the app's
        EXO service principal entry. Requires an interactive sign-in with Exchange admin rights.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AppId,
        [string] $DisplayName = $script:AppDisplayName
    )

    Confirm-RequiredModules -ModuleNames @('ExchangeOnlineManagement')
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
        Connect-ExchangeOnline -ShowBanner:$false
    }

    $roleAssignment = Get-ManagementRoleAssignment -RoleAssignee $DisplayName -Role "View-Only Configuration" -ErrorAction SilentlyContinue
    if ($roleAssignment) {
        Remove-ManagementRoleAssignment -Identity $roleAssignment.Identity -Confirm:$false
        Write-Host "  [-] Role assignment 'View-Only Configuration' removed." -ForegroundColor DarkGray
    } else {
        Write-Host "  [ok] No role assignment found." -ForegroundColor DarkGray
    }

    $exoSp = Get-ServicePrincipal -Identity $AppId -ErrorAction SilentlyContinue
    if ($exoSp) {
        Remove-ServicePrincipal -Identity $AppId -Confirm:$false
        Write-Host "  [-] EXO service principal removed." -ForegroundColor DarkGray
    } else {
        Write-Host "  [ok] No EXO service principal found." -ForegroundColor DarkGray
    }

    Write-Host "Exchange Online RBAC rolled back." -ForegroundColor Green
}

function Remove-SecurityComplianceRoleAssignment {
    <#
    .SYNOPSIS
        Removes the app (service principal) from the Entra directory role "Security Reader".
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SpObjectId)

    Connect-GraphForSetup

    $roleName = "Security Reader"
    $role = @(Get-MgDirectoryRole -Filter "displayName eq '$roleName'")
    if ($role.Count -eq 0) {
        Write-Host "  [ok] Role '$roleName' is not activated - nothing to remove." -ForegroundColor DarkGray
        return
    }

    $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role[0].Id -All)
    if ($members.Id -notcontains $SpObjectId) {
        Write-Host "  [ok] Service principal is not a member of '$roleName'." -ForegroundColor DarkGray
        return
    }

    Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $role[0].Id -DirectoryObjectId $SpObjectId
    Write-Host "  [-] Service principal removed from '$roleName'." -ForegroundColor DarkGray
    Write-Host "Security Reader role assignment rolled back." -ForegroundColor Green
}

function Remove-TeamsReaderRoleAssignment {
    <#
    .SYNOPSIS
        Removes the app (service principal) from the Entra directory role "Teams Reader".
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SpObjectId)

    Connect-GraphForSetup

    $roleName = "Teams Reader"
    $role = @(Get-MgDirectoryRole -Filter "displayName eq '$roleName'")
    if ($role.Count -eq 0) {
        Write-Host "  [ok] Role '$roleName' is not activated - nothing to remove." -ForegroundColor DarkGray
        return
    }

    $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role[0].Id -All)
    if ($members.Id -notcontains $SpObjectId) {
        Write-Host "  [ok] Service principal is not a member of '$roleName'." -ForegroundColor DarkGray
        return
    }

    Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $role[0].Id -DirectoryObjectId $SpObjectId
    Write-Host "  [-] Service principal removed from '$roleName'." -ForegroundColor DarkGray
    Write-Host "Teams Reader role assignment rolled back." -ForegroundColor Green
}

function Revoke-AzureReaderAccess {
    <#
    .SYNOPSIS
        Removes the app's Reader role assignments on "/", "/providers/Microsoft.aadiam", and
        "/providers/Microsoft.Intune". Briefly elevates access on the root scope for this and
        removes its own elevation again afterwards.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SpObjectId)

    Connect-AzForSetup

    Write-Host "Elevating access on the root scope (only for the currently signed-in admin)..." -ForegroundColor Yellow
    Invoke-AzRestMethod -Path "/providers/Microsoft.Authorization/elevateAccess?api-version=2015-07-01" -Method POST | Out-Null

    foreach ($scope in @("/", "/providers/Microsoft.aadiam", "/providers/Microsoft.Intune")) {
        $existing = Get-AzRoleAssignment -ObjectId $SpObjectId -Scope $scope -RoleDefinitionName "Reader" -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-AzRoleAssignment -ObjectId $SpObjectId -Scope $scope -RoleDefinitionName "Reader" | Out-Null
            Write-Host "  [-] Reader removed on '$scope'." -ForegroundColor DarkGray
        } else {
            Write-Host "  [ok] No Reader assignment found on '$scope'." -ForegroundColor DarkGray
        }
    }

    $assignment = Get-AzRoleAssignment -RoleDefinitionId $script:UserAccessAdminRoleId |
        Where-Object { $_.Scope -eq "/" -and $_.SignInName -eq (Get-AzContext).Account.Id }
    if ($assignment) {
        Invoke-AzRestMethod -Path "$($assignment.RoleAssignmentId)?api-version=2018-07-01" -Method DELETE | Out-Null
        Write-Host "Own root-scope elevation removed." -ForegroundColor DarkGray
    }

    Write-Host "Azure RBAC rolled back." -ForegroundColor Green
}

function Remove-DataverseCopilotStudioAccess {
    <#
    .SYNOPSIS
        Disables the application user in a Dataverse environment (default, reversible). With
        -HardDelete, the application user is deleted instead. The custom role ("Previder
        TenantCheck Security Reader") is kept by default and is only deleted as well with
        -RemoveRole.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $EnvironmentUrl,
        [Parameter(Mandatory)] [string] $AppClientId,
        [switch] $HardDelete,
        [switch] $RemoveRole
    )

    Connect-AzForSetup

    $tokenObj = Get-AzAccessToken -ResourceUrl $EnvironmentUrl -AsSecureString
    $token = $tokenObj.Token | ConvertFrom-SecureString -AsPlainText
    $headers = @{
        Authorization      = "Bearer $token"
        Accept             = 'application/json'
        'OData-MaxVersion' = '4.0'
        'OData-Version'    = '4.0'
        'Content-Type'     = 'application/json'
    }
    $apiBase = "$EnvironmentUrl/api/data/v9.2"

    $existingUser = Invoke-RestMethod -Uri "$apiBase/systemusers?`$filter=applicationid eq $AppClientId&`$select=systemuserid" -Headers $headers
    if ($existingUser.value.Count -eq 0) {
        Write-Host "  [ok] No application user found in '$EnvironmentUrl'." -ForegroundColor DarkGray
    } else {
        $appUserId = $existingUser.value[0].systemuserid
        if ($HardDelete) {
            Invoke-RestMethod -Uri "$apiBase/systemusers($appUserId)" -Headers $headers -Method DELETE | Out-Null
            Write-Host "  [-] Application user deleted: $appUserId" -ForegroundColor DarkGray
        } else {
            $disableBody = @{ isdisabled = $true } | ConvertTo-Json
            Invoke-RestMethod -Uri "$apiBase/systemusers($appUserId)" -Headers $headers -Method PATCH -Body $disableBody | Out-Null
            Write-Host "  [-] Application user disabled: $appUserId" -ForegroundColor DarkGray
        }
    }

    if ($RemoveRole) {
        $roleName = "Previder TenantCheck Security Reader"
        $existingRole = Invoke-RestMethod -Uri "$apiBase/roles?`$filter=name eq '$roleName'&`$select=roleid" -Headers $headers
        foreach ($r in $existingRole.value) {
            Invoke-RestMethod -Uri "$apiBase/roles($($r.roleid))" -Headers $headers -Method DELETE | Out-Null
            Write-Host "  [-] Custom role '$roleName' deleted ($($r.roleid))." -ForegroundColor DarkGray
        }
    }

    Write-Host "Dataverse permission for '$EnvironmentUrl' rolled back." -ForegroundColor Green
}

function Remove-TenantCheckAppCertificate {
    <#
    .SYNOPSIS
        Removes certificates from the app registration. Without -Thumbprint, ALL KeyCredentials are
        removed. With -RemoveLocalCertificate, the certificate is also deleted from the local
        certificate store (Cert:\CurrentUser\My), including the private key.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AppObjectId,
        [string] $Thumbprint,
        [switch] $RemoveLocalCertificate
    )

    Connect-GraphForSetup

    $app = Get-MgApplication -ApplicationId $AppObjectId
    $existingKeys = @($app.KeyCredentials)

    if ($existingKeys.Count -eq 0) {
        Write-Host "  [ok] No certificates attached to the app." -ForegroundColor DarkGray
        return
    }

    if ($Thumbprint) {
        $normalizedThumbprint = $Thumbprint.ToUpper()
        $remainingKeys = @($existingKeys | Where-Object {
            (([System.BitConverter]::ToString($_.CustomKeyIdentifier)) -replace '-', '') -ne $normalizedThumbprint
        })
    } else {
        $remainingKeys = @()
    }

    Update-MgApplication -ApplicationId $AppObjectId -KeyCredentials $remainingKeys
    Write-Host "  [-] $($existingKeys.Count - $remainingKeys.Count) certificate(s) removed from the app." -ForegroundColor DarkGray

    if ($RemoveLocalCertificate) {
        $certsToRemove = if ($Thumbprint) {
            @($Thumbprint.ToUpper())
        } else {
            @($existingKeys | ForEach-Object { ([System.BitConverter]::ToString($_.CustomKeyIdentifier)) -replace '-', '' })
        }
        foreach ($tp in $certsToRemove) {
            $localCert = Get-Item "Cert:\CurrentUser\My\$tp" -ErrorAction SilentlyContinue
            if ($localCert) {
                Remove-Item "Cert:\CurrentUser\My\$tp" -DeleteKey -Force
                Write-Host "  [-] Local certificate removed: $tp" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host "Certificate(s) rolled back." -ForegroundColor Green
}

function Show-TenantCheckDecommissionMenu {
    <#
    .SYNOPSIS
        Interactive submenu for the rollback. Automatically detects the app registration by
        DisplayName - manual entry of the IDs is only needed if no app is found.
    #>
    [CmdletBinding()]
    param()

    $resolved = Resolve-TenantCheckApp
    if (-not $resolved) {
        Write-Warning "No app registration '$script:AppDisplayName' found. Manual entry of the IDs is required."
        $state = @{
            AppId       = Read-Host "App (Client) ID"
            AppObjectId = Read-Host "Application Object ID"
            SpObjectId  = Read-Host "Service Principal Object ID (Enterprise App)"
        }
    } else {
        Write-Host "Found: $($resolved.DisplayName) (AppId: $($resolved.AppId))" -ForegroundColor Green
        $state = @{
            AppId       = $resolved.AppId
            AppObjectId = $resolved.AppObjectId
            SpObjectId  = $resolved.SpObjectId
        }
    }

    do {
        Write-Host ""
        Write-Host "=========================================="
        Write-Host " Previder_TenantCheck - Decommissioning"
        Write-Host "=========================================="
        Write-Host " 1) Remove Graph/Exchange permissions (app stays)"
        Write-Host " 2) Roll back Exchange Online RBAC + Security Reader role (EXO/SCC)"
        Write-Host " 3) Remove Teams Reader role"
        Write-Host " 4) Remove Azure RBAC (root/aadiam/Intune)"
        Write-Host " 5) Remove Dataverse/Copilot Studio access (disable)"
        Write-Host " 6) Remove certificate(s) from the app"
        Write-Host " A) Roll back everything (1-6, app shell is kept)"
        Write-Host " X) DELETE the app registration COMPLETELY (irrevocable)"
        Write-Host " Q) Back / Exit"
        Write-Host "=========================================="
        $choice = Read-Host "Choice"

        switch ($choice.ToUpper()) {
            '1' {
                Invoke-TenantCheckStep -StepName "Remove Graph/Exchange permissions" -RequiredRoles $script:RolesAppAdmin -Action {
                    Remove-TenantCheckAppRegistration -AppObjectId $state.AppObjectId -SpObjectId $state.SpObjectId
                } | Out-Null
            }
            '2' {
                Invoke-TenantCheckStep -StepName "Remove Exchange Online RBAC" -RequiredRoles $script:RolesExchange -Action {
                    Remove-ExchangeOnlineRbacRole -AppId $state.AppId
                } | Out-Null
                Invoke-TenantCheckStep -StepName "Remove Security Reader role" -RequiredRoles $script:RolesPrivRole -Action {
                    Remove-SecurityComplianceRoleAssignment -SpObjectId $state.SpObjectId
                } | Out-Null
            }
            '3' {
                Invoke-TenantCheckStep -StepName "Remove Teams Reader role" -RequiredRoles $script:RolesPrivRole -Action {
                    Remove-TeamsReaderRoleAssignment -SpObjectId $state.SpObjectId
                } | Out-Null
            }
            '4' {
                Invoke-TenantCheckStep -StepName "Remove Azure RBAC" -RequiredRoles $script:RolesGlobalOnly -Action {
                    Revoke-AzureReaderAccess -SpObjectId $state.SpObjectId
                } | Out-Null
            }
            '5' {
                $envUrl = Read-Host "Dataverse environment URL"
                $hard = Read-Host "Hard-delete the application user instead of just disabling it? (y/N)"
                Invoke-TenantCheckStep -StepName "Remove Dataverse access" -RequiredRoles $script:RolesPowerPlatform -Action {
                    Remove-DataverseCopilotStudioAccess -EnvironmentUrl $envUrl -AppClientId $state.AppId -HardDelete:($hard -eq 'y')
                } | Out-Null
            }
            '6' {
                $removeLocal = Read-Host "Also remove the local certificate from Cert:\CurrentUser\My? (y/N)"
                Invoke-TenantCheckStep -StepName "Remove certificate(s)" -RequiredRoles $script:RolesAppAdmin -Action {
                    Remove-TenantCheckAppCertificate -AppObjectId $state.AppObjectId -RemoveLocalCertificate:($removeLocal -eq 'y')
                } | Out-Null
            }
            'A' {
                Invoke-TenantCheckStep -StepName "Remove certificate(s)" -RequiredRoles $script:RolesAppAdmin -Action {
                    Remove-TenantCheckAppCertificate -AppObjectId $state.AppObjectId
                } | Out-Null

                $envUrl = Read-Host "Dataverse environment URL for the rollback (leave empty to skip)"
                if ($envUrl) {
                    Invoke-TenantCheckStep -StepName "Remove Dataverse access" -RequiredRoles $script:RolesPowerPlatform -Action {
                        Remove-DataverseCopilotStudioAccess -EnvironmentUrl $envUrl -AppClientId $state.AppId
                    } | Out-Null
                }

                Invoke-TenantCheckStep -StepName "Remove Azure RBAC" -RequiredRoles $script:RolesGlobalOnly -Action {
                    Revoke-AzureReaderAccess -SpObjectId $state.SpObjectId
                } | Out-Null

                Invoke-TenantCheckStep -StepName "Remove Teams Reader role" -RequiredRoles $script:RolesPrivRole -Action {
                    Remove-TeamsReaderRoleAssignment -SpObjectId $state.SpObjectId
                } | Out-Null

                Invoke-TenantCheckStep -StepName "Remove Exchange Online RBAC" -RequiredRoles $script:RolesExchange -Action {
                    Remove-ExchangeOnlineRbacRole -AppId $state.AppId
                } | Out-Null

                Invoke-TenantCheckStep -StepName "Remove Security Reader role" -RequiredRoles $script:RolesPrivRole -Action {
                    Remove-SecurityComplianceRoleAssignment -SpObjectId $state.SpObjectId
                } | Out-Null

                Invoke-TenantCheckStep -StepName "Remove Graph/Exchange permissions" -RequiredRoles $script:RolesAppAdmin -Action {
                    Remove-TenantCheckAppRegistration -AppObjectId $state.AppObjectId -SpObjectId $state.SpObjectId
                } | Out-Null

                Write-Host ""
                Write-Host "Rollback complete (see any warnings above about skipped steps). The app registration itself was NOT deleted (option X for a complete deletion)." -ForegroundColor Green
            }
            'X' {
                Invoke-TenantCheckStep -StepName "Delete the app registration completely" -RequiredRoles $script:RolesAppAdmin -Action {
                    Remove-TenantCheckAppRegistration -AppObjectId $state.AppObjectId -SpObjectId $state.SpObjectId -DeleteApplication
                } | Out-Null
            }
            'Q' { return }
            default { Write-Warning "Invalid choice." }
        }
    } while ($true)
}

# ======================================================================================
# Module 8: Export / customer handoff
# ======================================================================================

function Export-TenantCheckPackage {
    <#
    .SYNOPSIS
        Creates a handoff package (Markdown summary + certificate) as a ZIP that the customer can
        provide to Previder to fill in Connect-And-Run-Maester.ps1 and the maester-config.json
        (Dataverse).
    .DESCRIPTION
        Includes AppId, TenantId, default domain, object IDs, the certificate thumbprint/subject/
        validity, the public key (.cer), and - since Previder needs it to authenticate as the app
        from its own infrastructure - the private key as a password-protected .pfx, both freshly
        exported from the local certificate store. The PFX password is never written to the
        package; it must be sent to Previder through a separate channel. Also includes the
        Dataverse environment URL if set.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $State,
        [string] $CustomerTag,
        [string] $OutputPath
    )

    Connect-GraphForSetup

    if (-not $State.AppId) { $State.AppId = Read-Host "App (Client) ID" }
    if (-not $State.SpObjectId) { $State.SpObjectId = Read-Host "Service Principal Object ID (Enterprise App) (optional, press Enter to skip)" }
    if (-not $State.CertThumbprint) { $State.CertThumbprint = Read-Host "Certificate thumbprint (optional, press Enter to skip)" }

    if (-not $CustomerTag) { $CustomerTag = Get-TenantCheckCustomerTag }

    $tenantId = (Get-MgContext).TenantId
    $defaultDomain = $null
    try {
        $org = Get-MgOrganization -Property DisplayName, VerifiedDomains -ErrorAction Stop | Select-Object -First 1
        if ($org) { $defaultDomain = ($org.VerifiedDomains | Where-Object { $_.IsDefault }).Name }
    } catch {
        Write-Verbose "Could not determine the default domain: $($_.Exception.Message)"
    }

    if (-not $OutputPath) { $OutputPath = "C:\Scripts\$($script:AppDisplayName)-$CustomerTag-Export" }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Export the certificate fresh from the local store, including the private key: Previder runs
    # Connect-And-Run-Maester.ps1 from its own infrastructure and needs the .pfx to authenticate as
    # the app. The PFX itself is password-protected; the password must travel to Previder through a
    # separate channel (phone, Teams chat, Signal, ...) - never in the same email as this ZIP.
    $cerDestination = $null
    $pfxDestination = $null
    if ($State.CertThumbprint) {
        $localCert = Get-Item "Cert:\CurrentUser\My\$($State.CertThumbprint)" -ErrorAction SilentlyContinue
        if ($localCert) {
            $cerDestination = Join-Path $OutputPath "$($script:AppDisplayName)-$CustomerTag.cer"
            Export-Certificate -Cert $localCert -FilePath $cerDestination | Out-Null

            if (-not $localCert.HasPrivateKey) {
                Write-Warning "The certificate with thumbprint '$($State.CertThumbprint)' has no private key in this store - the .pfx cannot be exported. Only the public key (.cer) will be included."
            } else {
                $pfxPassword = $null
                while (-not $pfxPassword -or $pfxPassword.Length -eq 0) {
                    $pfxPassword = Read-Host "Password to protect the PFX export (mandatory - send it to Previder through a SEPARATE channel, never together with this ZIP)" -AsSecureString
                    if (-not $pfxPassword -or $pfxPassword.Length -eq 0) {
                        Write-Warning "A password is required to export the private key."
                    }
                }
                $pfxDestination = Join-Path $OutputPath "$($script:AppDisplayName)-$CustomerTag.pfx"
                Export-PfxCertificate -Cert $localCert -FilePath $pfxDestination -Password $pfxPassword | Out-Null
            }
        } else {
            Write-Warning "No certificate with thumbprint '$($State.CertThumbprint)' found in the local store - the certificate files will not be included."
        }
    }

    $md = New-Object System.Collections.Generic.List[string]
    $md.Add("# Previder Tenant Check - Handoff to Previder")
    $md.Add("")
    $md.Add("Created on: $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
    $md.Add("")
    $md.Add("## Customer / Tenant")
    $md.Add("- Label: $CustomerTag")
    $md.Add("- Tenant ID: $tenantId")
    if ($defaultDomain) { $md.Add("- Default domain (organization): $defaultDomain") }
    $md.Add("")
    $md.Add("## App Registration")
    $md.Add("- App (Client) ID: $($State.AppId)")
    if ($State.AppObjectId) { $md.Add("- Application Object ID: $($State.AppObjectId)") }
    if ($State.SpObjectId) { $md.Add("- Service Principal Object ID: $($State.SpObjectId)") }
    $md.Add("")
    $md.Add("## Certificate")
    if ($State.CertThumbprint) {
        $md.Add("- Thumbprint: $($State.CertThumbprint)")
        if ($State.CertSubject) { $md.Add("- Subject: $($State.CertSubject)") }
        if ($State.CertNotAfter) { $md.Add("- Valid until: $($State.CertNotAfter)") }
        if ($cerDestination) { $md.Add("- Public key included: $(Split-Path $cerDestination -Leaf)") }
        if ($pfxDestination) {
            $md.Add("- Private key included (password-protected): $(Split-Path $pfxDestination -Leaf)")
            $md.Add("")
            $md.Add("> **Important:** The PFX password is NOT included in this package or this file.")
            $md.Add("> Send it to Previder through a SEPARATE channel (e.g. phone call, Teams chat, Signal) -")
            $md.Add("> never in the same email or chat message as this ZIP.")
        } else {
            $md.Add("")
            $md.Add("> **Note:** Only the public key (.cer) is included - the private key (.pfx) could not be exported (see warnings printed during creation).")
        }
    } else {
        $md.Add("- No certificate recorded - please provide the thumbprint separately.")
    }
    $md.Add("")
    $md.Add("## Dataverse / Copilot Studio")
    if ($State.DataverseEnvironmentUrl) {
        $md.Add("- Environment URL: $($State.DataverseEnvironmentUrl)")
    } else {
        $md.Add("- No Copilot Studio environment set up (or not in use).")
    }
    $md.Add("")

    $configured = $State.Configured
    if (-not $configured) { $configured = @{} }

    $md.Add("## Configured Modules (as of this session)")
    $moduleStatus = [ordered]@{
        "Module 1 - App registration + Graph permissions" = $configured.AppRegistration
        "Module 2a - Exchange Online Graph permissions"    = $configured.ExchangeGraphPermission
        "Module 2b - Exchange Online RBAC role"            = $configured.ExchangeRbac
        "Module 2c - Security Reader role (EXO/SCC)"       = $configured.SecurityReader
        "Module 3 - Teams Reader role"                     = $configured.Teams
        "Module 4 - Azure RBAC (Reader)"                   = $configured.Azure
        "Module 5 - Dataverse/Copilot Studio"              = $configured.Dataverse
        "Module 6 - Certificate"                           = $configured.Certificate
    }
    foreach ($key in $moduleStatus.Keys) {
        $mark = switch ($moduleStatus[$key]) {
            $true  { "[x]" }
            $false { "[ ]" }
            default { "[?] unknown - not run in this session" }
        }
        $md.Add("- $mark $key")
    }
    $md.Add("")
    $md.Add("> Status reflects only what was run in THIS session of the setup script.")
    $md.Add("> If a module was already set up in an earlier run and not called again here,")
    $md.Add("> it still shows as '[?] unknown'.")

    $commentOutHints = New-Object System.Collections.Generic.List[string]
    if ($configured.ExchangeGraphPermission -eq $false -or $configured.ExchangeRbac -eq $false) {
        $commentOutHints.Add("Connect-ExchangeOnline (section 4) - Exchange Online permission not fully set up")
    }
    if ($configured.SecurityReader -eq $false) {
        $commentOutHints.Add("Connect-IPPSSession / Security & Compliance (section 7) - Security Reader role not assigned")
    }
    if ($configured.Teams -eq $false) {
        $commentOutHints.Add("Connect-MicrosoftTeams (section 5) - Teams Reader role not assigned")
    }
    if ($configured.Azure -eq $false) {
        $commentOutHints.Add("Connect-AzAccount (section 6) - Azure RBAC not set up")
    }
    if ($commentOutHints.Count -gt 0) {
        $md.Add("")
        $md.Add("## For Previder: comment out in Connect-And-Run-Maester.ps1")
        foreach ($hint in $commentOutHints) { $md.Add("- $hint") }
    }
    $md.Add("")
    $md.Add("## For Previder: Connect-And-Run-Maester.ps1 configuration block")
    $md.Add('```powershell')
    $md.Add("`$appId          = `"$($State.AppId)`"")
    $md.Add("`$tenantId       = `"$tenantId`"")
    $md.Add("`$organization   = `"$defaultDomain`"")
    $md.Add("`$certThumbprint = `"$($State.CertThumbprint)`"")
    $md.Add('```')
    if ($State.DataverseEnvironmentUrl) {
        $md.Add("")
        $md.Add("## For Previder: maester-config.json")
        $md.Add('```json')
        $md.Add('{ "GlobalSettings": { "DataverseEnvironmentUrl": "' + $State.DataverseEnvironmentUrl + '" } }')
        $md.Add('```')
    }

    $mdPath = Join-Path $OutputPath "Previder-TenantCheck-$CustomerTag.md"
    $md -join "`r`n" | Set-Content -Path $mdPath -Encoding UTF8

    $zipPath = Join-Path $OutputPath "Previder-TenantCheck-$CustomerTag.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    $itemsToZip = @($mdPath)
    if ($cerDestination) { $itemsToZip += $cerDestination }
    if ($pfxDestination) { $itemsToZip += $pfxDestination }
    Compress-Archive -Path $itemsToZip -DestinationPath $zipPath -Force

    Write-Host ""
    Write-Host "Handoff package created: $zipPath" -ForegroundColor Green
    Write-Host "   Contains: $(($itemsToZip | ForEach-Object { Split-Path $_ -Leaf }) -join ', ')" -ForegroundColor Cyan
    if ($pfxDestination) {
        Write-Host "   Includes the PASSWORD-PROTECTED private key (.pfx) - send the password to Previder through a separate channel, never together with this ZIP." -ForegroundColor Yellow
    } else {
        Write-Host "   Does NOT contain the private key (.pfx) - see the warning above." -ForegroundColor Yellow
    }

    return $zipPath
}

# ======================================================================================
# Interactive menu
# ======================================================================================

function Show-TenantCheckSetupMenu {
    [CmdletBinding()]
    param()

    $state = @{
        AppId                   = $null
        AppObjectId             = $null
        SpObjectId              = $null
        CertThumbprint          = $null
        CertSubject             = $null
        CertNotAfter            = $null
        DataverseEnvironmentUrl = $null
        # $null = not run in this session (unknown), $true/$false = the step's result.
        # Used in Export-TenantCheckPackage to say which Connect-*  blocks in
        # Connect-And-Run-Maester.ps1 need to be commented out.
        Configured = @{
            AppRegistration         = $null
            ExchangeGraphPermission = $null
            ExchangeRbac            = $null
            SecurityReader          = $null
            Teams                   = $null
            Azure                   = $null
            Dataverse               = $null
            Certificate             = $null
        }
    }

    do {
        Write-Host ""
        Write-Host "=========================================="
        Write-Host " Previder_TenantCheck - Setup Assistant"
        Write-Host "=========================================="
        Write-Host " 1) Create/update app registration + Graph permissions"
        Write-Host " 2) Exchange Online permissions (Graph) + RBAC role + Security Reader (SCC)"
        Write-Host " 3) Assign Teams Reader role"
        Write-Host " 4) Azure RBAC (Reader: root, Entra diagnostics, Intune)"
        Write-Host " 5) Dataverse/Copilot Studio permission (with auto-scan)"
        Write-Host " 6) Create certificate + attach to app registration"
        Write-Host " A) Run everything (1-6 in sequence, with prompts)"
        Write-Host " E) Create handoff package for Previder (Markdown + certificate as ZIP)"
        Write-Host " D) Decommissioning menu (remove permissions/resources)"
        Write-Host " S) Show current status (AppId/ObjectIds)"
        Write-Host " Q) Exit"
        Write-Host "=========================================="
        $choice = Read-Host "Choice"

        switch ($choice.ToUpper()) {
            '1' {
                $state.Configured.AppRegistration = Invoke-TenantCheckStep -StepName "App registration + Graph permissions" -RequiredRoles $script:RolesAppAdmin -Action {
                    $result = New-TenantCheckAppRegistration
                    $state.AppId = $result.AppId
                    $state.AppObjectId = $result.AppObjectId
                    $state.SpObjectId = $result.SpObjectId
                }
            }
            '2' {
                if (-not $state.AppId) { $state.AppId = Read-Host "App (Client) ID" }
                if (-not $state.AppObjectId) { $state.AppObjectId = Read-Host "Application Object ID" }
                if (-not $state.SpObjectId) { $state.SpObjectId = Read-Host "Service Principal Object ID (Enterprise App)" }

                $state.Configured.ExchangeGraphPermission = Invoke-TenantCheckStep -StepName "Exchange Online Graph permissions" -RequiredRoles $script:RolesAppAdmin -Action {
                    Add-ExchangeOnlineGraphPermission -SpObjectId $state.SpObjectId -AppObjectId $state.AppObjectId
                }

                $runExo = Read-Host "Also set the EXO RBAC role now (requires an Exchange admin sign-in)? (y/N)"
                if ($runExo -eq 'y') {
                    $state.Configured.ExchangeRbac = Invoke-TenantCheckStep -StepName "Exchange Online RBAC role" -RequiredRoles $script:RolesExchange -Action {
                        Set-ExchangeOnlineRbacRole -AppId $state.AppId -SpObjectId $state.SpObjectId
                    }
                } else {
                    $state.Configured.ExchangeRbac = $false
                }

                $state.Configured.SecurityReader = Invoke-TenantCheckStep -StepName "Security Reader role (EXO/SCC)" -RequiredRoles $script:RolesPrivRole -Action {
                    Add-SecurityComplianceRoleAssignment -SpObjectId $state.SpObjectId
                }
            }
            '3' {
                if (-not $state.SpObjectId) { $state.SpObjectId = Read-Host "Service Principal Object ID (Enterprise App)" }
                $state.Configured.Teams = Invoke-TenantCheckStep -StepName "Teams Reader role" -RequiredRoles $script:RolesPrivRole -Action {
                    Add-TeamsReaderRoleAssignment -SpObjectId $state.SpObjectId
                }
            }
            '4' {
                if (-not $state.SpObjectId) { $state.SpObjectId = Read-Host "Service Principal Object ID (Enterprise App)" }
                $state.Configured.Azure = Invoke-TenantCheckStep -StepName "Azure RBAC (Reader)" -RequiredRoles $script:RolesGlobalOnly -Action {
                    Grant-AzureReaderAccess -SpObjectId $state.SpObjectId
                }
            }
            '5' {
                if (-not $state.AppId) { $state.AppId = Read-Host "App (Client) ID" }
                $roleModeChoice = Read-Host "Role mode: [1] Basic User (simple) or [2] custom least-privilege role (recommended, default) - choice"
                $roleMode = if ($roleModeChoice -eq '1') { 'BasicUser' } else { 'CustomRole' }
                $state.Configured.Dataverse = Invoke-TenantCheckStep -StepName "Dataverse/Copilot Studio permission" -RequiredRoles $script:RolesPowerPlatform -Action {
                    $active = Invoke-DataverseCopilotStudioSetup -AppClientId $state.AppId -RoleMode $roleMode
                    if ($active -and $active.Count -gt 0) { $state.DataverseEnvironmentUrl = $active[0].EnvironmentUrl }
                }
            }
            '6' {
                if (-not $state.AppObjectId) { $state.AppObjectId = Read-Host "Application Object ID" }
                $state.Configured.Certificate = Invoke-TenantCheckStep -StepName "Create certificate + attach it" -RequiredRoles $script:RolesAppAdmin -Action {
                    $cert = New-TenantCheckCertificate
                    Set-TenantCheckAppCertificate -AppObjectId $state.AppObjectId -Certificate $cert
                    $state.CertThumbprint = $cert.Thumbprint
                    $state.CertSubject = $cert.Subject
                    $state.CertNotAfter = $cert.NotAfter
                }
            }
            'A' {
                $state.Configured.AppRegistration = Invoke-TenantCheckStep -StepName "App registration + Graph permissions" -RequiredRoles $script:RolesAppAdmin -Action {
                    $result = New-TenantCheckAppRegistration
                    $state.AppId = $result.AppId
                    $state.AppObjectId = $result.AppObjectId
                    $state.SpObjectId = $result.SpObjectId
                }

                if (-not $state.AppId) {
                    Write-Warning "Without a successful app registration, the remaining steps cannot be run meaningfully. 'Run everything' aborted."
                    return
                }

                $runExoGraph = Read-Host "`nSet Exchange Online permissions? (Y/n)"
                if ($runExoGraph -ne 'n') {
                    $state.Configured.ExchangeGraphPermission = Invoke-TenantCheckStep -StepName "Exchange Online Graph permissions" -RequiredRoles $script:RolesAppAdmin -Action {
                        Add-ExchangeOnlineGraphPermission -SpObjectId $state.SpObjectId -AppObjectId $state.AppObjectId
                    }

                    $runExo = Read-Host "Set the EXO RBAC role now (requires an Exchange admin sign-in)? (y/N)"
                    if ($runExo -eq 'y') {
                        $state.Configured.ExchangeRbac = Invoke-TenantCheckStep -StepName "Exchange Online RBAC role" -RequiredRoles $script:RolesExchange -Action {
                            Set-ExchangeOnlineRbacRole -AppId $state.AppId -SpObjectId $state.SpObjectId
                        }
                    } else {
                        $state.Configured.ExchangeRbac = $false
                    }

                    $state.Configured.SecurityReader = Invoke-TenantCheckStep -StepName "Security Reader role (EXO/SCC)" -RequiredRoles $script:RolesPrivRole -Action {
                        Add-SecurityComplianceRoleAssignment -SpObjectId $state.SpObjectId
                    }
                } else {
                    $state.Configured.ExchangeGraphPermission = $false
                    $state.Configured.ExchangeRbac = $false
                    $state.Configured.SecurityReader = $false
                }

                $runTeams = Read-Host "`nAssign the Teams Reader role? (Y/n)"
                if ($runTeams -ne 'n') {
                    $state.Configured.Teams = Invoke-TenantCheckStep -StepName "Teams Reader role" -RequiredRoles $script:RolesPrivRole -Action {
                        Add-TeamsReaderRoleAssignment -SpObjectId $state.SpObjectId
                    }
                } else {
                    $state.Configured.Teams = $false
                }

                $runAzure = Read-Host "`nSet up Azure RBAC - root/aadiam/Intune (requires a Global Admin sign-in)? (Y/n)"
                if ($runAzure -ne 'n') {
                    $state.Configured.Azure = Invoke-TenantCheckStep -StepName "Azure RBAC (Reader)" -RequiredRoles $script:RolesGlobalOnly -Action {
                        Grant-AzureReaderAccess -SpObjectId $state.SpObjectId
                    }
                } else {
                    $state.Configured.Azure = $false
                }

                $runDataverse = Read-Host "`nRun the Dataverse/Copilot Studio scan? (Y/n)"
                if ($runDataverse -ne 'n') {
                    $state.Configured.Dataverse = Invoke-TenantCheckStep -StepName "Dataverse/Copilot Studio permission" -RequiredRoles $script:RolesPowerPlatform -Action {
                        $active = Invoke-DataverseCopilotStudioSetup -AppClientId $state.AppId -RoleMode 'CustomRole'
                        if ($active -and $active.Count -gt 0) { $state.DataverseEnvironmentUrl = $active[0].EnvironmentUrl }
                    }
                } else {
                    $state.Configured.Dataverse = $false
                }

                $runCert = Read-Host "`nCreate and attach a certificate? (Y/n)"
                if ($runCert -ne 'n') {
                    $state.Configured.Certificate = Invoke-TenantCheckStep -StepName "Create certificate + attach it" -RequiredRoles $script:RolesAppAdmin -Action {
                        $cert = New-TenantCheckCertificate
                        Set-TenantCheckAppCertificate -AppObjectId $state.AppObjectId -Certificate $cert
                        $state.CertThumbprint = $cert.Thumbprint
                        $state.CertSubject = $cert.Subject
                        $state.CertNotAfter = $cert.NotAfter
                    }
                } else {
                    $state.Configured.Certificate = $false
                }

                $runExport = Read-Host "`nCreate the handoff package for Previder now (Markdown + certificate as ZIP)? (Y/n)"
                if ($runExport -ne 'n') {
                    Invoke-TenantCheckStep -StepName "Create handoff package" -Action {
                        Export-TenantCheckPackage -State $state
                    } | Out-Null
                }

                Write-Host ""
                Write-Host "Setup complete (see any warnings above about skipped steps)." -ForegroundColor Green
            }
            'E' {
                Invoke-TenantCheckStep -StepName "Create handoff package" -Action {
                    Export-TenantCheckPackage -State $state
                } | Out-Null
            }
            'D' {
                Show-TenantCheckDecommissionMenu
            }
            'S' {
                Write-Host ""
                Write-Host "AppId:                   $($state.AppId)"
                Write-Host "AppObjectId:             $($state.AppObjectId)"
                Write-Host "SpObjectId:              $($state.SpObjectId)"
                Write-Host "CertThumbprint:          $($state.CertThumbprint)"
                Write-Host "DataverseEnvironmentUrl: $($state.DataverseEnvironmentUrl)"
            }
            'Q' { return }
            default { Write-Warning "Invalid choice." }
        }
    } while ($true)
}

# ======================================================================================
# Entry point
# ======================================================================================

if (-not $NoMenu) {
    Show-TenantCheckSetupMenu
}
