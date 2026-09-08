# Previder Tenant Check Setup Assistant

This repository contains a PowerShell setup assistant for preparing a customer tenant for the **Previder Tenant Check**.

The script creates and configures a dedicated Entra app registration, applies only the modules you need (Graph, Exchange, Teams, Azure, Dataverse/Copilot Studio, certificate auth), and can also roll everything back.

## Audience

- Technical implementation guide: this document
- Non-technical executive summary: [README-Executive.md](README-Executive.md)

---

## What this script does

The script file is:

- `New-PreviderTenantCheckApp.ps1`

It provides a guided menu and modular functions for:

1. App registration + Microsoft Graph permissions
2. Exchange Online permissions + EXO RBAC role
3. Teams Reader role assignment
4. Azure RBAC Reader assignments (root, Microsoft.aadiam, Microsoft.Intune)
5. Dataverse/Copilot Studio app user + security role (with auto-scan)
6. Certificate creation + app certificate attachment
7. Decommissioning (rollback)
8. Customer handoff export package (ZIP)

---

## Why it is modular

Not every tenant uses every workload. For example:

- No Exchange Online tests needed -> skip Exchange modules
- No Azure subscription / Intune scope needed -> skip Azure module
- No Copilot Studio in use -> skip Dataverse module

You can run only the modules that match your environment.

---

## Prerequisites

## 1) PowerShell

- PowerShell 7+ is recommended
- For certificate generation (module 6), `New-SelfSignedCertificate` must be available
  - Typically available on Windows PowerShell / PowerShell on Windows

## 2) Required admin roles (depending on module)

- Global Administrator (recommended overall)
- Exchange Administrator (for Exchange RBAC actions)
- Power Platform / Dataverse admin rights for Dataverse module

Important:

- The script performs a role pre-check and warns if active roles seem missing.
- PIM-eligible roles must be activated before running the module.

## 3) Required PowerShell modules

The script auto-installs missing modules (CurrentUser scope):

- Microsoft.Graph.Applications
- Microsoft.Graph.Identity.DirectoryManagement
- Microsoft.Graph.Authentication
- Az.Accounts
- Az.Resources
- ExchangeOnlineManagement (only when Exchange module is used)

---

## Quick start

Run the script interactively:

```powershell
.\New-PreviderTenantCheckApp.ps1
```

Load functions only (no menu):

```powershell
. .\New-PreviderTenantCheckApp.ps1 -NoMenu
```

In the menu:

- Use option `A` to run a complete guided setup
- Use options `1..6` for selective setup
- Use option `E` to create a customer handoff ZIP
- Use option `D` for decommissioning

---

## Menu overview

### Setup menu

1. Create/update app registration + Graph permissions
2. Exchange Online permissions (Graph) + RBAC + Security Reader
3. Assign Teams Reader role
4. Assign Azure RBAC Reader on required scopes
5. Configure Dataverse/Copilot Studio permissions
6. Create and attach certificate
A. Run all setup modules in sequence
E. Export handoff package for Previder
D. Open decommissioning menu
S. Show current state
Q. Exit

### Decommissioning menu

Rollback options let you remove selected assignments/resources, or all of them.

- Default rollback keeps the app registration shell unless full deletion is explicitly selected.
- Full delete requires an explicit confirmation (typing app name).

---

## Detailed module explanation

## Module 1: App registration + Microsoft Graph permissions

Creates or updates app registration `Previder_TenantCheck` and its service principal, then configures and grants required Graph permissions.

Includes:

- Application permissions (read/security/audit/policy/device/directory scopes used by tenant checks)
- Delegated `User.Read`
- Admin consent handling for delegated scope

Outputs:

- App (Client) ID
- Application Object ID
- Service Principal Object ID

## Module 2: Exchange Online

### 2a) Exchange API permissions on app

Adds Exchange application permissions and grants them:

- `Exchange.ManageAsApp`
- `Exchange.ManageAsAppV2`

### 2b) Exchange RBAC role

Connects to Exchange Online and assigns:

- `View-Only Configuration`

If required, the script can trigger one-time `Enable-OrganizationCustomization` after explicit prompt.

### 2c) Security Reader role (for Security & Compliance PowerShell)

Assigns Entra directory role:

- `Security Reader`

This is needed for Security & Compliance PowerShell app-only scenarios (`Connect-IPPSSession`).

## Module 3: Teams Reader role

Assigns Entra directory role:

- `Teams Reader`

Used for Teams-related read checks.

## Module 4: Azure RBAC Reader

Assigns Reader role to service principal on:

- `/`
- `/providers/Microsoft.aadiam`
- `/providers/Microsoft.Intune`

Behavior:

- Script temporarily elevates current admin for root-scope operation
- Script removes only its own temporary elevation afterward
- App role assignments remain in place

## Module 5: Dataverse / Copilot Studio

Flow:

1. Enumerates Power Platform environments
2. Filters Dataverse-enabled environments
3. Checks Copilot Studio usage by looking for active bots
4. Configures only relevant environments

Creates/uses application user and assigns either:

- Basic User role, or
- Custom least-privilege role (`Previder TenantCheck Security Reader`) with required read privileges

If no active Copilot Studio environments are found, setup is skipped by design.

## Module 6: Certificate-based authentication

Creates a self-signed certificate and attaches public key to app registration.

Features:

- Customer/tenant tag in subject/friendly name for easy identification
- Exports `.cer` always
- Optional `.pfx` export with password

After attachment, script prints connection examples for:

- Microsoft Graph
- Azure
- Exchange Online

## Module 7: Decommissioning

Rollback can remove:

- Graph/Exchange permissions
- Exchange RBAC + Security Reader
- Teams Reader
- Azure RBAC assignments
- Dataverse access
- App certificates

Optional full app deletion is available and irreversible.

## Module 8: Customer handoff export

Creates a ZIP package containing:

- Markdown handoff summary
- Exported `.cer`
- Exported password-protected `.pfx` (if available)

Summary includes:

- Tenant and app IDs
- certificate details
- module status from current session
- suggested configuration snippets for Previder scripts

---

## Security and handling guidelines

- Treat the `.pfx` as sensitive secret material.
- Never send ZIP and PFX password in the same channel.
- Use separate channel for password (for example phone call or separate Teams message).
- Keep export folder access restricted.
- Use decommissioning when engagement is completed.

---

## Typical customer workflow

1. Start script and run option `A` (or selected modules only)
2. Validate all required modules for your scope are successful
3. Run option `E` to create handoff ZIP
4. Send ZIP to Previder
5. Send PFX password separately
6. After project completion, run decommissioning option(s)

---

## Troubleshooting

### Missing permissions / role warnings

- Activate required role in PIM first
- Re-run the module

### Exchange role assignment fails

- Ensure Exchange admin session is used
- If prompted, allow one-time `Enable-OrganizationCustomization`

### Dataverse environments not visible

- Ensure account has Power Platform admin rights
- Manually verify environments in Power Platform Admin Center if API access is limited

### Certificate cmdlet unavailable

- Run on Windows host with PKI cmdlets available

### Azure sign-in odd errors in mixed Graph/Az sessions

- Script attempts to disable WAM broker for current process to prevent known module collisions

---

## Notes

- Script is designed to be idempotent where possible (existing resources are detected and reused).
- Some operations are tenant-wide and/or security-critical; prompts are included before irreversible actions.
- Module status in handoff export reflects only actions in the current script session.

---

## Support handover checklist

Before handing over to Previder, confirm:

- App registration exists and IDs are documented
- Required module steps for your agreed scope are complete
- Certificate thumbprint is documented
- Handoff ZIP was generated successfully
- PFX password transmission path is defined separately

---

## File in this repository

- `New-PreviderTenantCheckApp.ps1`: complete setup, rollback, and export assistant
