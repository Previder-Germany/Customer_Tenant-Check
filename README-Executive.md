# Previder Tenant Check - Executive Summary

This document is for non-technical customer contacts.

It explains what we are setting up, why it is needed, what your organization should provide, and what happens after the assessment.

---

## What this is

Previder performs a **Tenant Check** to assess the security posture of your Microsoft cloud environment.

To do this safely and consistently, a dedicated application identity is set up in your tenant. This identity gives Previder controlled read access to the areas included in scope.

---

## Why this setup is needed

The setup enables:

- Structured, repeatable security checks
- Consistent data collection across relevant Microsoft services
- Controlled access that can be removed again after the engagement

Without this setup, parts of the assessment may be incomplete or require manual alternatives.

---

## What may be included in scope

Depending on your environment and agreed scope, access can include:

- Microsoft Entra / Microsoft Graph
- Exchange Online
- Microsoft Teams
- Azure and Intune-related RBAC read scopes
- Dataverse / Copilot Studio (only when relevant)

Only required modules are applied.

---

## What your organization needs to provide

1. An authorized contact person for coordination.
2. An administrator to run/approve setup actions in your tenant.
3. Confirmation of which service areas are in scope.
4. A secure communication channel for sensitive information.

---

## Security approach

- Access is configured for assessment purposes and can be rolled back.
- Certificate-based authentication can be used for stronger security.
- Sensitive private key material is password-protected.
- Passwords must be shared through a separate channel.

Example best practice:

- Send the handoff package by email.
- Send the password by phone call or separate Teams message.

---

## Deliverables you will receive or provide

At handover, a package can be generated that contains:

- Tenant and application identifiers
- Certificate public key file
- Password-protected private key file (if required)
- Configuration summary for Previder operations

This package helps Previder run the agreed checks efficiently.

---

## Your decision points

You decide:

1. Which modules are enabled (based on agreed scope).
2. Whether Dataverse/Copilot Studio is included.
3. Whether full rollback or complete app deletion is required after completion.

---

## After the assessment

When the project is complete, you can choose to:

- Remove granted permissions while keeping the app record, or
- Fully delete the app registration and related access

This supports clean closure and governance requirements.

---

## Timeline (typical)

1. Scope confirmation
2. Setup and validation
3. Handover package creation
4. Assessment execution by Previder
5. Optional rollback/decommissioning

---

## Non-technical checklist

Before assessment starts:

- Scope is approved
- Responsible admin is assigned
- Secure password-sharing method is defined

Before handover to Previder:

- Handover package is generated
- Package transmission channel is agreed
- Password transmission channel is separate

After assessment:

- Decommission decision is confirmed
- Rollback/full deletion is completed as agreed

---

## Questions or changes

If your internal policy requires stricter controls, reduced scope, or accelerated rollback, inform Previder before execution so the setup can be adapted.
