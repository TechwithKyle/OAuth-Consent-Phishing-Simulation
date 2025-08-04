<p align="center">
  <img src="https://github.com/user-attachments/assets/c92d8f10-b20c-4fd1-a914-9db42d377e46" alt="Description" width="600">
</p>

---
## OAuth Consent Phishing Simulation with Microsoft Graph and User.Read Scope

---

# Platforms and Languages Leveraged

    Windows 10 Virtual Machines (Microsoft Azure)
    Microsoft Sentinel
    EDR Platform: Microsoft Defender for Endpoint
    Kusto Query Language (KQL)
    App registered in Azure Active Directory (multi-tenant)
    Python and MSAL used for token acquisition
    
---

## Scenario

This project demonstrates an OAuth consent phishing attack simulation using a multi-tenant Azure app. The goal was to simulate how an attacker can gain access to sensitive user data (without needing a password) by tricking a user into granting delegated access to a malicious application.

---

## Objective

### To simulate a realistic cloud-based attack path where a user unknowingly grants delegated access to a rogue application, allowing an attacker to:

- Read user profile information

- Persist access using refresh tokens

- Operate without detection if no user reports suspicious activity

---

## Attack Simulation Steps

App Registration: Registered a multi-tenant app in Azure AD with public client flow enabled.

Generated Consent URL: Shared phishing-style URL to trigger consent screen.

Consent: User accepted the app’s request for User.Read and offline_access scopes.

Access Token Retrieval: Used MSAL in Python to perform device code login.

API Call: Successfully queried Microsoft Graph API for the signed-in user's profile data.

Log Collection: Verified consent grant and app sign-ins using KQL queries in Sentinel.

---

## Sample Graph API Output

Display Name: e3cf69dbacbbce89aa76d8f5acef15ea51a051580fa22288481eedda249514de
UPN: e3cf69dbacbbce89aa76d8f5acef15ea51a051580fa22288481eedda249514de@lognpacific.com
ID: 5512a2c3-93f5-4e29-baf6-fc58c2710f19

---

## KQL Detection Queries Used

1. Consent Grant Detection

**Query used to locate events:**

```kql
AuditLogs
| where OperationName in ("Consent to application", "Add delegated permission grant")
| extend AppName = tostring(TargetResources[0].displayName)
| where AppName has "Phish" or AppName has "PhishMailReader" 
| project TimeGenerated, AppName, InitiatedBy, ActivityDisplayName, Result
```

<img width="1730" height="492" alt="image" src="https://github.com/user-attachments/assets/d6f27f8c-3d3a-42d5-ba6e-518f3ae0ec42" />

---

2. App Sign-in Usage

```kql
SigninLogs
| where AppDisplayName has "Phish" or AppDisplayName has "PhishMailReader"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ClientAppUsed
```

<img width="1734" height="756" alt="image" src="https://github.com/user-attachments/assets/5e6b6284-6d64-47c0-ba04-95f5039398af" />

---
## MITRE ATT&CK Mapping

T1078.004

Credential Access

Access Token Manipulation

T1528

Defense Evasion

Exploit Authorization Logic Flaw

T1550.003

Persistence

Cloud Service Permissions

T1098.001

Command and Control

Application Layer Protocol

T1071.001

---

## Recommendations

### Prevention

-Disable user consent to unverified applications in Entra ID settings.
- Require admin approval for apps requesting high-impact scopes (Mail.Read, Files.Read.All).
- Enable app consent policies and set trusted publisher restrictions.

---

## Detection

Deploy Sentinel analytic rules for:
- New delegated consent events
- Apps requesting offline_access, Files.Read.All, etc.
- Sign-ins from unknown app IDs

---

## Containment

- Revoke access tokens using:
- Revoke-MgUserSignInSession -UserId <UPN>
- Block sign-ins from malicious app client IDs
- Remove consent via: Enterprise Applications > Permissions
