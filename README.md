<p align="center">
  <img src="https://github.com/user-attachments/assets/c92d8f10-b20c-4fd1-a914-9db42d377e46" alt="Description" width="600">
</p>

---
## OAuth Consent Phishing Simulation with Microsoft Graph and User.Read Scope

---

# Platforms and Languages Leveraged

- Windows 10 Virtual Machines (Microsoft Azure)
- Microsoft Sentinel
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- App registered in Azure Active Directory (multi-tenant)
- Python and MSAL used for token acquisition
    
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

1) App Registration: Registered a multi-tenant app in Azure AD with public client flow enabled.

<img width="1035" height="419" alt="image" src="https://github.com/user-attachments/assets/191599d8-aa88-40a5-a7ef-d67cabe486bc" />

Redirects: 

<img width="1232" height="518" alt="image" src="https://github.com/user-attachments/assets/87819af4-9232-4d93-a3a7-084b1e0de59e" />

---

2) Generated Consent URL: Shared phishing-style URL to trigger consent screen. This link can be shared via email, any chat platform, etc.):

https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
client_id=<348ed938-8c24-4cb4-8dff-1b5ed4e31778>
&response_type=code
&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
&response_mode=query
&scope=Mail.Read offline_access User.Read
&state=attack123

---

3) Consent: User accepted the app’s request for User.Read and offline_access scopes.

<img width="966" height="1002" alt="image" src="https://github.com/user-attachments/assets/7eb88ce3-4923-4ac5-bf6a-e3b28ecc5469" />

Once the user clicks agree they will be redirected to a page such as this:

<img width="2034" height="1020" alt="image" src="https://github.com/user-attachments/assets/460c23ea-c15c-4dc7-af68-0417e143e171" />

---

4) Access Token Retrieval: Used MSAL in Python to perform device code login.

Prompt requesting to sign into app:

<img width="1202" height="782" alt="image" src="https://github.com/user-attachments/assets/c1844797-29a3-481e-9f2d-5ca6becfe20e" />

Once the user signs into the app they will see a notification such as this:

<img width="2466" height="1102" alt="image" src="https://github.com/user-attachments/assets/534412a3-a853-4678-b157-d16ce920a504" />

---

5) API Call: Successfully queried Microsoft Graph API for the signed-in user's profile data.

- Sample Graph API Output

Display Name: e3cf69dbacbbce89aa76d8f5acef15ea51a051580fa22288481eedda249514de
UPN: e3cf69dbacbbce89aa76d8f5acef15ea51a051580fa22288481eedda249514de@lognpacific.com
ID: 5512a2c3-93f5-4e29-baf6-fc58c2710f19

6) Log Collection: Verified consent grant and app sign-ins using KQL queries in Sentinel.

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

This Python script represents post-consent activity performed by an attacker. The victim only sees the Microsoft OAuth consent prompt in their browser. No scripts or malware are needed for this attack — just social engineering and permission abuse.


```Python
import msal, requests

client_id = "348ed938-8c24-4cb4-8dff-1b5ed4e31778"
authority = "https://login.microsoftonline.com/common"
scopes = ["User.Read", "offline_access"]

app = msal.PublicClientApplication(client_id, authority=authority)
flow = app.initiate_device_flow(scopes=scopes)

if "user_code" not in flow:
    raise ValueError("Failed to start device code flow")

print("\nTo authenticate:")
print(flow["message"])

result = app.acquire_token_by_device_flow(flow)

if "access_token" in result:
    print("\n✅ Authenticated successfully.")
    token = result["access_token"]
    r = requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    user = r.json()
    print("\n👤 User Info:")
    print(f"Display Name: {user.get('displayName')}")
    print(f"UPN: {user.get('userPrincipalName')}")
    print(f"ID: {user.get('id')}")
else:
    print("\n❌ Failed to authenticate:")
    print(result.get("error_description"))
```
---

After the above script is ran the output will be what is shown below. Allowing me access to the end user: 

<img width="2040" height="152" alt="image" src="https://github.com/user-attachments/assets/c1891655-fe94-4308-84ac-acc694ff405d" /> 

---
## MITRE ATT&CK Mapping

- T1078.004 Initial Access - Valid Accounts (Cloud Accounts
- T1528 Credential Access - Access Token Manipulation
- T1550.003 Defense Evasion - Exploit Authorization Logic Flaw
- T1098.001 Persistence - Cloud Service Permissions
- T1071.001 Command and Control - Application Layer Protocol

---

## Recommendations

### Prevention

- Disable user consent to unverified applications in Entra ID settings.
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

Revoke access tokens using:
- Revoke-MgUserSignInSession -UserId <UPN>
- Block sign-ins from malicious app client IDs
- Remove consent via: Enterprise Applications > Permissions
