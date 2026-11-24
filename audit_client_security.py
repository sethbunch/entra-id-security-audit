import csv
from datetime import datetime, timezone
from pathlib import Path
import msal
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
import requests

MICROSOFT_GRAPH_CLI_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
REQUEST_TIMEOUT = 30
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

SCOPES = [
    "https://graph.microsoft.com/UserAuthenticationMethod.Read.All",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/RoleManagement.Read.Directory",
    "https://graph.microsoft.com/Application.Read.All",
    "https://graph.microsoft.com/IdentityRiskyUser.Read.All",
]

HIGH_PRIV_APP_ROLES = {
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read",
    "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
}


def get_interactive_token(tenant: str, use_device_code: bool = False) -> tuple[str, str]:
    """Prompts interactive login for a client admin account and returns (access_token, identity_label)."""
    authority = f"https://login.microsoftonline.com/{tenant}"

    app = msal.PublicClientApplication(
        client_id=MICROSOFT_GRAPH_CLI_CLIENT_ID,
        authority=authority,
    )

    if use_device_code:
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise RuntimeError(f"Failed to initiate device flow: {flow}")
        print(flow["message"])
        result = app.acquire_token_by_device_flow(flow)
    else:
        result = app.acquire_token_interactive(
            scopes=SCOPES,
            prompt="select_account",
        )

    if "access_token" in result:
        claims = result.get("id_token_claims", {})
        upn = claims.get("preferred_username", "unknown_user")
        tid = claims.get("tid", tenant)
        return result["access_token"], f"{upn} ({tid})"

    raise RuntimeError(f"Authentication failed ({result.get('error')}): {result.get('error_description')}")


def graph_get_paginated(access_token: str, url: str, params: dict | None = None, optional: bool = False) -> list:
    """Fetches all pages from a Graph collection endpoint."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    items = []

    while url:
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT, verify=True)
        params = None

        if response.status_code != 200:
            if optional and response.status_code in (400, 403, 404):
                # TODO: surface skipped endpoints (e.g. "Conditional Access: skipped (no consent)")
                # to the GUI log so an empty tab reads as "not consented", not "no findings".
                return []
            raise RuntimeError(f"Graph API error on {url} ({response.status_code}): {response.text}")

        payload = response.json()
        items.extend(payload.get("value", []))
        url = payload.get("@odata.nextLink")

    return items


def graph_get_single(access_token: str, url: str) -> dict:
    """Fetches a single JSON object from Graph."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=True)
    if response.status_code != 200:
        return {}
    return response.json()


def parse_iso_days_ago(iso_str: str | None) -> int | str:
    """Calculates how many days ago an ISO-8601 timestamp occurred."""
    if not iso_str:
        return "Never"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return "Unknown"


def audit_users_and_mfa(token: str, client_label: str) -> list[list]:
    """Joins MFA registration details with directory user metadata."""
    mfa_records = graph_get_paginated(token, f"{GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails")
    user_records = graph_get_paginated(
        token,
        f"{GRAPH_BASE}/users",
        params={"$select": "id,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity"},
        optional=True,
    )

    user_lookup = {u.get("id"): u for u in user_records if u.get("id")}
    rows = []

    for rec in mfa_records:
        uid = rec.get("id")
        u_meta = user_lookup.get(uid, {})

        enabled_val = u_meta.get("accountEnabled")
        account_status = "Enabled" if enabled_val is True else ("Disabled" if enabled_val is False else "Unknown")
        user_type = u_meta.get("userType", "Unknown")

        sign_in = u_meta.get("signInActivity") or {}
        latest_signin = sign_in.get("lastSignInDateTime") or sign_in.get("lastNonInteractiveSignInDateTime")
        days_inactive = parse_iso_days_ago(latest_signin)

        rows.append([
            client_label,
            rec.get("userDisplayName", "N/A"),
            rec.get("userPrincipalName", "N/A"),
            account_status,
            user_type,
            "Yes" if rec.get("isMfaRegistered", False) else "No",
            "Yes" if rec.get("isMfaCapable", False) else "No",
            ", ".join(rec.get("methodsRegistered", [])),
            "Yes" if rec.get("isAdmin", False) else "No",
            latest_signin[:10] if latest_signin else "Never",
            days_inactive,
        ])

    return rows


def audit_privileged_roles(token: str, user_rows: list[list]) -> list[list]:
    """Audits active directory role assignments and cross-references MFA registration status."""
    roles = graph_get_paginated(token, f"{GRAPH_BASE}/directoryRoles?$expand=members", optional=True)
    mfa_by_upn = {r[2].lower(): (r[3], r[5], r[7]) for r in user_rows}

    role_rows = []
    for role in roles:
        role_name = role.get("displayName", "Unknown Role")
        for member in role.get("members", []):
            odata_type = member.get("@odata.type", "")
            member_type = "User" if "user" in odata_type else ("ServicePrincipal" if "servicePrincipal" in odata_type else "Group")
            # TODO: expand group members via /groups/{id}/members so nested users appear
            # with their own MFA status instead of the group object only.
            upn = member.get("userPrincipalName") or member.get("appId") or member.get("id", "N/A")
            display_name = member.get("displayName", "N/A")

            acct_status, has_mfa, methods = mfa_by_upn.get(upn.lower(), ("N/A", "N/A", "N/A"))
            role_rows.append([role_name, member_type, display_name, upn, acct_status, has_mfa, methods])

    return role_rows


def audit_conditional_access(token: str) -> list[list]:
    """Audits Conditional Access policies."""
    policies = graph_get_paginated(token, f"{GRAPH_BASE}/identity/conditionalAccess/policies", optional=True)
    ca_rows = []

    for p in policies:
        conditions = p.get("conditions", {})
        users = conditions.get("users", {})
        client_apps = ", ".join(conditions.get("clientAppTypes", []))
        grant = p.get("grantControls") or {}
        built_in_controls = ", ".join(grant.get("builtInControls", []))
        auth_strength = (grant.get("authenticationStrength") or {}).get("displayName", "")
        controls_summary = f"{built_in_controls} {f'({auth_strength})' if auth_strength else ''}".strip()

        inc_users = ", ".join(users.get("includeUsers", []))
        inc_roles = ", ".join(users.get("includeRoles", []))
        target_scope = f"Users: [{inc_users}] | Roles: [{inc_roles}]"

        ca_rows.append([
            p.get("displayName", "Unnamed Policy"),
            p.get("state", "unknown"),
            target_scope,
            client_apps or "All",
            controls_summary or "None",
            p.get("modifiedDateTime", "")[:10],
        ])

    return ca_rows


def audit_app_registrations(token: str) -> list[list]:
    """Audits App Registrations for expired/expiring credentials and high-privilege API permissions."""
    apps = graph_get_paginated(
        token,
        f"{GRAPH_BASE}/applications",
        params={"$select": "displayName,appId,passwordCredentials,keyCredentials,requiredResourceAccess"},
        optional=True,
    )
    now = datetime.now(timezone.utc)
    app_rows = []

    for app in apps:
        app_name = app.get("displayName", "Unnamed App")
        app_id = app.get("appId", "N/A")

        flagged_perms = []
        for resource in app.get("requiredResourceAccess", []):
            if resource.get("resourceAppId") == "00000003-0000-0000-c000-000000000000":
                for access in resource.get("resourceAccess", []):
                    if access.get("type") == "Role" and access.get("id") in HIGH_PRIV_APP_ROLES:
                        flagged_perms.append(HIGH_PRIV_APP_ROLES[access["id"]])

        high_priv_str = ", ".join(flagged_perms) if flagged_perms else "None"

        creds = []
        for pwd in app.get("passwordCredentials", []):
            creds.append(("Client Secret", pwd.get("displayName") or "Unnamed Secret", pwd.get("endDateTime")))
        for cert in app.get("keyCredentials", []):
            creds.append(("Certificate", cert.get("displayName") or "Unnamed Cert", cert.get("endDateTime")))

        if not creds:
            if flagged_perms:
                app_rows.append([app_name, app_id, "No Credentials", "N/A", "N/A", "N/A", high_priv_str])
            continue

        for cred_type, cred_name, end_iso in creds:
            status = "Valid"
            days_left: int | str = "Unknown"
            if end_iso:
                try:
                    end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
                    delta_days = (end_dt - now).days
                    days_left = delta_days
                    if delta_days < 0:
                        status = "EXPIRED"
                    elif delta_days <= 30:
                        status = "EXPIRING SOON (<=30d)"
                    elif delta_days > 730:
                        status = "EXCESSIVE LIFETIME (>2yr)"
                except ValueError:
                    pass

            app_rows.append([
                app_name,
                app_id,
                cred_type,
                cred_name,
                end_iso[:10] if end_iso else "N/A",
                f"{status} ({days_left}d)" if isinstance(days_left, int) else status,
                high_priv_str,
            ])

    return app_rows


def audit_risky_users(token: str, user_rows: list[list]) -> list[list]:
    """Audits Entra ID Protection Risky Users."""
    risky = graph_get_paginated(
        token,
        f"{GRAPH_BASE}/identityProtection/riskyUsers",
        params={"$filter": "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"},
        optional=True,
    )
    mfa_by_upn = {r[2].lower(): (r[3], r[5]) for r in user_rows}
    risky_rows = []

    for r in risky:
        upn = r.get("userPrincipalName", "N/A")
        acct_status, has_mfa = mfa_by_upn.get(upn.lower(), ("Unknown", "Unknown"))
        risky_rows.append([
            r.get("userDisplayName", "N/A"),
            upn,
            r.get("riskLevel", "unknown"),
            r.get("riskState", "unknown"),
            r.get("riskDetail", "unknown"),
            acct_status,
            has_mfa,
            (r.get("riskLastUpdatedDateTime") or "")[:10],
        ])

    return risky_rows


def audit_tenant_posture(token: str) -> list[list]:
    """Audits tenant-wide Security Defaults, Guest Invite settings, and Auth Method policies."""
    posture_rows = []

    sec_defaults = graph_get_single(token, f"{GRAPH_BASE}/policies/identitySecurityDefaultsEnforcementPolicy")
    if sec_defaults:
        posture_rows.append([
            "Security Defaults",
            "Enabled" if sec_defaults.get("isEnabled") else "Disabled",
            "Should be Enabled if no Conditional Access policies are used.",
        ])

    authz = graph_get_single(token, f"{GRAPH_BASE}/policies/authorizationPolicy")
    if authz:
        default_role = authz.get("defaultUserRolePermissions") or {}
        posture_rows.append([
            "Non-Admin Users Can Register Apps",
            str(default_role.get("allowedToCreateApps", "Unknown")),
            "Recommended: False (prevents illicit consent / rogue app persistence).",
        ])
        posture_rows.append([
            "Guest Invite Restrictions",
            authz.get("allowInvitesFrom", "Unknown"),
            "Recommended: adminsAndGuestInviters or none.",
        ])

    auth_methods = graph_get_single(token, f"{GRAPH_BASE}/policies/authenticationMethodsPolicy")
    for cfg in auth_methods.get("authenticationMethodConfigurations", []):
        method_id = cfg.get("id", "")
        if method_id in ("Sms", "Voice", "Email", "MicrosoftAuthenticator", "Fido2"):
            posture_rows.append([
                f"Auth Method: {method_id}",
                cfg.get("state", "unknown"),
                "Weak methods (Sms/Voice) should be disabled where possible; Fido2/Authenticator enabled.",
            ])

    return posture_rows


def style_worksheet(ws, headers: list[str], rows: list[list]):
    """Applies consistent header styling, frozen panes, AutoFilter, and column widths."""
    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")

    ws.append(headers)
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font

    ws.freeze_panes = "A2"
    for r in rows:
        ws.append(r)

    ws.auto_filter.ref = ws.dimensions

    for col in ws.columns:
        max_len = max((len(str(cell.value or "")) for cell in col), default=10)
        ws.column_dimensions[col[0].column_letter].width = min(max_len + 4, 60)


def export_to_excel(
    client_label: str,
    timestamp: str,
    output_dir: Path,
    user_rows: list[list],
    role_rows: list[list],
    ca_rows: list[list],
    app_rows: list[list],
    risky_rows: list[list],
    posture_rows: list[list],
) -> Path:
    """Generates a multi-tab Excel security audit workbook and returns the file path."""
    safe_label = "".join(c if c.isalnum() or c in ("-", ".") else "_" for c in client_label)
    output_path = output_dir / f"entra_security_audit_{safe_label}_{timestamp}.xlsx"

    wb = Workbook()

    active_no_mfa = [r for r in user_rows if r[3] == "Enabled" and r[5] == "No"]
    all_no_mfa = [r for r in user_rows if r[5] == "No"]
    admins_no_mfa = [r for r in user_rows if r[5] == "No" and r[8] == "Yes"]
    stale_enabled = [r for r in user_rows if r[3] == "Enabled" and isinstance(r[10], int) and r[10] >= 90]
    global_admins = [r for r in role_rows if r[0] == "Global Administrator"]
    enabled_ca = [r for r in ca_rows if r[1] == "enabled"]
    legacy_block_ca = [r for r in enabled_ca if ("exchangeActiveSync" in r[3] or "other" in r[3]) and "block" in r[4].lower()]
    flagged_apps = [r for r in app_rows if "EXPIRED" in r[5] or "EXPIRING" in r[5] or "EXCESSIVE" in r[5] or r[6] != "None"]

    ws_summary = wb.active
    ws_summary.title = "Executive Summary"
    summary_rows = [
        ["Client", client_label],
        ["Audit Timestamp (UTC)", timestamp],
        ["Total Directory Users", len(user_rows)],
        ["Enabled Users WITHOUT MFA (Actionable)", len(active_no_mfa)],
        ["All Users WITHOUT MFA (Includes Disabled/Guests)", len(all_no_mfa)],
        ["Admins WITHOUT MFA (Critical)", len(admins_no_mfa)],
        ["Enabled Stale Accounts (90+ Days Inactive)", len(stale_enabled)],
        ["Permanent Global Administrators", len(global_admins)],
        ["Enabled Conditional Access Policies", len(enabled_ca)],
        ["Policies Blocking Legacy Authentication", len(legacy_block_ca)],
        ["Flagged App Secrets / High-Priv Apps", len(flagged_apps)],
        ["Active Risky Users (Entra ID Protection)", len(risky_rows)],
    ]
    style_worksheet(ws_summary, ["Security Audit Metric", "Value / Count"], summary_rows)

    user_headers = [
        "Client", "Display Name", "User Principal Name", "Account Status", "User Type",
        "Has MFA", "MFA Capable", "Registered Methods", "Is Admin", "Last Sign-In", "Days Inactive",
    ]
    style_worksheet(wb.create_sheet("Admins No MFA"), user_headers, admins_no_mfa)
    style_worksheet(wb.create_sheet("Enabled Users No MFA"), user_headers, active_no_mfa)
    style_worksheet(wb.create_sheet("All Users"), user_headers, user_rows)

    style_worksheet(
        wb.create_sheet("Privileged Roles"),
        ["Role Name", "Member Type", "Display Name", "UPN / App ID", "Account Status", "Has MFA", "Registered Methods"],
        role_rows,
    )
    style_worksheet(
        wb.create_sheet("Conditional Access"),
        ["Policy Name", "State", "Target Scope", "Client App Types", "Grant Controls", "Last Modified"],
        ca_rows,
    )
    style_worksheet(
        wb.create_sheet("App Credentials & Perms"),
        ["App Name", "App ID", "Credential Type", "Credential Name", "Expires", "Status", "High-Privilege Graph Permissions"],
        app_rows,
    )
    style_worksheet(
        wb.create_sheet("Tenant Posture"),
        ["Setting / Control", "Current Value", "Security Guidance"],
        posture_rows,
    )
    if risky_rows:
        style_worksheet(
            wb.create_sheet("Risky Users"),
            ["Display Name", "UPN", "Risk Level", "Risk State", "Risk Detail", "Account Status", "Has MFA", "Last Updated"],
            risky_rows,
        )

    wb.save(output_path)
    return output_path


def export_to_csv(user_rows: list[list], client_label: str, timestamp: str, output_dir: Path) -> Path:
    """Exports the enriched user & MFA dataset to CSV and returns the file path."""
    safe_label = "".join(c if c.isalnum() or c in ("-", ".") else "_" for c in client_label)
    output_path = output_dir / f"entra_user_mfa_{safe_label}_{timestamp}.csv"

    headers = [
        "Client", "Display Name", "User Principal Name", "Account Status", "User Type",
        "Has MFA", "MFA Capable", "Registered Methods", "Is Admin", "Last Sign-In", "Days Inactive",
    ]

    with open(output_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(user_rows)

    return output_path