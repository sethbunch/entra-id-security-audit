# EntraSecurityAudit

Standalone Windows tool that audits Microsoft Entra ID (Azure AD) security posture across client tenants — built for multi-client managed IT services work, where identity audits were manual and repetitive.

## What it audits

- **MFA registration gaps** — enabled users and admins without MFA, with registered methods per user
- **Privileged role membership** — every directory role, cross-referenced with each member's MFA status
- **Conditional Access policy inventory** — state, target scope, client app types, grant controls
- **App registration credentials** — client secrets/certificates expired, expiring (≤30d), or excessively long-lived (>2yr), plus high-privilege Graph API application permissions flagged
- **Entra ID Protection risky users** — at-risk and confirmed-compromised users, with account status
- **Tenant posture** — security defaults, guest invite restrictions, app registration by non-admins, authentication method states (weak methods like SMS/voice flagged)

## Output

A styled multi-tab Excel workbook (Executive Summary + detail tabs with frozen headers, autofilter, sized columns) and a CSV of the full user/MFA dataset — one set per client, timestamped, ready for a client review meeting.

## Running

```bash
pip install -r requirements.txt
python audit_gui.py
```

Requires an account with read permissions in the target tenant. Authenticate via **device code** (recommended when auditing client tenants from a separate browser profile) or interactive browser prompt. Delegated permissions only — no app registration, no stored credentials.

## Packaging

`EntraSecurityAudit.spec` is a PyInstaller spec that builds a single windowed `EntraSecurityAudit.exe` — no Python required on the operator's machine:

```bash
pyinstaller EntraSecurityAudit.spec
```

## Known limitations

- Role members granted via groups are listed as groups; nested members are not expanded (TODO)
- Some Graph scopes require tenant admin consent; without it those tabs return empty rather than error
- `Open Output Folder` uses `os.startfile` (Windows-only)
