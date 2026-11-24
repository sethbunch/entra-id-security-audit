"""Generate demo audit reports with zero real data.

For screenshots, demos, training, and regression-testing the report path.
No network calls, no authentication. Every identity uses RFC 2606 reserved
domains (.example can never resolve and is never issued), fictional company
names, and all-zero GUIDs — nothing here maps to a real tenant.

Usage:
    python demo_report.py            -> writes demo_output/ in the current dir

The Excel/CSV output is produced by the REAL export functions in
audit_client_security, so what you screenshot is exactly what a live
client audit produces.
"""
from datetime import datetime, timezone
from pathlib import Path

from audit_client_security import export_to_excel, export_to_csv

NOW = datetime.now(timezone.utc)

CLIENT_DOMAINS = {
    "Fourth Coffee": "fourthcoffee.example",
    "Tailspin Toys": "tailspintoys.example",
}


def build_demo_datasets(client: str):
    """Return (users, roles, ca, apps, risky, posture) with fully synthetic rows."""

    domain = CLIENT_DOMAINS.get(client, "demo.example")
    u = []
    def user(name, first, status="Enabled", mtype="Member", mfa="Yes", cap="Yes",
             methods="Authenticator, WindowsHello", admin="No", last="2026-11-20", days=4):
        u.append([client, name, f"{first}@{domain}", status, mtype,
                  mfa, cap, methods, admin, last, days])

    def find(display):
        for row in u:
            if row[1] == display:
                return row
        return None

    # 32 healthy enabled members with MFA
    for i, nm in enumerate([
        ("Alex Rivera", "alex.rivera"), ("Jordan Lee", "jordan.lee"), ("Sam Ortiz", "sam.ortiz"),
        ("Morgan Chen", "morgan.chen"), ("Casey Kim", "casey.kim"), ("Riley Patel", "riley.patel"),
        ("Jamie Fox", "jamie.fox"), ("Drew Bailey", "drew.bailey"), ("Taylor Reed", "taylor.reed"),
        ("Skyler Nash", "skyler.nash"), ("Quinn Hayes", "quinn.hayes"), ("Avery Brooks", "avery.brooks"),
        ("Rowan Vargas", "rowan.vargas"), ("Emery Duncan", "emery.duncan"), ("Blake Sutton", "blake.sutton"),
        ("Reese Malone", "reese.malone"), ("Finley Grant", "finley.grant"), ("Sage Wolfe", "sage.wolfe"),
        ("Marlow Ely", "marlow.ely"), ("Indie Hart", "indie.hart"), ("Kai Mercer", "kai.mercer"),
        ("Nova Quinn", "nova.quinn"), ("Ezra Voss", "ezra.voss"), ("Lux Barnes", "lux.barnes"),
        ("Ari Vance", "ari.vance"), ("Zephyr Kane", "zephyr.kane"), ("Onyx Pratt", "onyx.pratt"),
        ("Sol Reyes", "sol.reyes"), ("Jules Mayer", "jules.mayer"), ("Vale Roach", "vale.roach"),
        ("Arden Frost", "arden.frost"), ("Wren Hale", "wren.hale"),
    ]):
        user(nm[0], nm[1], methods="Authenticator, WindowsHello", last="2026-11-18", days=6)

    # FIDO2 + phone-free crowd
    user("Devon Marsh", "devon.marsh", methods="FIDO2", last="2026-11-21", days=3)
    user("Harper Ellis", "harper.ellis", methods="WindowsHello", last="2026-11-22", days=2)

    # Enabled members WITHOUT MFA (the actionable finding)
    user("Robin Steele", "robin.steele", mfa="No", cap="Yes", methods="", last="2026-11-15", days=9)
    user("Ash Dover", "ash.dover", mfa="No", cap="Yes", methods="", last="2026-10-30", days=25)
    user("Bryn Locke", "bryn.locke", mfa="No", cap="No", methods="", last="2026-09-12", days=73)
    user("Colt Weaver", "colt.weaver", mfa="No", cap="Yes", methods="", last="2026-08-04", days=112)  # stale too
    user("Wells Crane", "wells.crane", mfa="No", cap="Yes", methods="", last="2026-04-19", days=219)  # stale
    user("Jean Irons", "jean.irons", mfa="No", cap="Yes", methods="", last="Never", days="Never")

    # Weak method only (SMS) — registered, but weak
    user("Marla Finch", "marla.finch", mfa="Yes", cap="Yes", methods="SMS", last="2026-11-05", days=19)

    # Admins — one with MFA, one without (critical finding)
    user("Dana Cole", "dana.cole", mfa="Yes", cap="Yes", methods="Authenticator", admin="Yes", last="2026-11-23", days=1)
    user("Trent York", "trent.york", mfa="No", cap="Yes", methods="", admin="Yes", last="2026-11-10", days=14)

    # Guests
    user("Vendor One", "vendor1@partner.example", mtype="Guest", mfa="No", cap="No", methods="", last="2026-10-02", days=53)
    user("Vendor Two", "vendor2@partner.example", mtype="Guest", mfa="Yes", cap="Yes", methods="Authenticator", last="2026-11-19", days=5)
    user("Contractor Three", "contractor3@partner.example", mtype="Guest", mfa="No", cap="No", methods="", status="Disabled", last="2026-07-28", days=119)

    # Disabled members
    user("Gale Sumner", "gale.sumner", status="Disabled", mfa="No", cap="Yes", methods="", last="2026-06-15", days=162)
    user("Pace Dune", "pace.dune", status="Disabled", mfa="Yes", cap="Yes", methods="Authenticator", last="2026-09-01", days=84)

    roles = [
        ["Global Administrator", "User", "Dana Cole", find("Dana Cole")[2], find("Dana Cole")[3], find("Dana Cole")[5], find("Dana Cole")[7]],
        ["Global Administrator", "User", "Trent York", find("Trent York")[2], find("Trent York")[3], find("Trent York")[5], find("Trent York")[7]],
        ["Global Administrator", "Group", "SG-IT-Admins", "N/A", "N/A", "N/A", "N/A"],
        ["Security Administrator", "User", "Dana Cole", find("Dana Cole")[2], find("Dana Cole")[3], find("Dana Cole")[5], find("Dana Cole")[7]],
        ["Security Administrator", "User", "Robin Steele", find("Robin Steele")[2], find("Robin Steele")[3], find("Robin Steele")[5], find("Robin Steele")[7]],
        ["Exchange Administrator", "User", "Ash Dover", find("Ash Dover")[2], find("Ash Dover")[3], find("Ash Dover")[5], find("Ash Dover")[7]],
        ["Helpdesk Administrator", "User", "Bryn Locke", find("Bryn Locke")[2], find("Bryn Locke")[3], find("Bryn Locke")[5], find("Bryn Locke")[7]],
        ["Helpdesk Administrator", "ServicePrincipal", "AutoTicket-Bot", "00000000-0000-0000-0000-000000000002", "N/A", "N/A", "N/A"],
    ]

    ca = [
        ["Require MFA - All Users", "enabled", "Users: [All]", "all", "mfa", "2026-09-15"],
        ["Block Legacy Authentication", "enabled", "Users: [All] | Roles: []", "exchangeActiveSync, other", "block", "2026-09-15"],
        ["Require Compliant Device - corp", "enabled", "Groups: [grp-corp-devices]", "all", "compliantDevice, mfa", "2026-08-02"],
        ["Sign-in Risk - Phishing MFA Required", "enabled", "Users: [All]", "all", "authenticationStrength: Phishing-resistant MFA", "2026-10-11"],
        ["Guest Access Report-Only", "enabledForReportingButNotEnforced", "Guests", "all", "mfa", "2026-10-20"],
        ["Legacy Pilot (retired)", "disabled", "Users: [grp-pilot]", "all", "mfa", "2026-03-04"],
    ]

    apps = [
        ["HR Portal App", "00000000-0000-0000-0000-0000000000a1", "Client Secret", "s-legacy", "2025-02-11", "EXPIRED (-650d)", "None"],
        ["Payroll Sync", "00000000-0000-0000-0000-0000000000a2", "Client Secret", "s-soon", "2026-12-08", "EXPIRING SOON (<=30d)", "None"],
        ["Reporting Bot", "00000000-0000-0000-0000-0000000000a3", "Client Secret", "s-long", "2029-01-20", "EXCESSIVE LIFETIME (>2yr)", "None"],
        ["Legacy Migration Tool", "00000000-0000-0000-0000-0000000000a4", "Certificate", "c-old", "2024-11-30", "EXPIRED (-720d)", "Application.ReadWrite.All"],
        ["Backup Exporter", "00000000-0000-0000-0000-0000000000a5", "Certificate", "c-valid", "2028-06-01", "Valid", "RoleManagement.ReadWrite.Directory"],
        ["Intranet SSO", "00000000-0000-0000-0000-0000000000a6", "Client Secret", "s-fresh", "2027-05-12", "Valid", "None"],
        ["Print Service", "00000000-0000-0000-0000-0000000000a7", "No Credentials", "None", "None", "Valid", "Mail.Read"],
        ["Doc Automation", "00000000-0000-0000-0000-0000000000a8", "No Credentials", "None", "None", "Valid", "Directory.ReadWrite.All"],
    ]

    risky = [
        ["Robin Steele", "robin.steele@fourthcoffee.example", "high", "atRisk", "userConfirmedSafeCompromised", "Enabled", "No", "2026-11-21"],
        ["Colt Weaver", "colt.weaver@fourthcoffee.example", "medium", "atRisk", "unfamiliarSignInProperties", "Enabled", "No", "2026-11-17"],
        ["Vendor Two", "vendor2@partner.example", "low", "confirmedCompromised", "mcasImpossibleTravel", "Enabled", "Yes", "2026-11-09"],
    ]

    posture = [
        ["Security Defaults", "Disabled", "Conditional Access is in use; defaults intentionally off"],
        ["Guest Invite Setting", "adminsAndGuestInviters", "Only admins and designated inviters can invite guests"],
        ["Users Can Register Apps", "Yes", "Default user role may consent to apps - consider restricting"],
        ["Auth Method: Sms", "enabled", "SMS remains enabled tenant-wide - weak against SIM swap"],
        ["Auth Method: Voice", "enabled", "Voice call enabled - weaker MFA factor"],
        ["Auth Method: Email", "disabled", "Email OTP disabled"],
        ["Auth Method: MicrosoftAuthenticator", "enabled", "Passwordless capable"],
        ["Auth Method: Fido2", "enabled", "Hardware keys allowed"],
    ]

    return u, roles, ca, apps, risky, posture


def main():
    out_dir = Path("demo_output")
    out_dir.mkdir(exist_ok=True)
    ts = NOW.strftime("%Y%m%d_%H%M%S")

    written = []
    for client in ("Fourth Coffee", "Tailspin Toys"):
        datasets = build_demo_datasets(client)
        if client == "Tailspin Toys":
            # second client: smaller tenant — healthy dozen, the findings, admins, guests
            u, roles, ca, apps, risky, posture = datasets
            u = u[0:12] + u[34:43]
            roles, apps, risky = roles[:4], apps[:4], risky[:1]
        else:
            u, roles, ca, apps, risky, posture = datasets
        xlsx = export_to_excel(client, ts, out_dir, u, roles, ca, apps, risky, posture)
        csvf = export_to_csv(u, client, ts, out_dir)
        written += [xlsx, csvf]

    print("Demo reports written (fully synthetic data):")
    for p in written:
        print(f"  {p.resolve()}")


if __name__ == "__main__":
    main()
