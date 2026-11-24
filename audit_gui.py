from datetime import datetime, timezone
import os
from pathlib import Path
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import msal

from audit_client_security import (
    MICROSOFT_GRAPH_CLI_CLIENT_ID,
    SCOPES,
    audit_app_registrations,
    audit_conditional_access,
    audit_privileged_roles,
    audit_risky_users,
    audit_tenant_posture,
    audit_users_and_mfa,
    export_to_csv,
    export_to_excel,
)


class AuditApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Entra ID Security Posture & MFA Audit")
        self.geometry("640x490")
        self.resizable(False, False)

        self.client_name = tk.StringVar()
        self.tenant_id = tk.StringVar(value="organizations")
        self.auth_mode = tk.StringVar(value="device")
        self.out_format = tk.StringVar(value="both")
        self.out_dir = tk.StringVar(value=str(Path.home() / "Desktop" / "EntraAudits"))

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 12, "pady": 6}
        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(frame, text="Client Name (for filename):").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(frame, textvariable=self.client_name, width=44).grid(row=0, column=1, sticky="ew", **pad)

        ttk.Label(frame, text="Tenant Domain or ID:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(frame, textvariable=self.tenant_id, width=44).grid(row=1, column=1, sticky="ew", **pad)

        ttk.Label(frame, text="Login Method:").grid(row=2, column=0, sticky="w", **pad)
        auth_frame = ttk.Frame(frame)
        auth_frame.grid(row=2, column=1, sticky="w", **pad)
        ttk.Radiobutton(
            auth_frame,
            text="Device Code (Best for Separate Browser Profiles)",
            variable=self.auth_mode,
            value="device",
        ).pack(anchor="w")
        ttk.Radiobutton(
            auth_frame,
            text="Default Browser Popup (Account Picker)",
            variable=self.auth_mode,
            value="browser",
        ).pack(anchor="w")

        ttk.Label(frame, text="Export Format:").grid(row=3, column=0, sticky="w", **pad)
        fmt_frame = ttk.Frame(frame)
        fmt_frame.grid(row=3, column=1, sticky="w", **pad)
        ttk.Radiobutton(fmt_frame, text="Both (.xlsx + .csv)", variable=self.out_format, value="both").pack(side="left", padx=(0, 10))
        ttk.Radiobutton(fmt_frame, text="Excel Only", variable=self.out_format, value="xlsx").pack(side="left", padx=(0, 10))
        ttk.Radiobutton(fmt_frame, text="CSV Only", variable=self.out_format, value="csv").pack(side="left", padx=(0, 10))

        ttk.Label(frame, text="Save Reports To:").grid(row=4, column=0, sticky="w", **pad)
        dir_frame = ttk.Frame(frame)
        dir_frame.grid(row=4, column=1, sticky="ew", **pad)
        ttk.Entry(dir_frame, textvariable=self.out_dir, width=34).pack(side="left", fill="x", expand=True)
        ttk.Button(dir_frame, text="Browse...", command=self._browse_dir).pack(side="right", padx=(6, 0))

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=12)
        self.run_btn = ttk.Button(btn_frame, text="Start Security Audit", command=self._start_audit_thread)
        self.run_btn.pack(side="left", padx=6, ipadx=16, ipady=4)
        ttk.Button(btn_frame, text="Open Output Folder", command=self._open_out_dir).pack(side="left", padx=6, ipadx=10, ipady=4)

        self.log_box = tk.Text(frame, height=12, state="disabled", wrap="word", font=("Consolas", 9))
        self.log_box.grid(row=6, column=0, columnspan=2, sticky="nsew", padx=12, pady=(4, 0))

    def _browse_dir(self):
        chosen = filedialog.askdirectory(initialdir=self.out_dir.get())
        if chosen:
            self.out_dir.set(chosen)

    def _open_out_dir(self):
        path = Path(self.out_dir.get())
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(str(path))

    def log(self, msg: str):
        def _append():
            self.log_box.configure(state="normal")
            self.log_box.insert("end", msg + "\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
        self.after(0, _append)

    def _copy_clipboard(self, text: str):
        def _copy():
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
        self.after(0, _copy)

    def _start_audit_thread(self):
        self.run_btn.configure(state="disabled")
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        threading.Thread(target=self._run_audit, daemon=True).start()

    def _run_audit(self):
        try:
            tenant = self.tenant_id.get().strip() or "organizations"
            authority = f"https://login.microsoftonline.com/{tenant}"
            app = msal.PublicClientApplication(client_id=MICROSOFT_GRAPH_CLI_CLIENT_ID, authority=authority)

            if self.auth_mode.get() == "device":
                flow = app.initiate_device_flow(scopes=SCOPES)
                if "user_code" not in flow:
                    raise RuntimeError(f"Device flow failed: {flow}")
                self._copy_clipboard(flow["user_code"])
                self.log(f"[ACTION REQUIRED] Code copied to clipboard: {flow['user_code']}")
                self.log("1. Open https://microsoft.com/devicelogin in your client browser profile.")
                self.log("2. Paste the code, sign in, and leave 'Consent on behalf of your organization' UNCHECKED.\n")
                result = app.acquire_token_by_device_flow(flow)
            else:
                self.log("Opening default browser for Microsoft sign-in...")
                result = app.acquire_token_interactive(scopes=SCOPES, prompt="select_account")

            if "access_token" not in result:
                raise RuntimeError(f"{result.get('error')}: {result.get('error_description')}")

            token = result["access_token"]
            claims = result.get("id_token_claims", {})
            upn = claims.get("preferred_username", "unknown")
            self.log(f"[OK] Authenticated as: {upn}")

            label = self.client_name.get().strip() or (tenant if tenant != "organizations" else upn.split("@")[-1])
            out_path = Path(self.out_dir.get())
            out_path.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")

            self.log(" -> Auditing users & MFA registration...")
            user_rows = audit_users_and_mfa(token, label)
            self.log(" -> Auditing privileged directory roles...")
            role_rows = audit_privileged_roles(token, user_rows)
            self.log(" -> Auditing Conditional Access policies...")
            ca_rows = audit_conditional_access(token)
            self.log(" -> Auditing App Registrations & secrets...")
            app_rows = audit_app_registrations(token)
            self.log(" -> Auditing tenant-wide posture settings...")
            posture_rows = audit_tenant_posture(token)
            self.log(" -> Checking Entra ID Protection risky users...")
            risky_rows = audit_risky_users(token, user_rows)

            fmt = self.out_format.get()
            if fmt in ("both", "xlsx"):
                xlsx_file = export_to_excel(label, timestamp, out_path, user_rows, role_rows, ca_rows, app_rows, risky_rows, posture_rows)
                self.log(f"[SAVED] {xlsx_file.name}")
            if fmt in ("both", "csv"):
                csv_file = export_to_csv(user_rows, label, timestamp, out_path)
                self.log(f"[SAVED] {csv_file.name}")

            self.log("\n[COMPLETE] Security audit finished.")
            self.after(0, lambda: messagebox.showinfo("Audit Complete", f"Reports saved to:\n{out_path}"))
        except Exception as exc:
            self.log(f"\n[ERROR] {exc}")
            self.after(0, lambda: messagebox.showerror("Audit Failed", str(exc)))
        finally:
            self.after(0, lambda: self.run_btn.configure(state="normal"))


if __name__ == "__main__":
    AuditApp().mainloop()
