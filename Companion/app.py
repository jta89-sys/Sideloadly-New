"""SideBridge Windows GUI. Run with Python or the packaged SideBridge.exe."""
from __future__ import annotations
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import install_ipa, private_directory, resource_path, sign_ipa, usb_devices
from server import Inbox, LocalServer, make_tls


class Window:
    def __init__(self, root, smoke=False):
        self.root = root
        self.root.title("SideBridge — iPad companion")
        self.root.geometry("1040x780")
        self.root.minsize(850, 680)
        self.events = queue.Queue()
        self.busy = False
        self.server = None
        self.devices = []
        self.folder = private_directory(Path(tempfile.gettempdir()) / "SideBridge-smoke" if smoke else
                                        Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SideBridge")
        self.session = tempfile.TemporaryDirectory(dir=self.folder, prefix="session-")
        self.session_path = Path(self.session.name)
        self.inbox = Inbox(self.session_path / "inbox")
        self.p12 = tk.StringVar()
        self.profile = tk.StringVar()
        self.password = tk.StringVar()
        self.bundle = tk.StringVar()
        self.address = tk.StringVar(value=self.local_address())
        self.pairing = tk.StringVar(value="Start the connection to pair your iPad.")
        self.status = tk.StringVar(value="Connect your iPad over USB, unlock it, and trust this PC.")
        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(200, self.tick)

    @staticmethod
    def local_address():
        try:
            addresses = socket.gethostbyname_ex(socket.gethostname())[2]
            return next(a for a in addresses if ipaddress.ip_address(a).is_private and not a.startswith("127."))
        except (OSError, StopIteration):
            return "127.0.0.1"

    def build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=7)
        base = ttk.Frame(self.root, padding=18)
        base.pack(fill="both", expand=True)
        ttk.Label(base, text="SideBridge", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ttk.Label(base, text="Sign your IPAs on Windows · Install on your USB-connected iPad",
                  font=("Segoe UI", 11)).pack(anchor="w", pady=(0, 12))
        tabs = ttk.Notebook(base)
        tabs.pack(fill="both", expand=True)
        signing, connection = ttk.Frame(tabs, padding=14), ttk.Frame(tabs, padding=14)
        tabs.add(signing, text="Sign & install")
        tabs.add(connection, text="Connect iPad")
        for label, variable, filters in [
            ("Certificate (.p12)", self.p12, [("Signing certificate", "*.p12 *.pfx")]),
            ("Provisioning profile", self.profile, [("Provisioning profile", "*.mobileprovision")])]:
            row = ttk.Frame(signing)
            row.pack(fill="x", pady=4)
            ttk.Label(row, text=label, width=23).pack(side="left")
            ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
            ttk.Button(row, text="Browse", command=lambda v=variable, f=filters: self.choose(v, f)).pack(side="left", padx=(8, 0))
        row = ttk.Frame(signing)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="Certificate password", width=23).pack(side="left")
        ttk.Entry(row, textvariable=self.password, show="•", width=28).pack(side="left")
        ttk.Label(row, text="  Kept only for this session").pack(side="left")
        row = ttk.Frame(signing)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="New bundle ID (optional)", width=23).pack(side="left")
        ttk.Entry(row, textvariable=self.bundle).pack(side="left", fill="x", expand=True)
        row = ttk.Frame(signing)
        row.pack(fill="x", pady=8)
        ttk.Label(row, text="USB device", width=23).pack(side="left")
        self.device_choice = ttk.Combobox(row, state="readonly")
        self.device_choice.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Find iPad", command=self.scan).pack(side="left", padx=(8, 0))
        actions = ttk.Frame(signing)
        actions.pack(fill="x", pady=10)
        for title, action in [("Add IPA from PC", self.add_local), ("Sign only", lambda: self.sign(False)),
                              ("Sign & install", lambda: self.sign(True)), ("Remove item", self.remove),
                              ("Signed files", self.open_output)]:
            ttk.Button(actions, text=title, command=action).pack(side="left", padx=(0, 6))
        self.table = ttk.Treeview(signing, columns=("app", "bundle", "status"), show="headings", selectmode="browse", height=9)
        for column, label, width in [("app", "App", 220), ("bundle", "Bundle ID", 300), ("status", "Status", 230)]:
            self.table.heading(column, text=label)
            self.table.column(column, width=width)
        self.table.pack(fill="both", expand=True)
        ttk.Label(signing, text="Single-app IPAs up to 512 MB. Signing files must cover your app and iPad.\n"
                  "This app does not create Apple certificates or provisioning profiles.", wraplength=850).pack(anchor="w", pady=8)
        ttk.Label(connection, text="Pair with the SideBridge iPad app", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        ttk.Label(connection, text="Use the same private Wi-Fi network. USB is still required to install apps.\n"
                  "Allow SideBridge through Windows Firewall on Private networks if prompted.", wraplength=800).pack(anchor="w", pady=8)
        row = ttk.Frame(connection)
        row.pack(fill="x")
        ttk.Label(row, text="PC local IPv4 address").pack(side="left", padx=(0, 8))
        ttk.Entry(row, textvariable=self.address, width=20).pack(side="left")
        ttk.Button(row, text="Start connection", command=self.start_server).pack(side="left", padx=8)
        ttk.Button(row, text="Stop connection", command=self.stop_server).pack(side="left")
        self.qr_label = ttk.Label(connection)
        self.qr_label.pack(pady=10)
        ttk.Entry(connection, textvariable=self.pairing, state="readonly").pack(fill="x")
        ttk.Button(connection, text="Copy pairing code", command=self.copy_pairing).pack(anchor="w", pady=6)
        ttk.Label(connection, text="Scan this QR code inside SideBridge on iPad, or paste the pairing code.\n"
                  "Pairing changes every time you start the connection. Only share it with your own iPad.", wraplength=800).pack(anchor="w")
        ttk.Separator(base).pack(fill="x", pady=10)
        ttk.Label(base, textvariable=self.status, wraplength=960).pack(anchor="w")

    def choose(self, variable, filters):
        value = filedialog.askopenfilename(filetypes=filters)
        if value:
            variable.set(value)

    def run(self, action):
        if self.busy:
            messagebox.showinfo("Please wait", "Wait for the current operation to finish.")
            return
        self.busy = True
        def worker():
            try:
                action()
            except Exception as error:
                self.events.put(("error", str(error)))
            finally:
                self.events.put(("done", None))
        threading.Thread(target=worker, daemon=True).start()

    def scan(self):
        self.status.set("Looking for USB devices. Accept Trust on the iPad if asked…")
        self.run(lambda: self.events.put(("devices", asyncio.run(usb_devices()))))

    def add_local(self):
        if self.busy:
            return
        chosen = filedialog.askopenfilename(filetypes=[("iPad app", "*.ipa")])
        if chosen:
            def add():
                from core import MAX_IPA
                if Path(chosen).stat().st_size > MAX_IPA:
                    raise ValueError("IPA exceeds the 512 MB limit.")
                with tempfile.NamedTemporaryFile(dir=self.inbox.directory, suffix=".upload", delete=False) as f:
                    temporary = Path(f.name)
                try:
                    shutil.copyfile(chosen, temporary)
                    self.inbox.add(temporary)
                    self.events.put(("status", "IPA added. Select it, then choose Sign only or Sign & install."))
                finally:
                    temporary.unlink(missing_ok=True)
            self.run(add)

    def sign(self, install):
        selected = self.table.selection()
        if self.busy or not selected:
            return
        job_id = selected[0]
        if not self.p12.get() or not self.profile.get():
            messagebox.showinfo("Signing files needed", "Choose your P12 signing certificate and provisioning profile first.")
            return
        index = self.device_choice.current()
        if install and index < 0:
            messagebox.showinfo("Choose an iPad", "Connect and trust your iPad, click Find iPad, and select it.")
            return
        udid = self.devices[index]["id"] if install else None
        p12, profile, password, bundle = Path(self.p12.get()), Path(self.profile.get()), self.password.get(), self.bundle.get()
        destination = self.folder / "Signed" / (job_id + "-signed.ipa")
        self.status.set("Validating certificate and profile…")
        def operation():
            try:
                self.inbox.update(job_id, status="Signing", detail="Windows is signing this app.", progress=0)
                metadata = sign_ipa(self.inbox.directory / (job_id + ".ipa"), destination,
                                    p12, password, profile, bundle, udid,
                                    resource_path("vendor/zsign.exe"), self.session_path)
                if install:
                    self.inbox.update(job_id, status="Installing", detail="Keep the iPad connected over USB.")
                    asyncio.run(install_ipa(destination, udid, lambda value:
                                           self.inbox.update(job_id, progress=value)))
                    self.inbox.update(job_id, status="Installed", detail="The iPad reported installation complete.", progress=100)
                    self.events.put(("status", "Installed. Enable Developer Mode / trust the developer profile on iPad if prompted."))
                else:
                    self.inbox.update(job_id, status="Signed", detail="Saved on the PC. Not installed yet.", progress=100)
                    self.events.put(("status", "Signed IPA saved. Click Signed files to find it."))
                self.inbox.update(job_id, expires=metadata["expires"])
            except Exception as error:
                self.inbox.update(job_id, status="Failed", detail="See the Windows companion for the error.", progress=0)
                raise error
        self.run(operation)

    def remove(self):
        if self.busy:
            return
        for job_id in self.table.selection():
            with self.inbox.lock:
                self.inbox.jobs.pop(job_id, None)
            (self.inbox.directory / (job_id + ".ipa")).unlink(missing_ok=True)

    def open_output(self):
        directory = self.folder / "Signed"
        directory.mkdir(exist_ok=True)
        os.startfile(directory)

    def start_server(self):
        if self.server:
            self.status.set("Connection already active. Stop it before pairing again.")
            return
        try:
            address = self.address.get().strip()
            ip = ipaddress.IPv4Address(address)
            if not ip.is_private or ip.is_loopback or ip.is_unspecified:
                raise ValueError("Enter your PC's private local IPv4 address, such as 192.168.1.20.")
            tls, fingerprint = make_tls(self.session_path)
            self.server = LocalServer((address, 0), self.inbox, tls)
            port = self.server.server_address[1]
            pairing = f"sidebridge://{address}:{port}?fp={fingerprint}&token={self.server.token}"
            self.pairing.set(pairing)
            import qrcode
            from PIL import ImageTk
            image = qrcode.make(pairing).resize((290, 290))
            self.qr = ImageTk.PhotoImage(image)
            self.qr_label.configure(image=self.qr)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            self.status.set("Connection active. Scan the QR code with SideBridge on iPad.")
        except Exception as error:
            if self.server:
                self.server.server_close()
                self.server = None
            messagebox.showerror("Connection failed", str(error))

    def stop_server(self):
        if self.server:
            self.server.token = "revoked"
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        self.pairing.set("Connection stopped. Start again to get a new pairing code.")
        self.qr_label.configure(image="")

    def copy_pairing(self):
        if self.server:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.pairing.get())

    def tick(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "done":
                    self.busy = False
                elif kind == "error":
                    self.status.set("Operation failed. See the error details.")
                    messagebox.showerror("SideBridge", value)
                elif kind == "status":
                    self.status.set(value)
                elif kind == "devices":
                    self.devices = value
                    self.device_choice["values"] = [d["name"] + " · " + d["id"] for d in value]
                    if value:
                        self.device_choice.current(0)
                    self.status.set(f"Found {len(value)} USB device(s)." if value else "No USB devices. Install Apple Devices, connect the cable, unlock, and trust this PC.")
        except queue.Empty:
            pass
        jobs = self.inbox.snapshot()
        ids = {j["id"] for j in jobs}
        for old in self.table.get_children():
            if old not in ids:
                self.table.delete(old)
        for job in jobs:
            values = (job["name"], job["bundle"], job["status"] + (f" {job['progress']}%" if job["status"] == "Installing" else ""))
            if self.table.exists(job["id"]):
                self.table.item(job["id"], values=values)
            else:
                self.table.insert("", "end", iid=job["id"], values=values)
        self.root.after(300, self.tick)

    def close(self):
        if self.busy:
            messagebox.showinfo("Operation in progress", "Wait for signing or installation to finish before closing.")
            return
        if self.inbox.upload_lock.locked():
            messagebox.showinfo("Upload in progress", "Wait for the upload to finish before closing.")
            return
        self.stop_server()
        self.password.set("")
        self.session.cleanup()
        self.root.destroy()


def main():
    root = tk.Tk()
    smoke = "--self-test" in sys.argv
    if smoke:
        root.withdraw()
    try:
        app = Window(root, smoke=smoke)
        if smoke:
            root.update()
            app.close()
            return
        root.mainloop()
    except Exception as error:
        if smoke:
            raise
        messagebox.showerror("SideBridge could not start", str(error))


if __name__ == "__main__":
    main()
