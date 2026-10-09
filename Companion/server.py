"""Session-scoped, authenticated HTTPS inbox. No signing credentials cross the network."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import ssl
import threading
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from core import MAX_IPA, inspect_ipa


class Inbox:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.upload_lock = threading.Lock()
        self.jobs = {}

    def add(self, path: Path) -> dict:
        metadata = inspect_ipa(path)
        with self.lock:
            if len(self.jobs) >= 20:
                raise ValueError("The inbox is full. Remove completed items on Windows first.")
            job_id = uuid.uuid4().hex
            target = self.directory / (job_id + ".ipa")
            path.replace(target)
            job = {"id": job_id, "name": metadata["name"], "bundle": metadata["bundle"],
                   "bytes": metadata["bytes"], "status": "Waiting for Windows",
                   "detail": "Select this item on the PC, then sign or install.", "progress": 0}
            self.jobs[job_id] = job
            return dict(job)

    def update(self, job_id: str, **fields):
        with self.lock:
            self.jobs[job_id].update(fields)

    def snapshot(self):
        with self.lock:
            return [dict(job) for job in self.jobs.values()]


def make_tls(directory: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SideBridge local companion")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    certificate_path, key_path = directory / "tls.crt", directory / "tls.key"
    certificate_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate_path, key_path)
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return context, fingerprint


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, inbox: Inbox, tls: ssl.SSLContext):
        self.inbox = inbox
        self.token = secrets.token_urlsafe(32)
        self.tls = tls
        self.connections = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        try:
            connection = self.tls.wrap_socket(connection, server_side=True)
            connection.settimeout(60)
            return connection, address
        except Exception:
            connection.close()
            raise

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


class Handler(BaseHTTPRequestHandler):
    server: LocalServer

    def log_message(self, *args):
        pass  # No access logs containing pairing credentials or filenames.

    def reply(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        token = self.headers.get("Authorization", "")
        if not secrets.compare_digest(token, "Bearer " + self.server.token):
            self.reply(401, {"error": "Pair again using the code on your PC."})
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        if self.path == "/v1/status":
            self.reply(200, {"name": "SideBridge", "version": 1, "jobs": self.server.inbox.snapshot()})
        else:
            self.reply(404, {"error": "Unknown endpoint."})

    def do_POST(self):
        if not self.authorized():
            return
        if self.path != "/v1/upload":
            self.reply(404, {"error": "Unknown endpoint."})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if not 0 < size <= MAX_IPA or self.headers.get("Transfer-Encoding"):
            self.reply(413, {"error": "Choose an IPA no larger than 512 MB."})
            return
        inbox = self.server.inbox
        if not inbox.upload_lock.acquire(blocking=False):
            self.reply(409, {"error": "Another file is uploading. Try again when it finishes."})
            return
        temporary = inbox.directory / (uuid.uuid4().hex + ".upload")
        try:
            with inbox.lock:
                if len(inbox.jobs) >= 20:
                    raise ValueError("Inbox full. Remove completed items on Windows.")
            with temporary.open("xb") as output:
                remaining = size
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Upload interrupted. Send the file again.")
                    output.write(chunk)
                    remaining -= len(chunk)
            job = inbox.add(temporary)
            status, response = 201, job
        except (ValueError, OSError) as error:
            status, response = 400, {"error": str(error)}
        except Exception:
            status, response = 400, {"error": "This file is not a supported IPA."}
        finally:
            temporary.unlink(missing_ok=True)
            inbox.upload_lock.release()
        self.reply(status, response)
