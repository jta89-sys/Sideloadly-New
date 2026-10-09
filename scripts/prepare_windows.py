"""Fetch a pinned, checksum-verified signer and retain dependency license notices."""
import hashlib
from importlib import metadata
import io
from pathlib import Path
import shutil
import urllib.request
import zipfile

root = Path(__file__).resolve().parents[1]
vendor = root / "Companion" / "vendor"
vendor.mkdir(parents=True, exist_ok=True)
url = "https://github.com/zhlynn/zsign/releases/download/v1.1.2/zsign-windows-x64.zip"
expected = "96b5bf7029a52c67cdb78b68b3666d8ff1e31e5c435535964be2a482afc09e5c"
data = urllib.request.urlopen(url, timeout=60).read()
assert hashlib.sha256(data).hexdigest() == expected, "zsign download checksum mismatch"
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    for entry in archive.infolist():
        if entry.is_dir():
            continue
        # Flatten the verified release to keep companion lookup independent of ZIP layout.
        if entry.filename.lower().endswith((".exe", ".dll", ".txt")) or "license" in entry.filename.lower():
            (vendor / Path(entry.filename).name).write_bytes(archive.read(entry))
assert (vendor / "zsign.exe").is_file(), "Missing zsign.exe"
licenses = root / "Companion" / "licenses"
licenses.mkdir(exist_ok=True)
names = []
for distribution in metadata.distributions():
    name = distribution.metadata.get("Name", "unknown")
    names.append(name + "==" + distribution.version)
    for file in distribution.files or []:
        if "license" in str(file).lower() or Path(str(file)).name.lower() in ("copying", "notice", "authors"):
            source = Path(distribution.locate_file(file))
            if source.is_file():
                target = licenses / name / str(file).replace("/", "_").replace("\\", "_")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
(licenses / "DEPENDENCIES.txt").write_text("\n".join(sorted(set(names))), encoding="utf-8")
print("Verified and prepared zsign 1.1.2 and dependency notices.")
