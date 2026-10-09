"""CI-only signer test. Generated credentials are NOT trusted by Apple."""
import argparse
from pathlib import Path
import tempfile
from core import inspect_ipa, sign_ipa
from test_core import identity

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
parser.add_argument("zsign", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory() as scratch:
    root = Path(scratch)
    metadata = inspect_ipa(args.source)
    p12, provision, _ = identity(root, metadata["bundle"])
    result = sign_ipa(args.source, args.output, p12, "test-password", provision,
                      "", "test-device", args.zsign.resolve(), root)
    assert result["bundle"] == metadata["bundle"]
    assert not list(root.glob("sign-*")), "Signing keys must be cleaned up"
print("PASS: zsign signs a real compiled IPA and cleans up its temporary signing keys.")
