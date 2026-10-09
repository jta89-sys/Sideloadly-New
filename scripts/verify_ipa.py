"""Check the device package structure and sharing settings after compilation."""
import plistlib
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    prefix = "Payload/FileBridge.app/"
    info = plistlib.loads(archive.read(prefix + "Info.plist"))
    assert info["UIFileSharingEnabled"] is True
    assert info["LSSupportsOpeningDocumentsInPlace"] is True
    assert info["UIDeviceFamily"] == [2]
    assert info["CFBundleSupportedPlatforms"] == ["iPhoneOS"]
    binary = archive.read(prefix + info["CFBundleExecutable"])
    assert len(binary) > 4096, "Missing app executable"
    assert binary[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbf\xba\xfe\xca"), "Expected Mach-O binary"
    assert archive.testzip() is None
print("PASS: iPad device executable, USB sharing, Files access, IPA integrity")
