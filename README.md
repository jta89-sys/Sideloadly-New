# SideBridge — iPad app + independent Windows companion

SideBridge sends IPAs from an iPad to a Windows PC, signs them with your P12 certificate and provisioning profile, and installs them on a USB-connected iPad. It uses the open-source **zsign** signing engine and **pymobiledevice3** device services. Sideloadly is not required or bundled. This is an initial certificate-based tool, not a feature-for-feature Sideloadly replacement.

## Downloads

Open **Actions → Build SideBridge for iPad and Windows → the latest successful run → Artifacts**:

- **SideBridge-iPad-unsigned** contains `SideBridge-unsigned.ipa`. It must be signed before installation.
- **SideBridge-Windows-x64** contains `SideBridge.exe` and its `_internal` folder. Extract the **entire ZIP** into one folder and launch `SideBridge.exe`. Keep `_internal` beside it. Windows 11 x64 is the target; Python is bundled.
- The `signing-test-only-NOT-INSTALLABLE` artifact uses a generated test certificate. It is only for CI validation and will not install on an iPad.

Build artifacts expire after 14 days; run the workflow again for new downloads. The Windows executable is not Authenticode-signed.

## What you need before installing

1. An Apple-issued signing certificate **with its private key**, exported as `.p12` or `.pfx`, and its password.
2. A valid development or ad hoc `.mobileprovision` that includes that certificate, covers your app's bundle ID, and registers your iPad's UDID. An App Store distribution profile cannot be installed over USB.
3. Apple Devices / Apple Mobile Device USB drivers installed on Windows, a data-capable USB cable, and an unlocked iPad that trusts the PC.
4. iPadOS 17 or later for the SideBridge iPad app. Enable Developer Mode and trust the developer profile when iPadOS requests it.

**The app does not create these Apple signing credentials, sign in to an Apple account, or bypass provisioning.** If you do not have a certificate and matching profile, both builds are available but you cannot complete installation yet. Keep your signing files on your PC; do not upload them to GitHub or share them in chat.

## Install SideBridge on your iPad first

1. Download and extract both build artifacts on Windows.
2. Run `SideBridge.exe`, choose your P12 certificate and provisioning profile, and enter the certificate password.
3. Connect the iPad via USB, unlock it, accept Trust, and click **Find iPad**.
4. Click **Add IPA from PC** and select `SideBridge-unsigned.ipa`.
5. The default bundle ID is `com.jta89.sidebridge`. If your profile is for another app identifier, enter that identifier under **New bundle ID**.
6. Select the app in the list and click **Sign & install**. Windows validates the selected identity/profile and device, signs a copy, and waits for the device's installation result.

Choose **Sign only** to save a signed IPA without installing it. **Signed files** opens `%LOCALAPPDATA%\SideBridge\Signed`. Originals remain unchanged.

## Pair and send apps from iPad

1. Keep the PC and iPad on the same private Wi-Fi network. USB remains necessary for installation.
2. In Windows, open **Connect iPad**, check the PC's local IPv4 address, and click **Start connection**. If Windows Firewall asks, allow Private networks.
3. In the iPad app, choose **Scan QR code** and scan the Windows QR code. Alternatively copy/paste the pairing code. Allow local-network access when asked.
4. Choose an IPA on the iPad. Keep the app open until the upload completes.
5. On Windows, select the received item and click **Sign & install**. Progress and the result appear on the iPad.

The pairing token and exact TLS certificate fingerprint are embedded in the QR code. Both change when the companion restarts its connection. The iPad accepts only the paired certificate and does not follow network redirects. No Apple credentials are sent to the iPad. Sending an IPA only queues it; installation requires clicking the Windows button.

## Supported in this version

- Local IPA selection on Windows; encrypted authenticated uploads from iPad.
- P12 signing, optional bundle ID change, profile expiry and certificate matching checks, device eligibility checks, USB installation, status reporting, and signed IPA export.
- Apps with a thin 64-bit executable and no extensions or Watch app. Maximum 512 MB per IPA; 20 queued apps per session.
- A file inbox tab retains Wi-Fi/USB document-sharing features through Files and Apple Devices.

## Limits

- No free-Apple-account provisioning, automatic certificate creation, background renewal, Wi-Fi installation, dylib injection, or extension-specific profiles.
- Encrypted App Store downloads and unsupported ZIP entries are rejected. The tool does not remove encryption or silently remove app extensions.
- Arbitrary third-party apps may not work after signing. Entitlements, embedded frameworks, minimum iPadOS, and the selected profile still must be compatible; iPadOS makes the final installation decision.
- Profile contents are parsed for compatibility; the tool does not independently verify Apple's CMS trust chain or certificate revocation. iPadOS enforces signature and provisioning trust when installing.
- The local connection is foreground-only. Pair again after restarting the companion. Inbox jobs are session-only and deleted on normal exit; signed exports remain on the PC.
- P12 passwords are held only for the current session. A decrypted signing key exists temporarily in a per-user protected folder while zsign runs and is removed afterward. An abrupt process or power failure may leave temporary files in the app's private data folder.
- Builds and automated tests can be verified without Apple credentials. End-to-end installation on a real iPad requires your signing files and hardware and is not claimed by CI tests.

## Build and tests

GitHub Actions builds the iPad app on macOS and the Windows executable on Windows. It tests malformed IPA rejection, certificate/profile checks, authenticated HTTPS upload integrity, error cleanup, and the packaged GUI. It signs a compiled IPA using a generated **test-only** identity on Windows, then checks that signature with Apple's `codesign` on macOS. Those generated credentials are never installation credentials.

For Windows development, install Python 3.12, run `python -m pip install -r Companion/requirements.txt`, `python scripts/prepare_windows.py`, then `python Companion/app.py`. Run tests with `python -m unittest discover -s Companion -p test_core.py -v`.

The Xcode project retains the internal `FileBridge` target name. Its displayed name is SideBridge and the CI bundle ID is `com.jta89.sidebridge`.

## Open-source components and references

- [zsign 1.1.2](https://github.com/zhlynn/zsign/tree/v1.1.2), MIT. The Windows release is pinned and SHA-256 checked before packaging. License included.
- [pymobiledevice3 11.26.0](https://github.com/doronz88/pymobiledevice3/tree/v11.26.0), GPL-3.0. Dependency license files are retained in the Windows distribution.
- This project's original code is GPL-3.0-or-later to accommodate the bundled device library. See LICENSE. Full source is available in this repository.
- [Apple: distributing to registered devices](https://developer.apple.com/documentation/xcode/distributing-your-app-to-registered-devices)
- [Apple Devices file sharing](https://support.apple.com/en-gb/120402)

SideBridge is not affiliated with Apple or Sideloadly.
