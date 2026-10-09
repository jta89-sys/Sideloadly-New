import SwiftUI
import CryptoKit
import Security
import VisionKit
import AVFoundation

struct TransferJob: Decodable, Identifiable {
    let id: String
    let name: String
    let bundle: String
    let status: String
    let detail: String
    let progress: Int
    let expires: String?
}

private struct CompanionStatus: Decodable {
    let name: String
    let version: Int
    let jobs: [TransferJob]
}

private final class PinnedConnection: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    let host: String
    let fingerprint: String
    let progress: (Double) -> Void
    init(host: String, fingerprint: String, progress: @escaping (Double) -> Void) {
        self.host = host
        self.fingerprint = fingerprint
        self.progress = progress
    }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host == host,
              let trust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let actual = SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
            .map { String(format: "%02x", $0) }.joined()
        guard actual == fingerprint else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didSendBodyData bytesSent: Int64,
                    totalBytesSent: Int64, totalBytesExpectedToSend: Int64) {
        if totalBytesExpectedToSend > 0 {
            progress(Double(totalBytesSent) / Double(totalBytesExpectedToSend))
        }
    }
}

@MainActor
final class CompanionModel: ObservableObject {
    @Published var code = ""
    @Published var connected = false
    @Published var connecting = false
    @Published var uploading = false
    @Published var progress = 0.0
    @Published var jobs: [TransferJob] = []
    @Published var message = "Open SideBridge on Windows and start the connection."
    @Published var error: String?
    private var session: URLSession?
    private var baseURL: URL?
    private var token = ""
    private var generation = UUID()

    func connect() async {
        guard !connecting, !uploading else { return }
        disconnect()
        guard let parts = URLComponents(string: code.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme == "sidebridge", let host = parts.host, let port = parts.port,
              (1...65535).contains(port),
              let fingerprint = parts.queryItems?.first(where: { $0.name == "fp" })?.value,
              fingerprint.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              let newToken = parts.queryItems?.first(where: { $0.name == "token" })?.value,
              newToken.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else {
            error = "Scan or paste the complete pairing code from the Windows companion."
            return
        }
        let octets = host.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4, octets.allSatisfy({ (0...255).contains($0) }),
              octets[0] == 10 || (octets[0] == 192 && octets[1] == 168) ||
              (octets[0] == 172 && (16...31).contains(octets[1])) else {
            error = "Use your PC's private Wi-Fi address (10.x, 172.16–31.x, or 192.168.x)."
            return
        }
        connecting = true
        let attempt = generation
        defer { if generation == attempt { connecting = false } }
        baseURL = URL(string: "https://\(host):\(port)")
        token = newToken
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 1800
        let delegate = PinnedConnection(host: host, fingerprint: fingerprint) { [weak self] value in
            Task { @MainActor in self?.progress = value }
        }
        session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        do {
            try await fetchStatus()
            guard generation == attempt else { return }
            connected = true
            message = "Connected to \(host). Select an IPA to send to Windows."
        } catch {
            guard generation == attempt else { return }
            disconnect()
            self.error = "Could not connect: \(error.localizedDescription)\nKeep both devices on the same network and allow the companion through Windows Firewall on Private networks."
        }
    }

    func disconnect() {
        generation = UUID()
        session?.invalidateAndCancel()
        session = nil
        baseURL = nil
        token = ""
        connected = false
        connecting = false
        jobs = []
        message = "Open SideBridge on Windows and start the connection."
    }

    private func request(_ path: String) throws -> URLRequest {
        guard let baseURL else { throw URLError(.notConnectedToInternet) }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        return request
    }

    private func check(_ data: Data, _ response: URLResponse) throws {
        guard let response = response as? HTTPURLResponse, (200...299).contains(response.statusCode) else {
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: String]
            throw NSError(domain: "SideBridge", code: 1, userInfo: [NSLocalizedDescriptionKey:
                object?["error"] ?? "The companion rejected this request. Pair again or check Windows."])
        }
    }

    private func fetchStatus() async throws {
        guard let session else { throw URLError(.notConnectedToInternet) }
        let current = generation
        let (data, response) = try await session.data(for: request("v1/status"))
        try check(data, response)
        let state = try JSONDecoder().decode(CompanionStatus.self, from: data)
        guard state.name == "SideBridge", state.version == 1 else { throw URLError(.badServerResponse) }
        if generation == current { jobs = state.jobs }
    }

    func refresh() async {
        guard connected, !uploading else { return }
        do { try await fetchStatus() }
        catch { message = "Connection interrupted. Check Windows or disconnect and pair again." }
    }

    func send(_ source: URL) {
        guard connected, !uploading, let session else { return }
        guard source.pathExtension.lowercased() == "ipa" else {
            error = "Choose a file ending in .ipa."
            return
        }
        uploading = true
        progress = 0
        let accessed = source.startAccessingSecurityScopedResource()
        Task {
            defer {
                if accessed { source.stopAccessingSecurityScopedResource() }
                uploading = false
            }
            let staging = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: staging) }
            do {
                message = "Preparing IPA…"
                let local = try await Task.detached(priority: .userInitiated) {
                    var failure: NSError?
                    var result: Result<URL, Error>?
                    NSFileCoordinator().coordinate(readingItemAt: source, options: [], error: &failure) { readable in
                        result = Result {
                            let size = try readable.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                            guard size > 0, size <= 512 * 1024 * 1024 else {
                                throw NSError(domain: "SideBridge", code: 2, userInfo: [NSLocalizedDescriptionKey: "Choose an IPA no larger than 512 MB."])
                            }
                            return try FileOperations.copy(readable, into: staging)
                        }
                    }
                    if let failure { throw failure }
                    guard let result else { throw URLError(.cannotOpenFile) }
                    return try result.get()
                }.value
                message = "Sending IPA to Windows. Keep SideBridge open…"
                var upload = try request("v1/upload")
                upload.httpMethod = "POST"
                upload.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
                let size = try local.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                upload.setValue(String(size), forHTTPHeaderField: "Content-Length")
                let (data, response) = try await session.upload(for: upload, fromFile: local)
                try check(data, response)
                message = "Received on Windows. Select the app there and choose Sign & install."
                try await fetchStatus()
            } catch {
                self.error = error.localizedDescription
                message = "Upload did not complete. Check the connection and try again."
            }
        }
    }
}

struct CompanionView: View {
    @StateObject private var model = CompanionModel()
    @State private var picker = false
    @State private var scanner = false
    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label("Sign on Windows. Install on iPad.", systemImage: "ipad.and.arrow.forward")
                        .font(.title2.bold())
                    Text("Send an IPA to your Windows companion. Signing certificates stay on your PC. Connect the iPad to that PC over USB for installation.")
                        .foregroundStyle(.secondary)
                }
                Section("Windows connection") {
                    if !model.connected {
                        TextField("Paste pairing code from Windows", text: $model.code)
                            .textInputAutocapitalization(.never).autocorrectionDisabled().privacySensitive()
                        HStack {
                            Button("Scan QR code", systemImage: "qrcode.viewfinder") {
                                Task {
                                    let granted = await AVCaptureDevice.requestAccess(for: .video)
                                    if granted && DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                                        scanner = true
                                    } else { model.error = "Camera scanning is unavailable. Paste the pairing code, or allow camera access in Settings." }
                                }
                            }
                            Spacer()
                            Button("Connect") { Task { await model.connect() } }
                                .buttonStyle(.borderedProminent)
                        }.disabled(model.connecting)
                        if model.connecting { ProgressView("Connecting…") }
                    } else {
                        Label("Connected to Windows", systemImage: "checkmark.shield.fill").foregroundStyle(.green)
                        Button("Disconnect") { model.disconnect() }.disabled(model.uploading)
                    }
                    Text(model.message).font(.callout)
                }
                if model.connected {
                    Section("Send an app") {
                        Button("Choose IPA", systemImage: "square.and.arrow.up") { picker = true }
                            .disabled(model.uploading)
                        if model.uploading { ProgressView(value: model.progress) }
                        Text("Up to 512 MB. Apps with extensions and encrypted App Store downloads are not supported in this version.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Section("Apps on Windows") {
                        if model.jobs.isEmpty { Text("No apps sent yet.").foregroundStyle(.secondary) }
                        ForEach(model.jobs) { job in
                            VStack(alignment: .leading, spacing: 5) {
                                HStack { Text(job.name).font(.headline); Spacer(); Text(job.status).font(.subheadline.bold()) }
                                Text(job.bundle).font(.caption).foregroundStyle(.secondary)
                                Text(job.detail).font(.callout)
                                if job.status == "Installing" { ProgressView(value: Double(job.progress), total: 100) }
                                if let expires = job.expires { Text("Profile expires: \(expires)").font(.caption).foregroundStyle(.secondary) }
                            }.padding(.vertical, 5)
                        }
                    }
                }
                Section("First installation") {
                    Text("Use the Windows app to sign and install this SideBridge IPA first. You need a valid P12 certificate and a development or ad hoc provisioning profile covering your iPad. Enable Developer Mode and trust the developer profile if iPadOS asks.")
                }
            }.navigationTitle("SideBridge")
                .refreshable { await model.refresh() }
                .task {
                    while !Task.isCancelled {
                        await model.refresh()
                        try? await Task.sleep(for: .seconds(3))
                    }
                }
                .sheet(isPresented: $picker) {
                    DocumentPicker(exporting: nil) { urls in
                        picker = false
                        if let first = urls.first { model.send(first) }
                    } onCancel: { picker = false }
                }
                .sheet(isPresented: $scanner) {
                    QRScanner { code in
                        model.code = code
                        scanner = false
                        Task { await model.connect() }
                    }
                }
                .alert("SideBridge", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
                    Button("OK") { model.error = nil }
                } message: { Text(model.error ?? "") }
        }
    }
}

private struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    func makeCoordinator() -> Coordinator { Coordinator(onCode) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced, recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true, isGuidanceEnabled: true, isHighlightingEnabled: true)
        controller.delegate = context.coordinator
        try? controller.startScanning()
        return controller
    }
    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}
    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) { controller.stopScanning() }
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        var found = false
        init(_ onCode: @escaping (String) -> Void) { self.onCode = onCode }
        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            for item in addedItems {
                if case .barcode(let barcode) = item, let value = barcode.payloadStringValue,
                   value.hasPrefix("sidebridge://"), !found {
                    found = true
                    dataScanner.stopScanning()
                    onCode(value)
                }
            }
        }
    }
}
