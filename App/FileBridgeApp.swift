import SwiftUI
import UniformTypeIdentifiers
import UIKit

@main
struct FileBridgeApp: App {
    var body: some Scene {
        WindowGroup {
            TabView {
                CompanionView().tabItem { Label("Install apps", systemImage: "square.and.arrow.down") }
                InboxView().tabItem { Label("File inbox", systemImage: "folder") }
            }
        }
    }
}

struct InboxFile: Identifiable {
    let url: URL
    let size: Int64
    var id: URL { url }
    var name: String { url.lastPathComponent }
}

@MainActor
final class Inbox: ObservableObject {
    @Published var files: [InboxFile] = []
    @Published var busy = false
    @Published var message = "Add files to get started."
    @Published var error: String?
    let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]

    func refresh() {
        do {
            let urls = try FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                options: [.skipsHiddenFiles])
            files = try urls.compactMap { url in
                let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                guard values.isRegularFile == true else { return nil }
                return InboxFile(url: url, size: Int64(values.fileSize ?? 0))
            }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        } catch { self.error = error.localizedDescription }
    }

    func importFiles(_ urls: [URL]) {
        guard !busy, !urls.isEmpty else { return }
        busy = true
        message = "Copying \(urls.count) file(s) into the inbox…"
        let scopes = urls.map { $0.startAccessingSecurityScopedResource() }
        let destination = directory
        Task {
            let result = await Task.detached(priority: .userInitiated) { () -> (Int, [String]) in
                defer {
                    for (url, accessed) in zip(urls, scopes) where accessed {
                        url.stopAccessingSecurityScopedResource()
                    }
                }
                var count = 0
                var failures: [String] = []
                for url in urls {
                    var coordinationError: NSError?
                    var copyError: Error?
                    NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { readable in
                        do { _ = try FileOperations.copy(readable, into: destination) }
                        catch { copyError = error }
                    }
                    if let failure = coordinationError ?? copyError as NSError? {
                        failures.append("\(url.lastPathComponent): \(failure.localizedDescription)")
                    } else { count += 1 }
                }
                return (count, failures)
            }.value
            busy = false
            refresh()
            message = "Added \(result.0) of \(urls.count) file(s)."
            if !result.1.isEmpty { error = result.1.joined(separator: "\n\n") }
        }
    }
}

private enum ActiveSheet: String, Identifiable {
    case add, export, help
    var id: String { rawValue }
}

struct InboxView: View {
    @StateObject private var inbox = Inbox()
    @Environment(\.scenePhase) private var scenePhase
    @State private var selected: Set<URL> = []
    @State private var sheet: ActiveSheet?
    @State private var exportURLs: [URL] = []

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 8) {
                    Label("iPad ↔ Windows", systemImage: "arrow.left.arrow.right")
                        .font(.largeTitle.bold())
                    Text("Keep files in your inbox. Copy them to a Windows shared folder or collect them over USB.")
                        .foregroundStyle(.secondary)
                }.padding(.horizontal)

                HStack(spacing: 12) {
                    Button { sheet = .add } label: { Label("Add files", systemImage: "plus") }
                        .buttonStyle(.borderedProminent)
                    Button {
                        exportURLs = inbox.files.filter { selected.contains($0.url) }.map(\.url)
                        sheet = .export
                    } label: { Label("Copy to folder", systemImage: "folder.badge.plus") }
                        .buttonStyle(.bordered)
                        .disabled(selected.isEmpty)
                    Spacer()
                }.padding(.horizontal).disabled(inbox.busy)

                if inbox.files.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "tray.and.arrow.down").font(.system(size: 56)).foregroundStyle(.tint)
                        Text("Your file inbox").font(.title2.bold())
                        Text("Add documents, photos, videos, or ZIP files from Files. For Wi-Fi, connect your Windows share in Files first.")
                            .multilineTextAlignment(.center).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(40)
                } else {
                    List(inbox.files) { file in
                        Button {
                            if selected.contains(file.url) { selected.remove(file.url) }
                            else { selected.insert(file.url) }
                        } label: {
                            HStack(spacing: 14) {
                                Image(systemName: selected.contains(file.url) ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(.tint).font(.title2)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(file.name).foregroundStyle(.primary)
                                    Text(ByteCountFormatter.string(fromByteCount: file.size, countStyle: .file))
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                            }.padding(.vertical, 4).contentShape(Rectangle())
                        }.buttonStyle(.plain)
                            .accessibilityAddTraits(selected.contains(file.url) ? .isSelected : [])
                    }.listStyle(.insetGrouped).disabled(inbox.busy)
                }
                HStack {
                    if inbox.busy { ProgressView() }
                    Text(inbox.message).font(.footnote).foregroundStyle(.secondary)
                    Spacer()
                    Text("\(selected.count) selected").font(.footnote)
                }.padding(.horizontal)
            }.padding(.vertical)
                .navigationTitle("File Bridge")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItemGroup(placement: .topBarTrailing) {
                        Button("Select all") { selected = Set(inbox.files.map(\.url)) }
                            .disabled(inbox.files.isEmpty || inbox.busy)
                        Button { inbox.refresh() } label: { Image(systemName: "arrow.clockwise") }
                            .accessibilityLabel("Refresh inbox").disabled(inbox.busy)
                        Button { sheet = .help } label: { Image(systemName: "questionmark.circle") }
                            .accessibilityLabel("Transfer setup")
                    }
                }
                .sheet(item: $sheet) { current in
                    switch current {
                    case .add:
                        DocumentPicker(exporting: nil) { urls in
                            sheet = nil
                            inbox.importFiles(urls)
                        } onCancel: { sheet = nil }
                    case .export:
                        DocumentPicker(exporting: exportURLs) { _ in
                            sheet = nil
                            inbox.message = "Copy completed to the folder you chose."
                        } onCancel: { sheet = nil }
                    case .help: SetupView()
                    }
                }
                .alert("File operation failed", isPresented: Binding(
                    get: { inbox.error != nil }, set: { if !$0 { inbox.error = nil } })) {
                        Button("OK") { inbox.error = nil }
                    } message: { Text(inbox.error ?? "") }
                .onAppear { inbox.refresh() }
                .onChange(of: scenePhase) { _, phase in
                    if phase == .active && !inbox.busy { inbox.refresh() }
                }
                .onChange(of: inbox.files.map(\.url)) { _, urls in
                    selected.formIntersection(Set(urls))
                }
        }
    }
}

struct DocumentPicker: UIViewControllerRepresentable {
    let exporting: [URL]?
    let onPick: ([URL]) -> Void
    let onCancel: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker: UIDocumentPickerViewController
        if let exporting {
            picker = UIDocumentPickerViewController(forExporting: exporting, asCopy: true)
        } else {
            picker = UIDocumentPickerViewController(forOpeningContentTypes: [.item], asCopy: false)
            picker.allowsMultipleSelection = true
        }
        picker.delegate = context.coordinator
        return picker
    }
    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let parent: DocumentPicker
        init(_ parent: DocumentPicker) { self.parent = parent }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            parent.onPick(urls)
        }
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { parent.onCancel() }
    }
}

struct SetupView: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            List {
                Section("Wi-Fi • Windows shared folder") {
                    Text("1. Put the iPad and PC on the same trusted local network.")
                    Text("2. On Windows, share a folder with your Windows user account and allow write access. Enable network discovery and file sharing for the Private network.")
                    Text("3. On iPad, open Files → Browse → … → Connect to Server. Enter smb:// followed by your PC’s name or local IP address. Sign in as a registered user with your Windows username and password.")
                    Text("4. Return here, add files, select them, and tap Copy to folder. Choose your Windows share in the system picker. To receive files, use Add files and browse the share.")
                }
                Section("USB • Apple Devices for Windows") {
                    Text("1. Install Apple Devices from the Microsoft Store, connect the iPad using a data-capable USB cable, unlock it, and trust the computer.")
                    Text("2. In Apple Devices, select the iPad → Files → File Bridge. Select inbox files and save them to your PC, or add files from the PC to this app.")
                    Text("3. Tap Refresh when returning to File Bridge to see files added from Windows. Use individual files; folders are not listed in this inbox.")
                }
                Section("Your files") {
                    Text("Transfers copy files and preserve the originals. Duplicate imports receive a numbered name. Manage or delete inbox files in Files → On My iPad → File Bridge. Keep the app open while importing. Network copy errors and replacement choices are handled by the system picker.")
                }
            }.navigationTitle("Transfer setup")
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}
