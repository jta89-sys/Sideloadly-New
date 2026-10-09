import Foundation

enum FileOperations {
    static func copy(_ source: URL, into directory: URL) throws -> URL {
        let manager = FileManager.default
        let values = try source.resourceValues(forKeys: [.isRegularFileKey])
        guard values.isRegularFile == true else {
            throw NSError(domain: "FileBridge", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Choose individual files. Folder import is not supported."])
        }
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        let ext = source.pathExtension
        let base = source.deletingPathExtension().lastPathComponent
        var destination = directory.appendingPathComponent(source.lastPathComponent)
        var index = 2
        while manager.fileExists(atPath: destination.path) {
            let name = "\(base) (\(index))" + (ext.isEmpty ? "" : ".\(ext)")
            destination = directory.appendingPathComponent(name)
            index += 1
        }
        // Stage outside Documents so a failed copy never appears as a complete file.
        let staging = manager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? manager.removeItem(at: staging) }
        try manager.copyItem(at: source, to: staging)
        try manager.moveItem(at: staging, to: destination)
        return destination
    }
}
