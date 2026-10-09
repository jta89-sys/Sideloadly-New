import Foundation

@main
struct FileOperationsTests {
    static func main() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? fm.removeItem(at: root) }
        let source = root.appendingPathComponent("source")
        let inbox = root.appendingPathComponent("inbox")
        try fm.createDirectory(at: source, withIntermediateDirectories: true)
        let original = source.appendingPathComponent("résumé data.bin")
        let bytes = Data((0..<65536).map { UInt8($0 % 256) })
        try bytes.write(to: original)
        let first = try FileOperations.copy(original, into: inbox)
        let second = try FileOperations.copy(original, into: inbox)
        precondition(first.lastPathComponent == "résumé data.bin")
        precondition(second.lastPathComponent == "résumé data (2).bin")
        let firstData = try Data(contentsOf: first)
        let secondData = try Data(contentsOf: second)
        let sourceData = try Data(contentsOf: original)
        precondition(firstData == bytes && secondData == bytes && sourceData == bytes)
        let empty = source.appendingPathComponent("empty")
        try Data().write(to: empty)
        _ = try FileOperations.copy(empty, into: inbox)
        let emptyAgain = try FileOperations.copy(empty, into: inbox)
        precondition(emptyAgain.lastPathComponent == "empty (2)")
        do {
            _ = try FileOperations.copy(source, into: inbox)
            fatalError("Folder should be rejected")
        } catch { /* expected */ }
        do {
            _ = try FileOperations.copy(source.appendingPathComponent("missing"), into: inbox)
            fatalError("Missing source should fail")
        } catch { /* expected */ }
        let entries = try fm.contentsOfDirectory(atPath: inbox.path)
        precondition(entries.count == 4, "Failures must not leave partial inbox files")
        print("PASS: binary integrity, originals preserved, duplicate names, Unicode, empty files, failure cleanup")
    }
}
