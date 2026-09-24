import Foundation
import Combine

/// Глобальное хранилище логов приложения (видно в UI)
@MainActor
final class LogStore: ObservableObject {
    static let shared = LogStore()

    @Published private(set) var lines: [String] = []
    private let maxLines = 500

    private let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    func log(_ message: String, tag: String = "APP") {
        let time = formatter.string(from: Date())
        let line = "[\(time)] [\(tag)] \(message)"
        lines.append(line)
        if lines.count > maxLines {
            lines.removeFirst(lines.count - maxLines)
        }
        // Также пишем в системный лог
        print(line)
    }

    func clear() {
        lines.removeAll()
    }

    func export() -> String {
        lines.joined(separator: "\n")
    }
}
