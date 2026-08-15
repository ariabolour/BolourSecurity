import SwiftUI

/// Shared result log for every validation screen: run an async action, record success or the
/// actual typed error — never a scripted double.
@MainActor
final class ActionLog: ObservableObject {
    @Published private(set) var entries: [String] = []

    func run(_ label: String, _ action: @escaping () async throws -> String) {
        Task {
            do {
                let result = try await action()
                entries.insert("OK  \(label): \(result)", at: 0)
            } catch {
                entries.insert("ERR \(label): \(error.localizedDescription)", at: 0)
            }
        }
    }
}

struct ActionLogView: View {
    @ObservedObject var log: ActionLog

    var body: some View {
        Section("Result Log") {
            if log.entries.isEmpty {
                Text("No actions run yet.").foregroundStyle(.secondary)
            } else {
                ForEach(Array(log.entries.enumerated()), id: \.offset) { _, entry in
                    Text(entry).font(.system(.footnote, design: .monospaced))
                }
            }
        }
    }
}
