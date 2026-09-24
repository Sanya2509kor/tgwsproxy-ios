import SwiftUI

@available(iOS 17.0, *)
struct LogsView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var store = LogStore.shared

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(store.lines.enumerated()), id: \.offset) { index, line in
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(colorFor(line))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(index)
                        }
                    }
                    .padding(8)
                }
                .onChange(of: store.lines.count) {
                    if let last = store.lines.indices.last {
                        withAnimation { proxy.scrollTo(last, anchor: .bottom) }
                    }
                }
            }
            .navigationTitle("Логи")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Очистить") { store.clear() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Готово") { dismiss() }
                }
            }
        }
    }

    private func colorFor(_ line: String) -> Color {
        if line.contains("[WORKER]") { return .blue }
        if line.contains("[WS]") { return .cyan }
        if line.contains("[TCP]") { return .orange }
        if line.contains("[MT]") { return .green }
        if line.contains("[BRIDGE]") { return .purple }
        if line.contains("failed") || line.contains("error") { return .red }
        return .primary
    }
}
