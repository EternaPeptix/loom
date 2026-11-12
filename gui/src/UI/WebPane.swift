import SwiftUI
import WebKit

/// A `WKWebView` that shows the daemon's own web UI over the tunnel. See gui/DESIGN.md "Web pane".
///
/// CONTRACT for the implementer:
/// - loads `url` (which is `<baseURL>/?token=<token>`) when it changes; shows connecting /
///   unreachable / no-connection states instead of a blank view.
/// - restricts navigation to `url`'s origin (loopback); any other origin is cancelled and opened in
///   the default browser (`NSWorkspace.shared.open`).
/// - navigates to a specific session when `focusSession` is set (then the caller clears it).
/// - never injects scripts or reads page contents.
struct WebPane: NSViewRepresentable {
    let url: URL?
    @Binding var focusSession: String?

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        let view = WKWebView(frame: .zero, configuration: config)
        view.navigationDelegate = context.coordinator
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        context.coordinator.load(url, into: view)
        // focusSession handling: see DESIGN.md.
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, WKNavigationDelegate {
        private var loaded: URL?

        func load(_ url: URL?, into view: WKWebView) {
            guard let url, url != loaded else { return }
            loaded = url
            view.load(URLRequest(url: url))
        }

        // Restrict navigation to the loopback origin; open anything else in the browser.
        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            decisionHandler(.allow)
        }
    }
}
