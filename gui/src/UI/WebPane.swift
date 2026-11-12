import SwiftUI
import WebKit

/// What the web view is doing, for the overlay in `RootView`.
enum WebState: Equatable {
    case idle
    case loading
    case loaded
    case failed(String)
}

/// A `WKWebView` that shows the daemon's own web UI over the tunnel. See gui/DESIGN.md "Web pane".
///
/// - loads `url` (`<baseURL>/?token=<token>`: the daemon answers 303 + `Set-Cookie: loom_token` and
///   redirects to `/`) when it changes; reports loading / loaded / failed through `onState`.
/// - restricts navigation to `url`'s origin (loopback); any other http(s) origin is cancelled and
///   opened in the default browser, other schemes are just cancelled.
/// - navigates to `#/s/<id>` when `focusSession` is set (then clears it).
/// - never injects scripts or reads page contents (it does look at the HTTP status of the main
///   frame response, which is navigation metadata, to report a rejected token).
/// - uses a non-persistent data store, so the session cookie never touches disk and a stale cookie
///   from another daemon on the same loopback host can never be replayed.
struct WebPane: NSViewRepresentable {
    let url: URL?
    @Binding var focusSession: String?
    var reloadTick: Int = 0
    var onState: (WebState) -> Void = { _ in }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        let view = WKWebView(frame: .zero, configuration: config)
        view.navigationDelegate = context.coordinator
        view.uiDelegate = context.coordinator
        view.allowsBackForwardNavigationGestures = true
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        let c = context.coordinator
        c.onState = onState
        c.load(url, into: view)
        if reloadTick != c.lastReloadTick {
            c.lastReloadTick = reloadTick
            c.reload(view)
        }
        if let id = focusSession {
            c.focus(session: id, in: view)
            DispatchQueue.main.async { self.focusSession = nil }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    // MARK: pure helpers

    /// Same scheme, host and (effective) port.
    static func isSameOrigin(_ a: URL, _ b: URL) -> Bool {
        func port(_ u: URL) -> Int? { u.port ?? (u.scheme?.lowercased() == "https" ? 443 : u.scheme?.lowercased() == "http" ? 80 : nil) }
        guard let sa = a.scheme?.lowercased(), let sb = b.scheme?.lowercased(), sa == sb,
              let ha = a.host?.lowercased(), let hb = b.host?.lowercased(), ha == hb else { return false }
        return port(a) == port(b)
    }

    /// `<origin>/#/s/<id>` — the web UI's own route for a session.
    static func sessionURL(origin: URL, session: String) -> URL? {
        guard var c = URLComponents(url: origin, resolvingAgainstBaseURL: false) else { return nil }
        c.path = "/"; c.query = nil
        c.percentEncodedFragment = "/s/" + (session.addingPercentEncoding(withAllowedCharacters: CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? "")
        return c.url
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        private var loaded: URL?
        private var origin: URL?
        private var pageLoaded = false
        private var pendingFocus: String?
        var lastReloadTick = 0
        var onState: (WebState) -> Void = { _ in }

        func load(_ url: URL?, into view: WKWebView) {
            guard let url else { return }
            origin = url
            guard url != loaded else { return }
            loaded = url
            pageLoaded = false
            report(.loading)
            view.load(URLRequest(url: url))
        }

        func reload(_ view: WKWebView) {
            report(.loading)
            if view.url == nil || !pageLoaded, let l = loaded {
                view.load(URLRequest(url: l))
            } else {
                view.reload()
            }
        }

        func focus(session id: String, in view: WKWebView) {
            guard let origin else { return }
            if !pageLoaded { pendingFocus = id; return }
            if let u = WebPane.sessionURL(origin: origin, session: id) { view.load(URLRequest(url: u)) }
        }

        private func report(_ s: WebState) {
            let cb = onState
            DispatchQueue.main.async { cb(s) }
        }

        // MARK: navigation policy

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let target = navigationAction.request.url else { decisionHandler(.cancel); return }
            if target.absoluteString == "about:blank" { decisionHandler(.allow); return }
            if let origin, WebPane.isSameOrigin(target, origin) { decisionHandler(.allow); return }
            decisionHandler(.cancel)
            openExternally(target)
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationResponse: WKNavigationResponse,
                     decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
            if navigationResponse.isForMainFrame, let http = navigationResponse.response as? HTTPURLResponse,
               http.statusCode == 401 || http.statusCode == 403 {
                report(.failed("the daemon rejected the token (HTTP \(http.statusCode)). Edit the connection and reconnect."))
            }
            decisionHandler(.allow)
        }

        // target=_blank / window.open: same-origin loads in this view, anything else goes to the browser.
        func webView(_ webView: WKWebView,
                     createWebViewWith configuration: WKWebViewConfiguration,
                     for navigationAction: WKNavigationAction,
                     windowFeatures: WKWindowFeatures) -> WKWebView? {
            if let target = navigationAction.request.url {
                if let origin, WebPane.isSameOrigin(target, origin) {
                    webView.load(URLRequest(url: target))
                } else {
                    openExternally(target)
                }
            }
            return nil
        }

        private func openExternally(_ url: URL) {
            guard let s = url.scheme?.lowercased(), s == "http" || s == "https" || s == "mailto" else { return }
            DispatchQueue.main.async { NSWorkspace.shared.open(url) }
        }

        // MARK: load state

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            report(.loading)
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            pageLoaded = true
            report(.loaded)
            if let id = pendingFocus {
                pendingFocus = nil
                focus(session: id, in: webView)
            }
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            fail(error)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            fail(error)
        }

        private func fail(_ error: Error) {
            let ns = error as NSError
            // A navigation we cancelled ourselves (foreign origin) or replaced is not a failure.
            if ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCancelled { return }
            if ns.domain == "WebKitErrorDomain" && ns.code == 102 { return }
            report(.failed(error.localizedDescription))
        }
    }

    #if DEBUG
    static func selfCheck() -> [String] {
        var f: [String] = []
        func chk(_ c: Bool, _ m: String) { if !c { f.append("WebPane: " + m) } }
        guard let a = URL(string: "http://127.0.0.1:5000/?token=x"),
              let b = URL(string: "http://127.0.0.1:5000/app.js"),
              let c = URL(string: "http://127.0.0.1:5001/"),
              let d = URL(string: "http://localhost:5000/"),
              let e = URL(string: "https://127.0.0.1:5000/") else { return ["WebPane: bad fixtures"] }
        chk(isSameOrigin(a, b), "same origin rejected")
        chk(!isSameOrigin(a, c), "other port accepted")
        chk(!isSameOrigin(a, d), "other host accepted")
        chk(!isSameOrigin(a, e), "other scheme accepted")
        chk(sessionURL(origin: a, session: "s-1")?.absoluteString == "http://127.0.0.1:5000/#/s/s-1",
            "session url: \(sessionURL(origin: a, session: "s-1")?.absoluteString ?? "nil")")
        return f
    }
    #endif
}
