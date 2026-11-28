import AppKit
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
/// - each web view loads exactly one entry URL (`<baseURL>/#code=<one-time code>`: the page exchanges the
///   code itself; the app sets no cookie and never puts the token in a URL). A new view calls `onCreated`;
///   AppState then makes the daemon prove its identity, mints a code, bumps
///   `entryTick`, and the view takes the URL once through `takeEntry`. A reload builds a new view, so
///   every load is a full document load, never a fragment change in the old one. Reports loading /
///   loaded / failed through `onState`.
/// - restricts navigation to the entry URL's origin (loopback); any other http(s) origin is cancelled and
///   opened in the default browser, other schemes are just cancelled (except page-initiated blob:/data:
///   downloads).
/// - navigates to `#/s/<id>`, `#/inbox`, or a preserved `#/...` SPA fragment via `routeTick` / `takeRoute`
///   (no script injection).
/// - never injects scripts or reads page contents (only observes WebKit navigation/metadata properties:
///   HTTP status, `title`, `url`, `canGoBack`, `canGoForward`).
/// - uses a per-connection non-persistent data store, so nothing the page stores touches disk and nothing
///   from another daemon on the same loopback host can be replayed.
struct WebPane: NSViewRepresentable {
    enum Route: Equatable {
        case session(String)
        case inbox
        case fragment(String)
    }

    enum FindAction: Equatable {
        case find(query: String, backwards: Bool)
        case clear
    }

    enum NavAction: Equatable {
        case back
        case forward
        case focus
    }

    /// Per-connection ephemeral data store (preserved across reloads of the same connection, cleared on switch/disconnect).
    let dataStore: WKWebsiteDataStore
    /// Native page zoom factor (persisted in UserDefaults on AppState).
    let pageZoom: CGFloat
    /// Bumped when a fresh entry URL waits in `takeEntry`.
    let entryTick: Int
    /// Bumped when a notification click, badge tap, or reload restoration requests an SPA route in `takeRoute`.
    let routeTick: Int
    /// Bumped when Find Next / Previous / Clear waits in `takeFindAction`.
    let findTick: Int
    /// Bumped when Back / Forward / Focus waits in `takeNavAction`.
    let navTick: Int
    /// True while the native Find bar is open so `didFinish` does not steal focus from the Find input.
    var isFindBarOpen: Bool = false
    /// Hands out the entry URL once (nil when there is none).
    var takeEntry: () -> URL? = { nil }
    /// Hands out the requested SPA route once (nil when there is none).
    var takeRoute: () -> Route? = { nil }
    /// Hands out a pending Find command once.
    var takeFindAction: () -> FindAction? = { nil }
    /// Hands out a pending Back/Forward/Focus command once.
    var takeNavAction: () -> NavAction? = { nil }
    /// Checked immediately before any navigation load against a tunneled daemon.
    var isTunnelAlive: () -> Bool = { true }
    /// Called once per created web view, which needs a fresh one-time code before it can load.
    var onCreated: () -> Void = {}
    var onState: (WebState) -> Void = { _ in }
    var onRouteChanged: (String) -> Void = { _ in }
    var onSessionExpired: () -> Void = {}
    var onProcessTerminated: () -> Void = {}
    var onNavCapability: (Bool, Bool) -> Void = { _, _ in }
    var onFindResult: (Bool) -> Void = { _ in }
    var onDownloadNotice: (String?) -> Void = { _ in }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = dataStore
        let view = WKWebView(frame: .zero, configuration: config)
        view.navigationDelegate = context.coordinator
        view.uiDelegate = context.coordinator
        view.allowsBackForwardNavigationGestures = true
        view.allowsMagnification = true
        view.pageZoom = pageZoom
        context.coordinator.attachObservers(to: view)
        let created = onCreated
        DispatchQueue.main.async { created() }   // after this view update, which must not publish changes
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        let c = context.coordinator
        c.onState = onState
        c.isTunnelAlive = isTunnelAlive
        c.isFindBarOpen = isFindBarOpen
        c.onRouteChanged = onRouteChanged
        c.onSessionExpired = onSessionExpired
        c.onProcessTerminated = onProcessTerminated
        c.onNavCapability = onNavCapability
        c.onFindResult = onFindResult
        c.onDownloadNotice = onDownloadNotice
        if abs(view.pageZoom - pageZoom) > 0.001 {
            view.pageZoom = pageZoom
        }
        if entryTick != c.entryTick {
            c.entryTick = entryTick
            if let url = takeEntry() { c.load(url, into: view) }
        }
        if routeTick != c.routeTick {
            c.routeTick = routeTick
            if let route = takeRoute() { c.navigate(route, in: view) }
        }
        if findTick != c.findTick {
            c.findTick = findTick
            if let action = takeFindAction() { c.performFind(action, in: view) }
        }
        if navTick != c.navTick {
            c.navTick = navTick
            if let action = takeNavAction() { c.performNav(action, in: view) }
        }
    }

    // `entryTick` starts at the current tick so an earlier view's URL is not taken; `routeTick` starts at
    // 0 so a pending notification or reload-preserved route is still consumed on mount.
    func makeCoordinator() -> Coordinator {
        Coordinator(entryTick: entryTick, routeTick: 0, findTick: findTick, navTick: navTick, isTunnelAlive: isTunnelAlive)
    }

    // MARK: pure helpers

    /// Same scheme, host and (effective) port.
    static func isSameOrigin(_ a: URL, _ b: URL) -> Bool {
        func port(_ u: URL) -> Int? { u.port ?? (u.scheme?.lowercased() == "https" ? 443 : u.scheme?.lowercased() == "http" ? 80 : nil) }
        guard let sa = a.scheme?.lowercased(), let sb = b.scheme?.lowercased(), sa == sb,
              let ha = a.host?.lowercased(), let hb = b.host?.lowercased(), ha == hb else { return false }
        return port(a) == port(b)
    }

    private static func fragmentURL(origin: URL, percentEncodedFragment: String) -> URL? {
        guard var c = URLComponents(url: origin, resolvingAgainstBaseURL: false) else { return nil }
        c.path = "/"; c.query = nil
        c.percentEncodedFragment = percentEncodedFragment
        return c.url
    }

    /// `<origin>/#/s/<id>` — the web UI's own route for a session.
    static func sessionURL(origin: URL, session: String) -> URL? {
        let encoded = session.addingPercentEncoding(withAllowedCharacters: CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? ""
        return fragmentURL(origin: origin, percentEncodedFragment: "/s/" + encoded)
    }

    /// `<origin>/#/inbox` — the web UI's inbox view.
    static func inboxURL(origin: URL) -> URL? {
        fragmentURL(origin: origin, percentEncodedFragment: "/inbox")
    }

    /// Extract a safe restorable SPA route fragment (starts with `/`, never a `#code=` login fragment).
    static func restorableFragment(from url: URL) -> String? {
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let frag = c.percentEncodedFragment,
              frag.hasPrefix("/"),
              !frag.contains("\n"), !frag.contains("\r") else { return nil }
        return frag
    }

    static func routeURL(origin: URL, route: Route) -> URL? {
        switch route {
        case .session(let id): return sessionURL(origin: origin, session: id)
        case .inbox: return inboxURL(origin: origin)
        case .fragment(let frag):
            guard frag.hasPrefix("/") else { return nil }
            return fragmentURL(origin: origin, percentEncodedFragment: frag)
        }
    }

    /// True when `current` and `target` match in origin, path, query, and fragment so calling `WKWebView.load`
    /// can be skipped instead of triggering a reload.
    static func isSameDocumentTarget(_ current: URL, _ target: URL) -> Bool {
        guard isSameOrigin(current, target),
              let a = URLComponents(url: current, resolvingAgainstBaseURL: false),
              let b = URLComponents(url: target, resolvingAgainstBaseURL: false) else { return false }
        let pa = a.path.isEmpty ? "/" : a.path
        let pb = b.path.isEmpty ? "/" : b.path
        return pa == pb && a.query == b.query && (a.fragment ?? "") == (b.fragment ?? "")
    }

    /// Policy decision for an HTTP navigation response so 4xx/5xx JSON errors never open NSSavePanel.
    enum HTTPResponseAction: Equatable {
        case allow
        case download
        case authRefused(Int)
        case downloadFailed(Int)
    }

    static func classifyHTTPResponse(statusCode: Int,
                                     isMainFrame: Bool,
                                     canShowMIMEType: Bool,
                                     contentDisposition: String?) -> HTTPResponseAction {
        if isMainFrame && (statusCode == 401 || statusCode == 403) {
            return .authRefused(statusCode)
        }
        let wantsDownload = isAttachmentDisposition(contentDisposition) || !canShowMIMEType
        if wantsDownload {
            if (200..<300).contains(statusCode) { return .download }
            if statusCode >= 400 { return .downloadFailed(statusCode) }
            return .allow
        }
        return .allow
    }

    /// True when a navigation response carries `Content-Disposition: attachment`.
    static func isAttachmentDisposition(_ header: String?) -> Bool {
        guard let header else { return false }
        let first = header.split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return first == "attachment"
    }

    /// True when a download URL is allowed from the current same-origin document.
    static func isAllowedDownloadTarget(_ target: URL, origin: URL?) -> Bool {
        if let scheme = target.scheme?.lowercased(), scheme == "blob" || scheme == "data" { return true }
        if let origin, isSameOrigin(target, origin) { return true }
        return false
    }

    /// Strip path separators and control characters from a server-suggested filename.
    static func safeDownloadFilename(_ raw: String) -> String {
        let last = (raw as NSString).lastPathComponent
        let cleaned = last.unicodeScalars.filter { scalar in
            scalar != "/" && scalar != ":" && scalar.properties.generalCategory != .control
        }
        let s = String(String.UnicodeScalarView(cleaned)).trimmingCharacters(in: .whitespacesAndNewlines)
        return (s.isEmpty || s == "." || s == "..") ? "download" : s
    }

    /// The exact document title `ui/app.js` sets in `lost()` when the web-session secret expires.
    static let notSignedInTitle = "ferret · not signed in"

    @MainActor
    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
        private var origin: URL?
        private var pageLoaded = false
        private var pendingRoute: WebPane.Route?
        private var reportedExpired = false
        private var observations: [NSKeyValueObservation] = []
        private var activeDownloads: [ObjectIdentifier: WKDownload] = [:]
        private var downloadDestinations: [ObjectIdentifier: URL] = [:]
        private weak var webView: WKWebView?
        /// The `entryTick` this view has seen; a URL is taken only when it moves on.
        var entryTick: Int
        var routeTick: Int
        var findTick: Int
        var navTick: Int
        var isFindBarOpen = false
        var isTunnelAlive: () -> Bool
        var onState: (WebState) -> Void = { _ in }
        var onRouteChanged: (String) -> Void = { _ in }
        var onSessionExpired: () -> Void = {}
        var onProcessTerminated: () -> Void = {}
        var onNavCapability: (Bool, Bool) -> Void = { _, _ in }
        var onFindResult: (Bool) -> Void = { _ in }
        var onDownloadNotice: (String?) -> Void = { _ in }

        init(entryTick: Int, routeTick: Int, findTick: Int, navTick: Int, isTunnelAlive: @escaping () -> Bool) {
            self.entryTick = entryTick
            self.routeTick = routeTick
            self.findTick = findTick
            self.navTick = navTick
            self.isTunnelAlive = isTunnelAlive
            super.init()
        }

        deinit {
            observations.forEach { $0.invalidate() }
        }

        /// Observe navigation/document metadata only (no script injection or DOM reads per DESIGN.md).
        func attachObservers(to view: WKWebView) {
            webView = view
            observations.forEach { $0.invalidate() }
            observations = [
                view.observe(\.title, options: [.new]) { [weak self] wv, _ in
                    let title = wv.title
                    Task { @MainActor [weak self] in
                        guard let self else { return }
                        if title == WebPane.notSignedInTitle {
                            if !self.reportedExpired {
                                self.reportedExpired = true
                                self.onSessionExpired()
                            }
                        } else if title != nil {
                            self.reportedExpired = false
                        }
                    }
                },
                view.observe(\.url, options: [.new]) { [weak self] wv, _ in
                    let url = wv.url
                    Task { @MainActor [weak self] in
                        guard let self, let url, let origin = self.origin, WebPane.isSameOrigin(url, origin) else { return }
                        if let frag = WebPane.restorableFragment(from: url) {
                            self.onRouteChanged(frag)
                        }
                    }
                },
                view.observe(\.canGoBack, options: [.initial, .new]) { [weak self] wv, _ in
                    let back = wv.canGoBack, fwd = wv.canGoForward
                    Task { @MainActor [weak self] in self?.onNavCapability(back, fwd) }
                },
                view.observe(\.canGoForward, options: [.initial, .new]) { [weak self] wv, _ in
                    let back = wv.canGoBack, fwd = wv.canGoForward
                    Task { @MainActor [weak self] in self?.onNavCapability(back, fwd) }
                },
            ]
        }

        /// The view's one load: a fresh view has no document, so this is always a full load.
        func load(_ url: URL, into view: WKWebView) {
            guard origin == nil else { return }
            origin = url
            reportedExpired = false
            report(.loading)
            view.load(URLRequest(url: url))
        }

        /// Until the page has loaded (the URL may still be on its way) the route waits for `didFinish`.
        func navigate(_ route: WebPane.Route, in view: WKWebView) {
            guard pageLoaded, let origin else { pendingRoute = route; return }
            guard isTunnelAlive() else { return }
            guard let u = WebPane.routeURL(origin: origin, route: route) else { return }
            if let current = view.url, WebPane.isSameDocumentTarget(current, u) { return }
            view.load(URLRequest(url: u))
        }

        func performFind(_ action: FindAction, in view: WKWebView) {
            switch action {
            case .find(let query, let backwards):
                let trimmed = query.trimmingCharacters(in: .newlines)
                guard !trimmed.isEmpty else {
                    onFindResult(true)
                    return
                }
                let cfg = WKFindConfiguration()
                cfg.backwards = backwards
                cfg.caseSensitive = false
                cfg.wraps = true
                view.find(trimmed, configuration: cfg) { [weak self] result in
                    Task { @MainActor [weak self] in
                        self?.onFindResult(result.matchFound)
                    }
                }
            case .clear:
                let cfg = WKFindConfiguration()
                view.find("", configuration: cfg) { _ in }
                onFindResult(true)
            }
        }

        func performNav(_ action: NavAction, in view: WKWebView) {
            switch action {
            case .back:
                if view.canGoBack { view.goBack() }
            case .forward:
                if view.canGoForward { view.goForward() }
            case .focus:
                focusWebView(view)
            }
        }

        private func focusWebView(_ view: WKWebView) {
            guard !isFindBarOpen, let window = view.window, window.attachedSheet == nil else { return }
            window.makeFirstResponder(view)
        }

        private func report(_ s: WebState) {
            let cb = onState
            DispatchQueue.main.async { cb(s) }
        }

        // MARK: navigation policy

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
            guard let target = navigationAction.request.url else { decisionHandler(.cancel); return }
            if navigationAction.shouldPerformDownload {
                if WebPane.isAllowedDownloadTarget(target, origin: origin) {
                    decisionHandler(.download)
                } else {
                    decisionHandler(.cancel)
                    openExternally(target)
                }
                return
            }
            if target.absoluteString == "about:blank" { decisionHandler(.allow); return }
            if let origin, WebPane.isSameOrigin(target, origin) { decisionHandler(.allow); return }
            decisionHandler(.cancel)
            openExternally(target)
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationResponse: WKNavigationResponse,
                     decisionHandler: @escaping @MainActor (WKNavigationResponsePolicy) -> Void) {
            if let http = navigationResponse.response as? HTTPURLResponse {
                switch WebPane.classifyHTTPResponse(statusCode: http.statusCode,
                                                    isMainFrame: navigationResponse.isForMainFrame,
                                                    canShowMIMEType: navigationResponse.canShowMIMEType,
                                                    contentDisposition: http.value(forHTTPHeaderField: "Content-Disposition")) {
                case .authRefused(let code):
                    report(.failed("the daemon refused the page (HTTP \(code)). Reconnect for a fresh login code."))
                    decisionHandler(.cancel)
                case .download:
                    decisionHandler(.download)
                case .downloadFailed(let code):
                    onDownloadNotice("Download failed (HTTP \(code))")
                    decisionHandler(.cancel)
                case .allow:
                    decisionHandler(.allow)
                }
                return
            }
            if !navigationResponse.canShowMIMEType {
                decisionHandler(.download)
                return
            }
            decisionHandler(.allow)
        }

        func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
            trackDownload(download)
        }

        func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
            trackDownload(download)
        }

        private func trackDownload(_ download: WKDownload) {
            download.delegate = self
            activeDownloads[ObjectIdentifier(download)] = download
        }

        // MARK: WKDownloadDelegate

        func download(_ download: WKDownload,
                      decideDestinationUsing response: URLResponse,
                      suggestedFilename: String,
                      completionHandler: @escaping @MainActor (URL?) -> Void) {
            let panel = NSSavePanel()
            panel.canCreateDirectories = true
            panel.nameFieldStringValue = WebPane.safeDownloadFilename(suggestedFilename)
            panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            let finish: (NSApplication.ModalResponse) -> Void = { [weak self] resp in
                let dest = resp == .OK ? panel.url : nil
                if let dest {
                    self?.downloadDestinations[ObjectIdentifier(download)] = dest
                } else {
                    self?.activeDownloads.removeValue(forKey: ObjectIdentifier(download))
                }
                completionHandler(dest)
            }
            if let window = webView?.window {
                panel.beginSheetModal(for: window, completionHandler: finish)
            } else {
                panel.begin(completionHandler: finish)
            }
        }

        func downloadDidFinish(_ download: WKDownload) {
            let key = ObjectIdentifier(download)
            activeDownloads.removeValue(forKey: key)
            if let dest = downloadDestinations.removeValue(forKey: key) {
                onDownloadNotice("Saved \(dest.lastPathComponent)")
            }
        }

        func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
            let key = ObjectIdentifier(download)
            activeDownloads.removeValue(forKey: key)
            downloadDestinations.removeValue(forKey: key)
            let ns = error as NSError
            if ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCancelled { return }
            onDownloadNotice("Download failed: \(error.localizedDescription)")
        }

        // MARK: WKUIDelegate

        // File uploads (`<input type="file">`): macOS WKWebView silently cancels uploads unless implemented.
        func webView(_ webView: WKWebView,
                     runOpenPanelWith parameters: WKOpenPanelParameters,
                     initiatedByFrame frame: WKFrameInfo,
                     completionHandler: @escaping @MainActor ([URL]?) -> Void) {
            let panel = NSOpenPanel()
            panel.canChooseFiles = true
            panel.canChooseDirectories = parameters.allowsDirectories
            panel.allowsMultipleSelection = parameters.allowsMultipleSelection
            let finish: (NSApplication.ModalResponse) -> Void = { resp in
                completionHandler(resp == .OK ? panel.urls : nil)
            }
            if let window = webView.window {
                panel.beginSheetModal(for: window, completionHandler: finish)
            } else {
                panel.begin(completionHandler: finish)
            }
        }

        // target=_blank / window.open: same-origin loads in this view, anything else goes to the browser.
        func webView(_ webView: WKWebView,
                     createWebViewWith configuration: WKWebViewConfiguration,
                     for navigationAction: WKNavigationAction,
                     windowFeatures: WKWindowFeatures) -> WKWebView? {
            if let target = navigationAction.request.url {
                if let origin, WebPane.isSameOrigin(target, origin) {
                    if isTunnelAlive() { webView.load(URLRequest(url: target)) }
                } else {
                    openExternally(target)
                }
            }
            return nil
        }

        // Defensive JS dialog handlers so alert/confirm/prompt never silently fail if invoked by the page.
        func webView(_ webView: WKWebView,
                     runJavaScriptAlertPanelWithMessage message: String,
                     initiatedByFrame frame: WKFrameInfo,
                     completionHandler: @escaping @MainActor () -> Void) {
            let alert = NSAlert()
            alert.messageText = "ferret"
            alert.informativeText = message
            alert.addButton(withTitle: "OK")
            if let window = webView.window {
                alert.beginSheetModal(for: window) { _ in completionHandler() }
            } else {
                alert.runModal()
                completionHandler()
            }
        }

        func webView(_ webView: WKWebView,
                     runJavaScriptConfirmPanelWithMessage message: String,
                     initiatedByFrame frame: WKFrameInfo,
                     completionHandler: @escaping @MainActor (Bool) -> Void) {
            let alert = NSAlert()
            alert.messageText = "ferret"
            alert.informativeText = message
            alert.addButton(withTitle: "OK")
            alert.addButton(withTitle: "Cancel")
            if let window = webView.window {
                alert.beginSheetModal(for: window) { resp in completionHandler(resp == .alertFirstButtonReturn) }
            } else {
                completionHandler(alert.runModal() == .alertFirstButtonReturn)
            }
        }

        func webView(_ webView: WKWebView,
                     runJavaScriptTextInputPanelWithPrompt prompt: String,
                     defaultText: String?,
                     initiatedByFrame frame: WKFrameInfo,
                     completionHandler: @escaping @MainActor (String?) -> Void) {
            let alert = NSAlert()
            alert.messageText = prompt
            alert.addButton(withTitle: "OK")
            alert.addButton(withTitle: "Cancel")
            let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
            field.stringValue = defaultText ?? ""
            alert.accessoryView = field
            if let window = webView.window {
                alert.beginSheetModal(for: window) { resp in
                    completionHandler(resp == .alertFirstButtonReturn ? field.stringValue : nil)
                }
            } else {
                completionHandler(alert.runModal() == .alertFirstButtonReturn ? field.stringValue : nil)
            }
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
            onNavCapability(webView.canGoBack, webView.canGoForward)
            if let route = pendingRoute {
                pendingRoute = nil
                navigate(route, in: webView)
            }
            focusWebView(webView)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            fail(error)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            fail(error)
        }

        func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
            onProcessTerminated()
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
        guard let a = URL(string: "http://127.0.0.1:5000/#code=x"),
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
        chk(inboxURL(origin: a)?.absoluteString == "http://127.0.0.1:5000/#/inbox",
            "inbox url: \(inboxURL(origin: a)?.absoluteString ?? "nil")")
        chk(routeURL(origin: a, route: .inbox)?.absoluteString == "http://127.0.0.1:5000/#/inbox", "routeURL inbox")
        chk(routeURL(origin: a, route: .session("s-1"))?.absoluteString == "http://127.0.0.1:5000/#/s/s-1", "routeURL session")
        chk(routeURL(origin: a, route: .fragment("/s/s-1/evidence"))?.absoluteString == "http://127.0.0.1:5000/#/s/s-1/evidence",
            "routeURL fragment")
        chk(routeURL(origin: a, route: .fragment("code=abc")) == nil, "routeURL accepted non-slash fragment")
        chk(restorableFragment(from: a) == nil, "code fragment treated as restorable")
        if let ev = URL(string: "http://127.0.0.1:5000/#/s/s-1/evidence") {
            chk(restorableFragment(from: ev) == "/s/s-1/evidence", "restorableFragment missed route")
        }
        chk(isAttachmentDisposition("attachment; filename=\"out-123\""), "attachment disposition missed")
        chk(!isAttachmentDisposition("inline"), "inline disposition misclassified")
        chk(classifyHTTPResponse(statusCode: 200, isMainFrame: true, canShowMIMEType: false, contentDisposition: nil) == .download,
            "200 unshowable not downloaded")
        chk(classifyHTTPResponse(statusCode: 200, isMainFrame: true, canShowMIMEType: true, contentDisposition: "attachment; filename=\"a.har\"") == .download,
            "200 attachment not downloaded")
        chk(classifyHTTPResponse(statusCode: 404, isMainFrame: true, canShowMIMEType: false, contentDisposition: nil) == .downloadFailed(404),
            "404 JSON error opened save panel instead of failing")
        chk(classifyHTTPResponse(statusCode: 500, isMainFrame: false, canShowMIMEType: false, contentDisposition: "attachment") == .downloadFailed(500),
            "500 attachment opened save panel")
        chk(classifyHTTPResponse(statusCode: 401, isMainFrame: true, canShowMIMEType: false, contentDisposition: nil) == .authRefused(401),
            "401 main frame not treated as auth refused")
        if let blob = URL(string: "blob:http://127.0.0.1:5000/abc"),
           let ext = URL(string: "https://example.com/a.zip") {
            chk(isAllowedDownloadTarget(blob, origin: a), "blob download rejected")
            chk(isAllowedDownloadTarget(b, origin: a), "same-origin download rejected")
            chk(!isAllowedDownloadTarget(ext, origin: a), "foreign download allowed")
        }
        chk(safeDownloadFilename("../../secret.har") == "secret.har", "filename traversal not stripped")
        chk(safeDownloadFilename("") == "download", "empty filename fallback")
        if let s1 = URL(string: "http://127.0.0.1:5000/#/s/s-1"),
           let s1o = URL(string: "http://127.0.0.1:5000/#/s/s-1/overview"),
           let root = URL(string: "http://127.0.0.1:5000/") {
            chk(isSameDocumentTarget(s1, s1), "identical session route not recognized")
            chk(!isSameDocumentTarget(s1o, s1), "different section treated as identical")
            chk(!isSameDocumentTarget(root, s1), "root treated as identical to session")
        }
        return f
    }
    #endif
}
