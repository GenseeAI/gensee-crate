import XCTest

final class HarnessActivationGuidanceTests: XCTestCase {
    func testUnverifiedHarnessStatusExplainsTheNextAction() {
        func integration(id: String) -> IntegrationDescriptor {
            IntegrationDescriptor(
                id: id,
                name: id,
                detail: "",
                configPath: "",
                symbolName: "terminal",
                installed: true,
                supportsDirectHooks: true,
                installationDetail: "",
                configurationIssue: nil,
                configurationNote: nil,
                canRepair: true,
                configuredBackendPath: nil,
                configured: true,
                verified: false
            )
        }

        XCTAssertEqual(integration(id: "codex").statusLabel, "Review hook & test")
        XCTAssertEqual(integration(id: "claude-code").statusLabel, "Restart & test")
    }

    func testProviderEventsMatchTheirHarness() {
        XCTAssertTrue(HarnessActivationGuidance.eventMatches(provider: "codex", source: "codex"))
        XCTAssertTrue(HarnessActivationGuidance.eventMatches(provider: "claude-code", source: "claude"))
        XCTAssertTrue(HarnessActivationGuidance.eventMatches(provider: "vscode", source: "github-copilot"))
        XCTAssertFalse(HarnessActivationGuidance.eventMatches(provider: "codex", source: "claude-code"))
    }

    func testCodexGuidanceUsesCLITrustFlow() {
        let instruction = HarnessActivationGuidance.instruction(for: "codex")
        XCTAssertTrue(instruction.detail.contains("/hooks"))
        XCTAssertTrue(instruction.detail.contains("ChatGPT app"))
        XCTAssertEqual(instruction.actionTitle, "Open Codex Hook Review")
    }

    func testOmnigentExplainsManagedLaunch() {
        let instruction = HarnessActivationGuidance.instruction(for: "omnigent")
        XCTAssertTrue(instruction.detail.contains("gensee run"))
        XCTAssertEqual(instruction.actionTitle, "Copy Managed Launch")
    }

    func testCodexResolverPrefersBundledApplicationBeforeCommandLineWrappers() {
        let home = URL(fileURLWithPath: "/Users/example")
        let application = URL(fileURLWithPath: "/Applications/ChatGPT.app")
        let candidates = CodexExecutableResolver.orderedCandidates(
            home: home,
            applicationURLs: [application]
        )

        XCTAssertEqual(
            candidates.first?.path,
            "/Applications/ChatGPT.app/Contents/Resources/codex"
        )
        XCTAssertLessThan(
            candidates.firstIndex(of: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex"))!,
            candidates.firstIndex(of: URL(fileURLWithPath: "/usr/local/bin/codex"))!
        )
    }

    func testCodexResolverSkipsAnExecutableThatFailsItsLaunchProbe() {
        let broken = URL(fileURLWithPath: "/usr/local/bin/codex")
        let working = URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex")

        XCTAssertEqual(
            CodexExecutableResolver.firstRunnable(candidates: [broken, working]) {
                $0 == working
            },
            working
        )
    }

    func testCodexHookReviewClosesOnlyItsOriginatingTerminalAfterTrustChanges() {
        let script = CodexHookReviewScript.render(
            codexURL: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex")
        )

        XCTAssertTrue(script.contains("current_checksum\" != \"$initial_checksum"))
        XCTAssertTrue(script.contains("hooks_are_trusted"))
        XCTAssertTrue(script.contains("gensee hook codex"))
        XCTAssertTrue(script.contains("if tty of terminalTab is targetTTY"))
        XCTAssertTrue(script.contains("return \"not-found\""))
        XCTAssertFalse(script.contains("close front window"))
    }

    func testCodexHookReviewUsesCodexHomeForConfigAndHooks() {
        let script = CodexHookReviewScript.render(
            codexURL: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex")
        )

        XCTAssertTrue(script.contains("codex_home=\"${CODEX_HOME:-$HOME/.codex}\""))
        XCTAssertTrue(script.contains("config_path=\"$codex_home/config.toml\""))
        XCTAssertTrue(script.contains("hooks_path=\"$codex_home/hooks.json\""))
    }

    func testCodexHookReviewKeepsSecureMarkerAndUsesSentinel() {
        let script = CodexHookReviewScript.render(
            codexURL: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex")
        )

        XCTAssertTrue(script.contains("printf 'approved\\n' > \"$approval_marker\""))
        XCTAssertTrue(script.contains("if [[ -s \"$approval_marker\" ]]"))
        XCTAssertFalse(script.contains("mktemp -t gensee-codex-hook-review)\n        /bin/rm"))
    }

    func testCodexReviewLauncherRunsInTerminalWithoutWritingACommandFile() {
        let command = CodexHookReviewScript.shellCommand(
            codexURL: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex")
        )
        let source = CodexHookReviewLauncher.appleScriptSource(shellCommand: command)

        XCTAssertTrue(command.contains("/usr/bin/base64 -D | /bin/zsh"))
        XCTAssertTrue(source.contains("tell application \"Terminal\""))
        XCTAssertTrue(source.contains("do script"))
        XCTAssertFalse(source.contains("review-codex-hooks.command"))
    }

    func testCodexReviewLauncherRecognizesAutomationPermissionFailures() {
        for errorNumber in [-1743, -1744] {
            XCTAssertTrue(CodexHookReviewLauncher.isAutomationPermissionError([
                "NSAppleScriptErrorNumber": NSNumber(value: errorNumber),
            ]))
        }
        XCTAssertFalse(CodexHookReviewLauncher.isAutomationPermissionError([
            "NSAppleScriptErrorNumber": NSNumber(value: -1708),
        ]))
        XCTAssertFalse(CodexHookReviewLauncher.isAutomationPermissionError(nil))
    }

    func testCodexVersionProbeTimesOut() throws {
        let executable = FileManager.default.temporaryDirectory
            .appendingPathComponent("gensee-codex-probe-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: executable) }
        try "#!/bin/sh\nexec /bin/sleep 5\n".write(to: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

        let started = Date()
        XCTAssertFalse(CodexExecutableResolver.respondsToVersionProbe(executable, timeout: 0.1))
        XCTAssertLessThan(Date().timeIntervalSince(started), 1.5)
    }

    func testCodexHookReviewScriptHasValidZshSyntax() throws {
        let script = CodexHookReviewScript.render(
            codexURL: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex")
        )
        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("gensee-codex-review-\(UUID().uuidString).command")
        defer { try? FileManager.default.removeItem(at: scriptURL) }
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-n", scriptURL.path]
        try process.run()
        process.waitUntilExit()

        XCTAssertEqual(process.terminationStatus, 0)
    }
}
