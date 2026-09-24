import Foundation
import Network
import os.log

private let logger = Logger(subsystem: "com.tgwsproxy.app", category: "ProxyServer")

@available(iOS 17.0, *)
final class MTProtoProxyServer {
    private let config: ProxyConfig
    private var listener: NWListener?
    private var statsCallback: ((ProxyStats) -> Void)?
    private let statsActor = StatsActor()

    init(config: ProxyConfig, statsCallback: ((ProxyStats) -> Void)? = nil) {
        self.config = config
        self.statsCallback = statsCallback
    }

    func start() async throws {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true

        let params = NWParameters(tls: nil, tcp: tcpOptions)

        let port = NWEndpoint.Port(rawValue: UInt16(config.port))!
        listener = try NWListener(using: params, on: port)

        listener?.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            Task { await self.handleNewConnection(connection) }
        }

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            listener?.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.listener?.stateUpdateHandler = nil
                    Task { @MainActor in
                        LogStore.shared.log("Proxy listening on port \(self?.config.port ?? 0)", tag: "SERVER")
                    }
                    cont.resume()
                case .failed(let error):
                    self?.listener?.stateUpdateHandler = nil
                    Task { @MainActor in
                        LogStore.shared.log("Listener failed: \(error)", tag: "SERVER")
                    }
                    cont.resume(throwing: error)
                case .cancelled:
                    self?.listener?.stateUpdateHandler = nil
                    cont.resume(throwing: CancellationError())
                default:
                    break
                }
            }
            listener?.start(queue: DispatchQueue.global(qos: .userInitiated))
        }

        // Периодическая статистика
        Task {
            while listener != nil {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                let currentStats = await statsActor.getStats()
                statsCallback?(currentStats)
            }
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    private func handleNewConnection(_ connection: NWConnection) async {
        connection.start(queue: DispatchQueue.global(qos: .userInitiated))
        await statsActor.update { $0.connectionsTotal += 1 }
        await statsActor.update { $0.connectionsActive += 1 }
        Task { @MainActor in
            LogStore.shared.log("New client connection", tag: "SERVER")
        }

        defer {
            Task {
                await statsActor.update { $0.connectionsActive -= 1 }
            }
            if connection.state != .cancelled {
                connection.cancel()
            }
        }

        do {
            try await processClient(connection)
        } catch {
            Task { @MainActor in
                LogStore.shared.log("Client error: \(error)", tag: "SERVER")
            }
        }
    }

    private func processClient(_ connection: NWConnection) async throws {
        try await waitForReady(connection)

        let handshakeData = try await receiveExact(connection, count: HANDSHAKE_LEN)
        let handshake = [UInt8](handshakeData)

        let secretBytes = hexToBytes(config.secret)
        guard let result = tryHandshake(handshake, secret: secretBytes) else {
            await statsActor.update { $0.connectionsBad += 1 }
            Task { @MainActor in
                LogStore.shared.log("Bad handshake (wrong secret)", tag: "SERVER")
            }
            _ = try? await receiveData(connection, maxLength: 4096)
            return
        }

        let dcIdx = result.isMedia ? -result.dcId : result.dcId
        let relayInit = generateRelayInit(protoTag: result.protoTag, dcIdx: dcIdx)

        let cltDecPrekey = Array(result.clientDecPrekeyIV[0..<PREKEY_LEN])
        let cltDecIV = Array(result.clientDecPrekeyIV[PREKEY_LEN...])
        let cltDecKey = sha256(cltDecPrekey + secretBytes)
        let cltEncPrekeyIV = Array(result.clientDecPrekeyIV.reversed())
        let cltEncKey = sha256(Array(cltEncPrekeyIV[0..<PREKEY_LEN]) + secretBytes)
        let cltEncIV = Array(cltEncPrekeyIV[PREKEY_LEN...])

        let cltDecryptor = AESCTR(key: cltDecKey, iv: cltDecIV)
        let cltEncryptor = AESCTR(key: cltEncKey, iv: cltEncIV)
        _ = cltDecryptor.process(ZERO_64)

        let relayEncKey = Array(relayInit[SKIP_LEN ..< SKIP_LEN + PREKEY_LEN])
        let relayEncIV = Array(relayInit[SKIP_LEN + PREKEY_LEN ..< SKIP_LEN + PREKEY_LEN + IV_LEN])
        let relayDecPrekeyIV = Array(relayInit[SKIP_LEN ..< SKIP_LEN + PREKEY_LEN + IV_LEN].reversed())
        let relayDecKey = Array(relayDecPrekeyIV[0..<KEY_LEN])
        let relayDecIV = Array(relayDecPrekeyIV[KEY_LEN...])
        let tgEncryptor = AESCTR(key: relayEncKey, iv: relayEncIV)
        let tgDecryptor = AESCTR(key: relayDecKey, iv: relayDecIV)
        _ = tgEncryptor.process(ZERO_64)

        let mediaTag = result.isMedia ? "m" : ""
        Task { @MainActor in
            LogStore.shared.log("Handshake OK: DC\(result.dcId)\(mediaTag)", tag: "MT")
        }

        guard let targetIP = config.dcRedirects[result.dcId] else {
            if let fallbackIP = ProxyConfig.dcDefaultIPs[result.dcId] {
                Task { @MainActor in
                    LogStore.shared.log("DC\(result.dcId) not in config → TCP fallback \(fallbackIP)", tag: "MT")
                }
                try await tcpFallback(
                    connection: connection, dst: fallbackIP, port: 443,
                    relayInit: relayInit,
                    cltDecryptor: cltDecryptor, cltEncryptor: cltEncryptor,
                    tgEncryptor: tgEncryptor, tgDecryptor: tgDecryptor
                )
            }
            return
        }

        var ws: RawWebSocket? = nil

        // 1. Cloudflare Worker
        if !self.config.cfWorkerDomain.isEmpty {
            let workerDomain = self.config.cfWorkerDomain
            Task { @MainActor in
                LogStore.shared.log("DC\(result.dcId)\(mediaTag) → trying Worker \(workerDomain) for \(targetIP)", tag: "WORKER")
            }
            do {
                let workerPath = "/apiws?dst=\(targetIP)&dc=\(result.dcId)"
                ws = try await RawWebSocket.connect(ip: workerDomain, domain: workerDomain, path: workerPath, timeout: 15)
                Task { @MainActor in
                    LogStore.shared.log("Worker connected for DC\(result.dcId)", tag: "WORKER")
                }
            } catch {
                Task { @MainActor in
                    LogStore.shared.log("Worker failed: \(error)", tag: "WORKER")
                }
            }
        }

        // 2. Прямой WS
        if ws == nil {
            let domains = wsDomains(dc: result.dcId, isMedia: result.isMedia, overrides: config.dcOverrides)
            for domain in domains {
                Task { @MainActor in
                    LogStore.shared.log("Trying direct WS wss://\(domain)/apiws", tag: "WS")
                }
                do {
                    ws = try await RawWebSocket.connect(ip: targetIP, domain: domain, timeout: 10)
                    break
                } catch {
                    Task { @MainActor in
                        LogStore.shared.log("Direct WS failed: \(error)", tag: "WS")
                    }
                }
            }
        }

        // 3. TCP fallback
        guard let activeWS = ws else {
            let fallbackIP = ProxyConfig.dcDefaultIPs[result.dcId] ?? targetIP
            Task { @MainActor in
                LogStore.shared.log("WS failed → TCP fallback \(fallbackIP)", tag: "TCP")
            }
            try await tcpFallback(
                connection: connection, dst: fallbackIP, port: 443,
                relayInit: relayInit,
                cltDecryptor: cltDecryptor, cltEncryptor: cltEncryptor,
                tgEncryptor: tgEncryptor, tgDecryptor: tgDecryptor
            )
            return
        }

        await statsActor.update { $0.connectionsWS += 1 }
        Task { @MainActor in
            LogStore.shared.log("Bridge started for DC\(result.dcId)", tag: "BRIDGE")
        }

        let splitter = MsgSplitter(relayInit: relayInit, protoInt: result.protoInt)
        try await activeWS.send(Data(relayInit))

        try await bridgeWSReencrypt(
            connection: connection, ws: activeWS,
            cltDecryptor: cltDecryptor, cltEncryptor: cltEncryptor,
            tgEncryptor: tgEncryptor, tgDecryptor: tgDecryptor,
            splitter: splitter
        )
    }

    // MARK: - Bridge WS

    private func bridgeWSReencrypt(
        connection: NWConnection, ws: RawWebSocket,
        cltDecryptor: AESCTR, cltEncryptor: AESCTR,
        tgEncryptor: AESCTR, tgDecryptor: AESCTR,
        splitter: MsgSplitter
    ) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [weak self] in
                guard let self else { return }
                do {
                    while true {
                        let chunk = try await self.receiveData(connection, maxLength: 65536)
                        guard !chunk.isEmpty else { break }
                        await self.statsActor.update { $0.bytesUp += UInt64(chunk.count) }
                        let plain = cltDecryptor.process(chunk)
                        let encrypted = tgEncryptor.process(plain)
                        let parts = splitter.split(encrypted)
                        if parts.isEmpty { continue }
                        if parts.count > 1 {
                            try await ws.sendBatch(parts)
                        } else {
                            try await ws.send(parts[0])
                        }
                    }
                } catch {
                    // Соединение закрылось — это нормально
                }
                await ws.close()
            }

            group.addTask { [weak self] in
                guard let self else { return }
                do {
                    while true {
                        guard let data = try await ws.recv() else { break }
                        await self.statsActor.update { $0.bytesDown += UInt64(data.count) }
                        let plain = tgDecryptor.process(data)
                        let encrypted = cltEncryptor.process(plain)
                        try await self.sendData(connection, data: encrypted)
                    }
                } catch {
                    // Соединение закрылось — это нормально
                }
                // connection.cancel() убран — закроется в handleNewConnection
            }

            // Ждём завершения ОБОИХ направлений, игнорируя ошибки
            try? await group.waitForAll()
        }
    }

    // MARK: - TCP Fallback

    private func tcpFallback(
        connection: NWConnection, dst: String, port: Int,
        relayInit: [UInt8],
        cltDecryptor: AESCTR, cltEncryptor: AESCTR,
        tgEncryptor: AESCTR, tgDecryptor: AESCTR
    ) async throws {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcpOptions)

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(dst),
            port: NWEndpoint.Port(rawValue: UInt16(port))!
        )
        let remote = NWConnection(to: endpoint, using: params)
        remote.start(queue: DispatchQueue.global(qos: .userInitiated))

        try await waitForReady(remote)

        try await sendData(remote, data: Data(relayInit))

        await statsActor.update { $0.connectionsTCPFallback += 1 }

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [weak self] in
                guard let self else { return }
                do {
                    while true {
                        let data = try await self.receiveData(connection, maxLength: 65536)
                        guard !data.isEmpty else { break }
                        await self.statsActor.update { $0.bytesUp += UInt64(data.count) }
                        let plain = cltDecryptor.process(data)
                        let enc = tgEncryptor.process(plain)
                        try await self.sendData(remote, data: enc)
                    }
                } catch {}
                // remote.cancel() убран
            }

            group.addTask { [weak self] in
                guard let self else { return }
                do {
                    while true {
                        let data = try await self.receiveData(remote, maxLength: 65536)
                        guard !data.isEmpty else { break }
                        await self.statsActor.update { $0.bytesDown += UInt64(data.count) }
                        let plain = tgDecryptor.process(data)
                        let enc = cltEncryptor.process(plain)
                        try await self.sendData(connection, data: enc)
                    }
                } catch {}
                // connection.cancel() убран
            }

            // Игнорируем ошибки, чтобы не пробрасывать наружу
            try? await group.waitForAll()
        }

        // Закрываем remote после завершения моста (безопасно)
        if remote.state != .cancelled {
            remote.cancel()
        }
    }

    // MARK: - NWConnection helpers

    private func waitForReady(_ connection: NWConnection) async throws {
        if connection.state == .ready { return }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.stateUpdateHandler = nil
                    cont.resume()
                case .failed(let error):
                    connection.stateUpdateHandler = nil
                    cont.resume(throwing: error)
                case .cancelled:
                    connection.stateUpdateHandler = nil
                    cont.resume(throwing: CancellationError())
                default:
                    break
                }
            }
        }
    }

    private func receiveExact(_ connection: NWConnection, count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error {
                    cont.resume(throwing: error)
                } else if let data, data.count == count {
                    cont.resume(returning: data)
                } else {
                    cont.resume(throwing: RawWebSocket.ConnectionError.closed)
                }
            }
        }
    }

    private func receiveData(_ connection: NWConnection, maxLength: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { data, _, isComplete, error in
                if let error {
                    cont.resume(throwing: error)
                } else if let data, !data.isEmpty {
                    cont.resume(returning: data)
                } else if isComplete {
                    cont.resume(returning: Data())
                } else {
                    cont.resume(throwing: RawWebSocket.ConnectionError.closed)
                }
            }
        }
    }

    private func sendData(_ connection: NWConnection, data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume()
                }
            })
        }
    }
}

// MARK: - Hex helpers

func hexToBytes(_ hex: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
        if let byte = UInt8(hex[index..<next], radix: 16) {
            bytes.append(byte)
        }
        index = next
    }
    return bytes
}

// MARK: - Stats Actor

@available(iOS 17.0, *)
actor StatsActor {
    private var stats = ProxyStats()

    func getStats() -> ProxyStats {
        return stats
    }

    func update(_ update: (inout ProxyStats) -> Void) {
        update(&stats)
    }
}
