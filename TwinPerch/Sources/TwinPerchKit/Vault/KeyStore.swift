import CryptoKit
import Foundation
import Security

/// 密钥存取抽象。真实实现用 Keychain；测试用内存实现。
public protocol KeyStore: AnyObject {
    func save(label: String, data: Data) throws
    func load(label: String) throws -> Data?
    func delete(label: String) throws
}

/// Keychain 实现：WhenUnlocked + ThisDeviceOnly（不进备份、不迁移）。
public final class KeychainKeyStore: KeyStore {
    private let service: String

    public init(service: String = "app.twinperch.vault") {
        self.service = service
    }

    public func save(label: String, data: Data) throws {
        var query = baseQuery(label: label)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            try update(label: label, data: data)
        } else if status != errSecSuccess {
            throw VaultError.keychainFailure(status)
        }
    }

    public func load(label: String) throws -> Data? {
        var query = baseQuery(label: label)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw VaultError.keychainFailure(status) }
        return result as? Data
    }

    public func delete(label: String) throws {
        let status = SecItemDelete(baseQuery(label: label) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultError.keychainFailure(status)
        }
    }

    private func update(label: String, data: Data) throws {
        let update = [kSecValueData as String: data] as CFDictionary
        let status = SecItemUpdate(baseQuery(label: label) as CFDictionary, update)
        guard status == errSecSuccess else { throw VaultError.keychainFailure(status) }
    }

    private func baseQuery(label: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
        ]
    }
}

/// 内存实现（测试）。
public final class InMemoryKeyStore: KeyStore {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func save(label: String, data: Data) throws {
        lock.lock(); defer { lock.unlock() }
        storage[label] = data
    }

    public func load(label: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return storage[label]
    }

    public func delete(label: String) throws {
        lock.lock(); defer { lock.unlock() }
        storage.removeValue(forKey: label)
    }
}
