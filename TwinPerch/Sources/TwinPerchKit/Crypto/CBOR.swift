import Foundation

/// 最小 CBOR 子集（RFC 8949）：map / uint / text / bytes，仅覆盖消息载荷所需。
/// 与 Python 参考实现的编码输出逐字节一致（确定性编码：固定键序按出现顺序）。
public enum CBOR {
    indirect public enum Value {
        case uint(UInt64)
        case text(String)
        case bytes(Data)
    }

    // MARK: - 编码

    public static func encode(_ pairs: [(String, Value)]) -> Data {
        var out = Data()
        appendHead(&out, major: 5, value: UInt64(pairs.count))
        for (k, v) in pairs {
            appendText(&out, k)
            appendValue(&out, v)
        }
        return out
    }

    public static func encodeMap(_ dict: [String: Value]) -> Data {
        // 固定按键的 UTF-8 字节序排序，保证跨实现确定性
        let keys = dict.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        var pairs: [(String, Value)] = []
        for k in keys { pairs.append((k, dict[k]!)) }
        return encode(pairs)
    }

    private static func appendValue(_ out: inout Data, _ v: Value) {
        switch v {
        case .uint(let n): appendHead(&out, major: 0, value: n)
        case .bytes(let d):
            appendHead(&out, major: 2, value: UInt64(d.count))
            out.append(d)
        case .text(let s): appendText(&out, s)
        }
    }

    private static func appendText(_ out: inout Data, _ s: String) {
        let d = Data(s.utf8)
        appendHead(&out, major: 3, value: UInt64(d.count))
        out.append(d)
    }

    private static func appendHead(_ out: inout Data, major: UInt8, value: UInt64) {
        let m = major << 5
        switch value {
        case ..<24:
            out.append(m | UInt8(value))
        case ..<0x100:
            out.append(m | 24); out.append(UInt8(value))
        case ..<0x10000:
            out.append(m | 25)
            out.append(UInt8((value >> 8) & 0xff)); out.append(UInt8(value & 0xff))
        case ..<0x1_0000_0000:
            out.append(m | 26)
            for shift in stride(from: 24, through: 0, by: -8) { out.append(UInt8((value >> UInt64(shift)) & 0xff)) }
        default:
            out.append(m | 27)
            for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((value >> UInt64(shift)) & 0xff)) }
        }
    }

    // MARK: - 解码

    public static func decodeMap(_ data: Data) throws -> [String: Value] {
        var reader = Reader(data: data)
        let v = try reader.readValue()
        guard case .map(let map) = v else { throw TPError.invalidInput }
        return map
    }

    fileprivate enum RawValue {
        case uint(UInt64), text(String), bytes(Data), map([String: Value])
    }

    fileprivate struct Reader {
        let data: Data
        var pos = 0

        mutating func readValue() throws -> RawValue {
            guard pos < data.count else { throw TPError.invalidInput }
            let head = data[data.startIndex + pos]
            pos += 1
            let major = head >> 5
            let info = head & 0x1f
            switch major {
            case 0:
                return .uint(try readArgument(info))
            case 2:
                let n = try readArgument(info)
                guard Int(n) <= data.count - pos else { throw TPError.invalidInput }
                let d = TP.slice(data, pos..<(pos + Int(n)))
                pos += Int(n)
                return .bytes(d)
            case 3:
                let n = try readArgument(info)
                guard Int(n) <= data.count - pos else { throw TPError.invalidInput }
                let d = TP.slice(data, pos..<(pos + Int(n)))
                pos += Int(n)
                guard let s = String(data: d, encoding: .utf8) else { throw TPError.invalidInput }
                return .text(s)
            case 5:
                let n = try readArgument(info)
                var map = [String: Value]()
                for _ in 0..<n {
                    guard case .text(let k) = try readValue() else { throw TPError.invalidInput }
                    let v = try readValue()
                    switch v {
                    case .uint(let u): map[k] = .uint(u)
                    case .text(let t): map[k] = .text(t)
                    case .bytes(let b): map[k] = .bytes(b)
                    case .map: throw TPError.invalidInput
                    }
                }
                return .map(map)
            default:
                throw TPError.invalidInput
            }
        }

        mutating func readArgument(_ info: UInt8) throws -> UInt64 {
            switch info {
            case ..<24: return UInt64(info)
            case 24:
                guard pos < data.count else { throw TPError.invalidInput }
                let v = UInt64(data[data.startIndex + pos]); pos += 1
                return v
            case 25:
                guard pos + 2 <= data.count else { throw TPError.invalidInput }
                var v: UInt64 = 0
                for i in 0..<2 { v = (v << 8) | UInt64(data[data.startIndex + pos + i]) }
                pos += 2
                return v
            case 26:
                guard pos + 4 <= data.count else { throw TPError.invalidInput }
                var v: UInt64 = 0
                for i in 0..<4 { v = (v << 8) | UInt64(data[data.startIndex + pos + i]) }
                pos += 4
                return v
            case 27:
                guard pos + 8 <= data.count else { throw TPError.invalidInput }
                var v: UInt64 = 0
                for i in 0..<8 { v = (v << 8) | UInt64(data[data.startIndex + pos + i]) }
                pos += 8
                return v
            default:
                throw TPError.invalidInput
            }
        }
    }
}
