#!/usr/bin/env python3
"""TP-Crypt v1 Python 参考实现（零依赖）。

与 TwinPerch/Sources/TwinPerchKit 的 Swift 实现逐字节对齐：
- X25519: RFC 7748 纯 Python 实现
- AEAD:   RFC 8439 ChaCha20-Poly1305 纯 Python 实现
- KDF:    HKDF-SHA256 / HMAC-SHA256（hashlib）
- Envelope/CBOR: 与 Swift Envelope.swift / CBOR.swift 一致
- 握手/棘轮: 与 Handshake.swift / Ratchet.swift 一致
"""

import hashlib
import hmac
import json
import struct

# ---------------------------------------------------------------- 原语

P = 2**255 - 19
A24 = 121665


def _cswap(swap, x2, x3):
    return (x3, x2) if swap else (x2, x3)


def x25519(scalar: bytes, u: bytes) -> bytes:
    """RFC 7748 标量乘法（内部钳位）。"""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(bytes(k), "little")
    u = bytearray(u)
    u[31] &= 127
    x1 = int.from_bytes(bytes(u), "little") % P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t
        A = (x2 + z2) % P
        AA = A * A % P
        B = (x2 - z2) % P
        BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = D * A % P
        CB = C * B % P
        x3 = pow(DA + CB, 2, P)
        z3 = x1 * pow(DA - CB, 2, P) % P
        x2 = AA * BB % P
        z2 = E * (AA + A24 * E) % P
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def _priv_pub(priv: bytes) -> bytes:
    return x25519(priv, bytes([9]) + bytes(31))  # u=9 基点（32 字节编码）


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(ikm: bytes, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


# ChaCha20（RFC 8439 §2.3）

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = ((s[d] << 16) | (s[d] >> 16)) & 0xFFFFFFFF
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = ((s[b] << 12) | (s[b] >> 20)) & 0xFFFFFFFF
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = ((s[d] << 8) | (s[d] >> 24)) & 0xFFFFFFFF
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = ((s[b] << 7) | (s[b] >> 25)) & 0xFFFFFFFF


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    consts = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    kw = list(struct.unpack("<8I", key))
    nw = list(struct.unpack("<3I", nonce))
    state = consts + kw + [counter] + nw
    working = list(state)
    for _ in range(10):
        _qr(working, 0, 4, 8, 12)
        _qr(working, 1, 5, 9, 13)
        _qr(working, 2, 6, 10, 14)
        _qr(working, 3, 7, 11, 15)
        _qr(working, 0, 5, 10, 15)
        _qr(working, 1, 6, 11, 12)
        _qr(working, 2, 7, 8, 13)
        _qr(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def _chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for block in range((len(data) + 63) // 64):
        ks = _chacha20_block(key, counter + block, nonce)
        chunk = data[block * 64:(block + 1) * 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _poly1305(key: bytes, data: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"\x00" * ((16 - len(data) % 16) % 16)


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """RFC 8439 AEAD：返回 ciphertext ‖ tag(16)，与 CryptoKit ChaChaPoly.combined 一致。"""
    ct = _chacha20_xor(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    pk = _chacha20_block(key, 0, nonce)[:32]
    tag = _poly1305(pk, mac_data)
    return ct + tag


def aead_open(key: bytes, nonce: bytes, combined: bytes, aad: bytes) -> bytes:
    ct, tag = combined[:-16], combined[-16:]
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    pk = _chacha20_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(tag, _poly1305(pk, mac_data)):
        raise ValueError("auth failed")
    return _chacha20_xor(key, 1, nonce, ct)


# ---------------------------------------------------------------- CBOR（与 Swift CBOR.swift 一致）

def _head(major: int, value: int) -> bytes:
    m = major << 5
    if value < 24:
        return bytes([m | value])
    if value < 0x100:
        return bytes([m | 24, value])
    if value < 0x10000:
        return bytes([m | 25]) + value.to_bytes(2, "big")
    if value < 0x1_0000_0000:
        return bytes([m | 26]) + value.to_bytes(4, "big")
    return bytes([m | 27]) + value.to_bytes(8, "big")


def cbor_encode_map(d: dict) -> bytes:
    out = _head(5, len(d))
    for k in sorted(d.keys(), key=lambda s: s.encode("utf-8")):
        kb = k.encode("utf-8")
        out += _head(3, len(kb)) + kb
        v = d[k]
        if isinstance(v, int):
            out += _head(0, v)
        elif isinstance(v, str):
            vb = v.encode("utf-8")
            out += _head(3, len(vb)) + vb
        else:
            out += _head(2, len(v)) + v
    return out


# ---------------------------------------------------------------- 常量（与 Swift TP 对应）

INFO_MASTER = b"TP-crypt-v1"
INFO_ROOT = b"root"
INFO_STEP = b"root-step"
INFO_CHAIN_A = b"chain-a"
INFO_CHAIN_B = b"chain-b"
INFO_ROOM_AUTH = b"room-auth"
INFO_ROOM_ID = b"room-id"
INFO_CONFIRM = b"confirm"

SKIPPED_KEY_CAP = 4096
RATCHET_STEP_MESSAGES = 500


# ---------------------------------------------------------------- Envelope

KIND_TEXT, KIND_MANIFEST, KIND_ACK, KIND_READ, KIND_SYNC, KIND_NOTICE = 0, 1, 3, 4, 5, 6


def envelope_encode(kind, dh_step, chain_index, session_id, ek_pub, root_fp, nonce, ct):
    out = bytes([1, kind]) + struct.pack("<H", dh_step) + struct.pack("<Q", chain_index)
    out += session_id + ek_pub + root_fp + nonce + struct.pack("<I", len(ct)) + ct
    return out


def envelope_aad(version, kind, dh_step, chain_index, session_id, ek_pub, root_fp, nonce):
    return (bytes([1, kind]) + struct.pack("<H", dh_step) + struct.pack("<Q", chain_index)
            + session_id + ek_pub + root_fp + nonce)


def envelope_decode(data: bytes):
    assert data[0] == 1
    kind = data[1]
    dh_step = struct.unpack("<H", data[2:4])[0]
    chain_index = struct.unpack("<Q", data[4:12])[0]
    session_id = data[12:28]
    ek_pub = data[28:60]
    root_fp = data[60:64]
    nonce = data[64:76]
    ct_len = struct.unpack("<I", data[76:80])[0]
    assert len(data) == 80 + ct_len
    ct = data[80:]
    return kind, dh_step, chain_index, session_id, ek_pub, root_fp, nonce, ct


# ---------------------------------------------------------------- 握手

def handshake(is_initiator: bool, ik_priv: bytes, ek_priv: bytes, peer_ik_pub: bytes,
              peer_ek_pub: bytes, session_id: bytes, my_nonce: bytes, peer_nonce: bytes):
    d1 = x25519(ik_priv, peer_ik_pub)
    if is_initiator:
        d2 = x25519(ik_priv, peer_ek_pub)
        d3 = x25519(ek_priv, peer_ik_pub)
    else:
        d2 = x25519(ek_priv, peer_ik_pub)
        d3 = x25519(ik_priv, peer_ek_pub)
    d4 = x25519(ek_priv, peer_ek_pub)
    salt = (my_nonce + peer_nonce) if is_initiator else (peer_nonce + my_nonce)
    master = hkdf(d1 + d2 + d3 + d4, salt, INFO_MASTER)
    root = hkdf(master, info=INFO_ROOT)
    seed_a = hkdf(master, info=INFO_CHAIN_A)
    seed_b = hkdf(master, info=INFO_CHAIN_B)
    k_room = hkdf(master, info=INFO_ROOM_AUTH)
    room_id = hkdf(master, info=INFO_ROOM_ID, length=16)
    k_confirm = hkdf(master, info=INFO_CONFIRM)
    init_pub = _priv_pub(ik_priv) if is_initiator else peer_ik_pub
    resp_pub = peer_ik_pub if is_initiator else _priv_pub(ik_priv)
    safety = sha256(init_pub + resp_pub)[:8].hex()
    return {
        "master": master, "root": root,
        "seed_a": seed_a, "seed_b": seed_b,
        "k_room": k_room, "room_id": room_id, "k_confirm": k_confirm,
        "safety": safety,
    }


# ---------------------------------------------------------------- 棘轮

class RefRatchet:
    """与 Swift Ratchet 一致的状态机。step_eks 提供确定性临时密钥序列。"""

    def __init__(self, is_initiator, ik_priv, peer_ik_pub, k_confirm, root, my_seed, peer_seed,
                 step_eks):
        self.is_initiator = is_initiator
        self.ik_priv = ik_priv
        self.peer_ik_pub = peer_ik_pub
        self.k_confirm = k_confirm
        self.root = root
        self.send_key = my_seed
        self.send_index = 0
        self.send_dh_step = 0
        self.recv_key = peer_seed
        self.recv_index = 0
        self.recv_dh_step = 0
        self.skipped = {}  # (step, index) -> mk
        self.messages_since_step = 0
        self.resync_pending = False
        self.step_requested = False
        self.step_eks = list(step_eks)
        self.step_ek_idx = 0
        self.step_ek_pub = None   # 本 dh_step 的临时公钥：随本步每条消息头携带（与 Swift 一致）

    def _should_step(self):
        if self.resync_pending:
            return False
        if not (self.is_initiator or self.step_requested):
            return False
        return self.messages_since_step >= RATCHET_STEP_MESSAGES or self.step_requested

    def _perform_step(self):
        ek = self.step_eks[self.step_ek_idx]
        self.step_ek_idx += 1
        dh_out = x25519(ek, self.peer_ik_pub)
        new_root = hkdf(dh_out, self.root, INFO_STEP)
        seed = hkdf(new_root, info=(INFO_CHAIN_A if self.is_initiator else INFO_CHAIN_B))
        self.root = new_root
        self.send_key = seed
        self.send_index = 0
        self.send_dh_step = (self.send_dh_step + 1) & 0xFFFF
        self.messages_since_step = 0
        self.step_requested = False
        self.step_ek_pub = _priv_pub(ek)
        return self.step_ek_pub

    def root_fp(self):
        return hmac_sha256(self.k_confirm, self.root)[:4]

    def next_message_keys(self):
        if self._should_step():
            _ = self._perform_step()
        ek_pub = self.step_ek_pub   # 非 step 0 期间恒带；step 0 时为 None
        k1 = hmac_sha256(self.send_key, b"\x01")
        mk = hmac_sha256(k1, b"\x02" + struct.pack("<Q", self.send_index))
        idx = self.send_index
        self.send_key = k1
        self.send_index += 1
        self.messages_since_step += 1
        return mk, self.send_dh_step, idx, ek_pub, self.root_fp()

    def _mk_for_current(self, env_index):
        if env_index >= self.recv_index:
            gap = env_index - self.recv_index
            if len(self.skipped) + gap > SKIPPED_KEY_CAP:
                raise OverflowError("skipped store overflow")
            key = self.recv_key
            for i in range(self.recv_index, env_index):
                k1 = hmac_sha256(key, b"\x01")
                self.skipped[(self.recv_dh_step, i)] = hmac_sha256(k1, b"\x02" + struct.pack("<Q", i))
                key = k1
            k1 = hmac_sha256(key, b"\x01")
            mk = hmac_sha256(k1, b"\x02" + struct.pack("<Q", env_index))
            self.recv_key = k1
            self.recv_index = env_index + 1
            return mk, False
        else:
            if (self.recv_dh_step, env_index) not in self.skipped:
                raise KeyError("unknown chain index")
            return self.skipped[(self.recv_dh_step, env_index)], True

    def message_key(self, kind, dh_step, chain_index, ek_pub, root_fp):
        from_step = False
        if dh_step > self.recv_dh_step:
            if ek_pub == bytes(32):
                raise ValueError("step carrier without ek")
            dh_out = x25519(self.ik_priv, ek_pub)
            new_root = hkdf(dh_out, self.root, INFO_STEP)
            if root_fp != hmac_sha256(self.k_confirm, new_root)[:4]:
                raise ValueError("session desync")
            # 步进方是对端：对端是发起方 → 其发送链是 chain-a；否则 chain-b
            stepper_info = INFO_CHAIN_B if self.is_initiator else INFO_CHAIN_A
            self.root = new_root
            self.recv_key = hkdf(new_root, info=stepper_info)
            self.recv_index = 0
            self.recv_dh_step = dh_step
            self.resync_pending = False
        elif dh_step == self.recv_dh_step:
            if root_fp != hmac_sha256(self.k_confirm, self.root)[:4]:
                raise ValueError("session desync")
        mk, from_step = self._mk_for_current(chain_index)
        return mk, from_step

    def consume_skipped(self, dh_step, index):
        self.skipped.pop((dh_step, index), None)


# ---------------------------------------------------------------- 会话级封装（生成向量用）

def seal_message(ratchet: RefRatchet, session_id: bytes, kind: int, payload: dict) -> bytes:
    mk, dh_step, idx, ek_pub, root_fp = ratchet.next_message_keys()
    enc_key = hmac_sha256(mk, b"enc")[:32]
    nonce = hmac_sha256(mk, b"nonce")[:12]
    pt = cbor_encode_map(payload)
    aad = envelope_aad(1, kind, dh_step, idx, session_id,
                       ek_pub if ek_pub else bytes(32), root_fp, nonce)
    ct = aead_seal(enc_key, nonce, pt, aad)
    return envelope_encode(kind, dh_step, idx, session_id,
                           ek_pub if ek_pub else bytes(32), root_fp, nonce, ct)


def open_message(ratchet: RefRatchet, session_id: bytes, env: bytes) -> dict:
    kind, dh_step, idx, sid, ek_pub, root_fp, nonce, ct = envelope_decode(env)
    assert sid == session_id
    mk, from_step = ratchet.message_key(kind, dh_step, idx, ek_pub, root_fp)
    enc_key = hmac_sha256(mk, b"enc")[:32]
    aad = envelope_aad(1, kind, dh_step, idx, sid, ek_pub, root_fp, nonce)
    pt = aead_open(enc_key, nonce, ct, aad)
    if from_step:
        ratchet.consume_skipped(dh_step, idx)
    # 解码 CBOR 载荷（仅所需子集）
    return _cbor_decode_map(pt)


def _cbor_decode_map(data: bytes) -> dict:
    assert data[0] >> 5 == 5
    n = data[0] & 0x1F
    pos = 1
    if n >= 24:
        width = {24: 1, 25: 2, 26: 4, 27: 8}[n]
        n = int.from_bytes(data[pos:pos + width], "big")
        pos += width
    out = {}
    for _ in range(n):
        k, pos = _cbor_value(data, pos)
        v, pos = _cbor_value(data, pos)
        out[k] = v
    return out


def _cbor_head(data: bytes, pos: int):
    head = data[pos]
    pos += 1
    major, info = head >> 5, head & 0x1F
    if info < 24:
        return major, info, pos
    width = {24: 1, 25: 2, 26: 4, 27: 8}[info]
    return major, int.from_bytes(data[pos:pos + width], "big"), pos + width


def _cbor_value(data: bytes, pos: int):
    major, val, pos = _cbor_head(data, pos)
    if major == 0:
        return val, pos
    if major == 2:
        return data[pos:pos + val], pos + val
    if major == 3:
        return data[pos:pos + val].decode("utf-8"), pos + val
    raise ValueError("unsupported major type")


# ---------------------------------------------------------------- 自检（RFC 标准向量）

def _self_test():
    # RFC 7748 §6.1（共享秘密；公钥断言由 Swift 侧交叉覆盖）
    assert x25519(bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
                  bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")) == \
        bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    # RFC 8439 §2.8.2 AEAD
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = b"Ladies and Gentlemen of the class of '99: If I could offer you " \
         b"only one tip for the future, sunscreen would be it."
    ct = aead_seal(key, nonce, pt, aad)
    assert ct[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691"
    assert aead_open(key, nonce, ct, aad) == pt
    # RFC 8439 §2.4.2 chacha20 block
    blk = _chacha20_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000"))
    assert blk.hex().startswith("10f1e7e4")   # RFC 8439 §2.4.2 keystream 首字节序
    print("python ref self-test ok")


if __name__ == "__main__":
    _self_test()
