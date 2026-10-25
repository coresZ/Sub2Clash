"""APXS v2 订阅正文解密。

容器格式（实测于 com.flapp.clients.apex 7.2.3）：

    offset  len   field
    0       4     b"APXS"
    4       1     0x02             version
    5       4     u32 BE           keyId        （查表索引，非密钥）
    9       4     u32 BE           encVersion
    13      12    nonce
    25      N     AES-256-GCM 密文
    25+N    80    尾部（16B 校验 + 64B 签名，不含在 YAML 正文内）

密钥由打包机器人以 base64 常量注入 libapp.so，见 apex.apk_keys。

正文本身是一份完整的 Clash/mihomo YAML，切掉尾部 80 字节后是纯 UTF-8。
"""

from __future__ import annotations

import codecs
import re

from Crypto.Cipher import AES

MAGIC = b"APXS"
HEADER_LEN = 13
NONCE_LEN = 12
TRAILER_LEN = 80  # 16B 校验 + 64B 签名，不含在 YAML 正文内
SUPPORTED_VERSIONS = (2,)


class ApxsError(Exception):
    """容器格式不符或解密失败。"""


def parse_header(blob: bytes) -> dict:
    if len(blob) < HEADER_LEN:
        raise ApxsError(f"blob too short: {len(blob)} bytes")
    if blob[:4] != MAGIC:
        raise ApxsError(f"bad magic: {blob[:4]!r} (expected {MAGIC!r})")
    version = blob[4]
    if version not in SUPPORTED_VERSIONS:
        raise ApxsError(f"unsupported APXS version: {version}")
    return {
        "version": version,
        "key_id": int.from_bytes(blob[5:9], "big"),
        "enc_version": int.from_bytes(blob[9:13], "big"),
    }


def _yaml_end(plaintext: bytes) -> int:
    """返回 UTF-8 有效前缀长度。

    正文是 YAML，尾部跟着一段二进制残留；用增量解码器找第一个非法字节的位置，
    比逐字节 try/except 快，也不会在多字节字符中间误判。
    """
    decoder = codecs.getincrementaldecoder("utf-8")()
    valid = 0
    step = 8192
    for start in range(0, len(plaintext), step):
        chunk = plaintext[start : start + step]
        try:
            decoder.decode(chunk)
        except UnicodeDecodeError as exc:
            return start + exc.start
        valid = start + len(chunk)
    return valid


def decrypt(blob: bytes, key: bytes) -> tuple[bytes, dict]:
    """返回 (明文字节, 头部信息)。

    尾部 80 字节是校验+签名，不参与正文，先切掉再解密。
    """
    header = parse_header(blob)
    if len(key) != 32:
        raise ApxsError(f"AES-256 key must be 32 bytes, got {len(key)}")
    body = blob[HEADER_LEN:]
    if len(body) <= NONCE_LEN + TRAILER_LEN:
        raise ApxsError(f"body too short: {len(body)} bytes")

    nonce = body[:NONCE_LEN]
    ciphertext = body[NONCE_LEN:-TRAILER_LEN]
    trailer = body[-TRAILER_LEN:]

    plaintext = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt(ciphertext)

    header["trailer_len"] = len(trailer)
    header["plaintext_len"] = len(plaintext)
    return plaintext, header


def looks_like_clash(plaintext: bytes) -> bool:
    head = plaintext[:16384]
    return (
        b"mixed-port:" in head
        or b"proxy-groups:" in head
        or re.search(rb"^proxies:", head, re.MULTILINE) is not None
    )


def decrypt_to_yaml(blob: bytes, key_candidates: list[bytes]) -> tuple[str, bytes, dict]:
    """用候选密钥依次尝试，返回 (yaml 文本, 命中密钥, 头部信息)。

    密钥有 29 个同长度候选（其余是无关常量），判定标准是明文像 Clash 配置。
    """
    errors: list[str] = []
    for key in key_candidates:
        try:
            plaintext, header = decrypt(blob, key)
        except ApxsError as exc:
            errors.append(str(exc))
            continue
        if not looks_like_clash(plaintext):
            continue
        end = _yaml_end(plaintext)
        try:
            text = plaintext[:end].decode("utf-8")
        except UnicodeDecodeError:
            continue
        header["residue_len"] = len(plaintext) - end
        return text, key, header
    raise ApxsError(
        "no candidate key produced a Clash config"
        + (f" ({'; '.join(errors[:3])})" if errors else "")
    )
