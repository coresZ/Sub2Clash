"""从 APK 的 libapp.so 中提取 Apex/Speed 客户端所需的密钥材料。

两类材料都以 base64 常量的形式躺在 Dart AOT 的字符串池里：

  mTLS 客户端证书  base64(JSON{version, profile_id, purpose,
                              client_cert_pem, client_key_pem})
                   purpose ∈ {api, oss, subscription}
  APXS 会话密钥    base64(32 字节) —— 用于 AES-256-GCM 解订阅正文

不依赖固定偏移：全部按内容特征扫描，换版本也能用。
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

DEFAULT_ABI = "arm64-v8a"
APP_SO_CANDIDATES = ("libapp.so",)

_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{16,8192}={0,2}")


class ApkKeyError(Exception):
    """APK 内未找到所需密钥材料。"""


@dataclass(frozen=True)
class MtlsProfile:
    purpose: str
    cert_pem: str
    key_pem: str
    profile_id: int | None = None


def _read_libapp(apk_path: str, abi: str) -> bytes:
    member = f"lib/{abi}/libapp.so"
    try:
        with zipfile.ZipFile(apk_path) as z:
            names = set(z.namelist())
            if member in names:
                return z.read(member)
            available = sorted(n for n in names if n.endswith("/libapp.so"))
    except FileNotFoundError as exc:
        raise ApkKeyError(f"APK not found: {apk_path}") from exc
    except zipfile.BadZipFile as exc:
        raise ApkKeyError(f"not a valid APK/zip: {apk_path}") from exc
    except OSError as exc:
        raise ApkKeyError(f"cannot read {apk_path}: {exc}") from exc
    raise ApkKeyError(
        f"{member} not found in APK. Available libapp.so entries: "
        + (", ".join(available) if available else "<none>")
    )


def _iter_b64_decoded(data: bytes, min_len: int) -> Iterable[tuple[int, bytes]]:
    """遍历文件里所有能解出 >= min_len 字节的 base64 串。"""
    seen: set[bytes] = set()
    for m in _B64_RUN.finditer(data):
        raw = m.group(0)
        if len(raw) < 24:
            continue
        padded = raw + b"=" * (-len(raw) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < min_len or decoded in seen:
            continue
        seen.add(decoded)
        yield m.start(), decoded


def extract_mtls_profiles(apk_path: str, abi: str = DEFAULT_ABI) -> dict[str, MtlsProfile]:
    """返回 {purpose: MtlsProfile}，通常是 api / oss / subscription 三套。"""
    data = _read_libapp(apk_path, abi)
    profiles: dict[str, MtlsProfile] = {}
    for _, decoded in _iter_b64_decoded(data, min_len=512):
        if b"client_cert_pem" not in decoded:
            continue
        try:
            obj = json.loads(decoded)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(obj, dict):
            continue
        purpose = obj.get("purpose")
        cert = obj.get("client_cert_pem")
        key = obj.get("client_key_pem")
        if not isinstance(purpose, str) or not isinstance(cert, str) or not isinstance(key, str):
            continue
        profiles.setdefault(
            purpose,
            MtlsProfile(
                purpose=purpose,
                cert_pem=cert,
                key_pem=key,
                profile_id=obj.get("profile_id"),
            ),
        )
    if not profiles:
        raise ApkKeyError(
            "no mTLS client certificate found in libapp.so "
            "(expected base64(JSON) containing client_cert_pem / client_key_pem)"
        )
    return profiles


def extract_aes_key_candidates(apk_path: str, abi: str = DEFAULT_ABI) -> list[bytes]:
    """返回所有 32 字节的 base64 常量，按出现顺序。

    Apex 把会话密钥作为 base64 字符串常量编进 libapp.so；同一个文件里通常还有
    一两个长度相同的无关常量，所以这里返回候选列表，由调用方用 GCM 解密结果
    自证（能解出 Clash YAML 的那个就是对的）。
    """
    data = _read_libapp(apk_path, abi)
    out: list[bytes] = []
    for _, decoded in _iter_b64_decoded(data, min_len=32):
        if len(decoded) == 32 and decoded not in out:
            out.append(decoded)
    if not out:
        raise ApkKeyError("no 32-byte base64 constant found in libapp.so")
    return out


def write_mtls_profiles(
    profiles: dict[str, MtlsProfile],
    out_dir: str | Path,
    purposes: Iterable[str] | None = None,
) -> dict[str, tuple[Path, Path]]:
    """把 mTLS 证书落成 PEM 文件，返回 {purpose: (cert_path, key_path)}。

    文件名固定为 `<purpose>.crt` / `<purpose>.key`，可直接喂给 curl
    (`--cert` / `--key`) 或其他需要文件路径的工具。
    """
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    wanted = set(purposes) if purposes is not None else set(profiles)
    written: dict[str, tuple[Path, Path]] = {}
    for purpose in sorted(wanted & set(profiles)):
        profile = profiles[purpose]
        cert_path = target / f"{purpose}.crt"
        key_path = target / f"{purpose}.key"
        cert_path.write_text(profile.cert_pem, encoding="ascii")
        key_path.write_text(profile.key_pem, encoding="ascii")
        written[purpose] = (cert_path, key_path)
    return written

