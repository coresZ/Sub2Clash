import argparse
import base64
import json
import sys
import tempfile
from pathlib import Path

import requests
import urllib3

from apex.apk_keys import ApkKeyError, extract_aes_key_candidates, extract_mtls_profiles, write_mtls_profiles
from apex.apxs import ApxsError, decrypt_to_yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATHS = ("/apos/fl_apex.json", "/saos/apos/fl_apex.json")

# APK 内置的 5 个源带 `-ax.` 中缀，那批已下线（404 / 证书过期 / 500）；
# 去掉中缀后同一台服务器仍在服务，且返回同一份配置。
CONFIG_SOURCES = (
    "https://cdno01.llguanglisf.com",
    "https://apisa.cnossfile.com",
    "https://tcdn.getxlx.com",
    "https://18.136.251.9",
)

SUBSCRIBE_PATH_KEY = "/api/v1/client/subscribe?token="
DEFAULT_SUBSCRIBE_PATH = "/v2/feed/download?access_key="
DEFAULT_VERSION = "7.2.3"


class Apex:
    def __init__(self, username, password, apk_path: str, abi: str = "arm64-v8a"):
        self.username = username.strip()
        self.password = password
        self.apk_path = apk_path
        self.abi = abi

        self.profiles = None
        self.keyCandidates = None
        self.config = None
        self.version = DEFAULT_VERSION
        self.apiUrls = []
        self.subUrls = []
        self.subscribePath = DEFAULT_SUBSCRIBE_PATH
        self.configSource = None
        self.loginData = None
        self.authData = None
        self.accessKey = None
        self.xboardUserSubInfo = None
        self.subData = None
        self.apxsHeader = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        pass

    @property
    def headers(self):
        # UA 必须小写：大写会被 Cloudflare 拦成 403
        return {"User-Agent": f"apex/{self.version}"}

    def apexSession(self, purpose):
        """requests 只接受证书文件路径，所以把 PEM 落到临时目录。"""
        profile = self.profiles.get(purpose)
        if profile is None:
            raise ApkKeyError(f"APK 缺少 {purpose} 证书，现有: {sorted(self.profiles)}")
        tmpdir = Path(tempfile.mkdtemp(prefix="apex-mtls-"))
        cert = tmpdir / "client.crt"
        key = tmpdir / "client.key"
        cert.write_text(profile.cert_pem, encoding="ascii")
        key.write_text(profile.key_pem, encoding="ascii")
        session = requests.Session()
        session.cert = (str(cert), str(key))
        session.verify = False
        return session, tmpdir

    @staticmethod
    def apexDropSession(session, tmpdir):
        session.close()
        for p in tmpdir.iterdir():
            p.unlink(missing_ok=True)
        try:
            tmpdir.rmdir()
        except OSError:
            pass

    def apexLoadKeyMaterial(self):
        self.profiles = extract_mtls_profiles(self.apk_path, self.abi)
        self.keyCandidates = extract_aes_key_candidates(self.apk_path, self.abi)
        print(f"mTLS 证书: {', '.join(sorted(self.profiles))}")
        print(f"密钥候选: {len(self.keyCandidates)} 个")

    def apexGetConfig(self):
        for base in CONFIG_SOURCES:
            for path in CONFIG_PATHS:
                url = base.rstrip("/") + path
                try:
                    with requests.get(url, headers=self.headers, timeout=15, verify=False) as response:
                        if response.status_code != 200:
                            continue
                        payload = response.json().get("payload")
                        if not payload:
                            continue
                        config = json.loads(base64.b64decode(payload))
                except (requests.RequestException, ValueError, TypeError):
                    continue

                api_urls = [d.rstrip("/") for d in config.get("domains") or [] if d]
                if not api_urls:
                    continue
                latest = ((config.get("update") or {}).get("latest") or {}).get("android") or {}
                self.config = config
                self.version = str(latest.get("version") or DEFAULT_VERSION)
                self.apiUrls = api_urls
                self.subUrls = [d.rstrip("/") for d in config.get("subscribe_domain") or [] if d] or api_urls
                self.subscribePath = (config.get("subscribe_path") or {}).get(
                    SUBSCRIBE_PATH_KEY, DEFAULT_SUBSCRIBE_PATH
                )
                self.configSource = url
                return True
        return False

    def apexLogin(self):
        errors = []
        for base in self.apiUrls:
            session, tmpdir = self.apexSession("api")
            try:
                response = session.post(
                    url=f"{base}/v2/auth/token",
                    headers=self.headers,
                    data={"email": self.username, "password": self.password},
                    timeout=25,
                )
            except requests.RequestException as e:
                errors.append(f"{base}: {type(e).__name__}")
                continue
            finally:
                self.apexDropSession(session, tmpdir)

            if response.status_code != 200:
                errors.append(f"{base}: 状态码 {response.status_code}")
                continue
            self.loginData = response.json()
            data = self.loginData.get("data") or {}
            self.authData = data.get("auth_data")
            self.accessKey = data.get("token")
            if not self.authData or not self.accessKey:
                errors.append(f"{base}: 返回缺少 auth_data/token")
                continue
            return True
        raise RuntimeError("登录失败，状态码: " + "; ".join(errors[:4]))

    def apexGetUserSubInfo(self):
        errors = []
        for base in self.apiUrls:
            session, tmpdir = self.apexSession("api")
            try:
                response = session.get(
                    url=f"{base}/v2/feed/access-token",
                    headers={
                        **self.headers,
                        "authorization": f"{self.authData}"
                    },
                    timeout=25,
                )
            except requests.RequestException as e:
                errors.append(f"{base}: {type(e).__name__}")
                continue
            finally:
                self.apexDropSession(session, tmpdir)

            if response.status_code != 200:
                errors.append(f"{base}: 状态码 {response.status_code}")
                continue
            self.xboardUserSubInfo = response.json()
            return True
        raise RuntimeError("获取订阅信息失败: " + "; ".join(errors[:4]))

    def apexDownload(self):
        sep = "" if self.subscribePath.endswith(("=", "?", "&")) else "="
        errors = []
        for base in self.subUrls:
            url = f"{base}{self.subscribePath}{sep}{self.accessKey}"
            session, tmpdir = self.apexSession("subscription")
            try:
                response = session.get(url=url, headers=self.headers, timeout=25)
            except requests.RequestException as e:
                errors.append(f"{base}: {type(e).__name__}")
                continue
            finally:
                self.apexDropSession(session, tmpdir)

            if response.status_code != 200:
                errors.append(f"{base}: 状态码 {response.status_code}")
                continue
            if not response.content.startswith(b"APXS"):
                errors.append(f"{base}: 不是 APXS 数据 ({response.content[:8]!r})")
                continue
            self.subData, _, self.apxsHeader = decrypt_to_yaml(response.content, self.keyCandidates)
            return True
        raise RuntimeError("下载订阅失败: " + "; ".join(errors[:4]))

    def apexGetSubData(self) -> bool:
        try:
            self.apexLoadKeyMaterial()
            print("获取配置文件......")
            if not self.apexGetConfig():
                print("没找到可用的配置文件源")
                return False
            print(f"配置文件来源: {self.configSource}")
            print(f'\n登录API: {self.apiUrls[0]}\n订阅API: {self.subUrls[0]}\n平台版本: apex/{self.version}\n')
            print("登录中......")
            self.apexLogin()
            print('登录成功！！！！！！')
            print("获取订阅链接!!!!")
            self.apexGetUserSubInfo()
            self.apexDownload()
        except (ApkKeyError, ApxsError, RuntimeError) as e:
            print(f"apex处理失败: {e}")
            return False

        header = self.apxsHeader or {}
        print(f"""
APXS v{header.get('version')} keyId={header.get('key_id')} encVersion={header.get('enc_version')}
订阅内容: 


{self.subData}
""")
        return True


def main(argv):
    ap = argparse.ArgumentParser(description="从 Apex/Speed 客户端 APK 获取 APXS v2 订阅")
    ap.add_argument("apk", nargs="?", default="flapp-speed.apk", help="path to APK")
    ap.add_argument("--email", default="", help="panel login email")
    ap.add_argument("--password", default="", help="panel login password")
    ap.add_argument("--abi", default="arm64-v8a", help="APK ABI, default: arm64-v8a")
    ap.add_argument("--dump-certs", metavar="DIR", default=None, help="export mTLS certs to DIR")
    ap.add_argument("--out", default=None, help="write subscription yaml to this file")
    args = ap.parse_args(argv)

    if args.dump_certs:
        profiles = extract_mtls_profiles(args.apk, args.abi)
        written = write_mtls_profiles(profiles, args.dump_certs)
        for purpose, (cert, key) in written.items():
            print(f"      {purpose:<13} {cert.name}  {key.name}")
        if not args.email:
            return

    with Apex(username=args.email, password=args.password, apk_path=args.apk, abi=args.abi) as apex:
        if apex.apexGetSubData() and args.out:
            Path(args.out).write_text(apex.subData, encoding="utf-8")
            print(f"已写入: {args.out}")


if __name__ == "__main__":
    main(sys.argv[1:])
