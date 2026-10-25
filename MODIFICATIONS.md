# MODIFICATIONS

按目录分节记录本仓库的改动（功能 → 修改内容 → 涉及文件与位置）。

---

## main.py

### 2026-10-25 · 接入 apex 处理流程

**功能**：`com.flapp.clients.apex` 这类客户端的订阅正文是 APXS v2 容器加密，原
xboard 链路（`/api/v1/client/subscribe`）只能拿到 SSPanel-Malio 兼容层的替代节点，
不是真节点。新增 `apex/` 包走真链路，`main.py` 只做接入。

**修改内容**（`main.py` 共 9 行）：

- 第 3 行：`from apex.getinfo import Apex`
- `run()` 中 `.apk` 分支之后、`getAppConfigUrl()` 之前插入 apex 尝试块：
  `with Apex(...) as apex: if apex.apexGetSubData(): return`，异常吞掉后继续原有流程

原有 xboard / flclash 逻辑一行未改。

**验证**：

```text
匹配到apex处理流程......
mTLS 证书: api, oss, subscription
密钥候选: 29 个
获取配置文件......
配置文件来源: https://cdno01.llguanglisf.com/apos/fl_apex.json

登录API: https://flaxapi.web.ak005.com
订阅API: https://flaxsub.web.ak005.com
平台版本: apex/7.2.3

登录中......
登录成功！！！！！！
```

错误密码时打印 `apex处理失败: 登录失败，状态码: ... 400` 后正常回落到原流程，不抛栈。

---

## apex/

### 2026-10-25 · 新增 apex 包

按 `xboard/` 的组织方式：`getinfo.py` 放主类与 `main(argv)`，其余模块放工具函数，
`__init__.py` 留空。

| 文件 | 内容 |
|---|---|
| `apex/__init__.py` | 空文件（与原仓库 `xboard/`、`flclash/` 一致） |
| `apex/getinfo.py` | `Apex` 类（`apexGetConfig` / `apexLogin` / `apexGetUserSubInfo` / `apexDownload` / `apexGetSubData`）+ `main(argv)` |
| `apex/apk_keys.py` | `extract_mtls_profiles()` / `extract_aes_key_candidates()` / `write_mtls_profiles()` |
| `apex/apxs.py` | `parse_header()` / `decrypt()` / `decrypt_to_yaml()` |

`Apex` 接口对齐 `Xboard`：同样的 `__enter__` / `__exit__` / `close()`，
同样的 `apexGetSubData()` 一站式入口，同样在结尾打印订阅正文。

### 链路

```text
1. GET  {cdn}/apos/fl_apex.json              UA: apex/<version>        无需证书
   -> {"format":"apex-config-v1","payload":"<base64 JSON>","signature":"..."}
   -> payload: {domains, subscribe_domain, subscribe_path, panel_type, ...}

2. POST {api_base}/v2/auth/token             UA: apex/<version>  + mTLS(api)
   form: email, password
   -> {"data":{"auth_data":"<JWT>", "token":"<access_key>"}}

3. GET  {sub_base}/v2/feed/download?access_key=<access_key>
                                             UA: apex/<version>  + mTLS(subscription)
   -> APXS v2 密文

4. AES-256-GCM 解密 -> Clash YAML
```

### 两个必须同时满足的开关

| 条件 | 结果 |
|---|---|
| 无 mTLS 客户端证书 | `404` nginx 默认页（连 vhost 都没进） |
| 有证书 + UA `Apex/7.2.3`（大写） | `403` Cloudflare 拦截页 |
| 有证书 + UA `apex/7.2.3`（**小写**） | `200` 应用层 JSON |

证书用错也是 404：`api` 证书只能打 `flaxapi.*`，`subscription` 证书只能打 `flaxsub.*`。

### APXS v2 容器格式

```text
offset  len   field
0       4     "APXS"
4       1     0x02             version
5       4     u32 BE           keyId        （查表索引，非密钥）
9       4     u32 BE           encVersion
13      12    nonce
25      N     AES-256-GCM 密文
25+N    80    尾部（16B 校验 + 64B 签名，不含在 YAML 正文内）
```

### 密钥材料来源

两类材料都以 base64 常量形式躺在 `libapp.so` 的 Dart AOT 字符串池里，
`apex/apk_keys.py` 按内容特征扫描，不依赖固定偏移：

| 材料 | 形态 | 用途 |
|---|---|---|
| mTLS 证书 | `base64(JSON{version, profile_id, purpose, client_cert_pem, client_key_pem})`，`purpose` ∈ `api`/`oss`/`subscription` | 双向 TLS 客户端认证 |
| APXS 密钥 | `base64(32 字节)` | AES-256-GCM 解订阅正文 |

APK 里同时存在 29 个 32 字节 base64 常量，只有一个是真密钥。`decrypt_to_yaml()`
逐个尝试，以「明文像 Clash 配置」判定，不依赖 GCM tag 校验（该服务端 tag 位置与
常规 `nonce|ct|tag` 布局不吻合，校验会误杀正确密钥）。

### 内置 CDN 源

APK 里硬编码的 5 个源带 `-ax.` 中缀，那批已下线（404 / 证书过期 / 500）。去掉中缀后
同一台服务器仍在服务，且返回同一份配置（sha256 一致）：

```text
https://cdno01.llguanglisf.com/apos/fl_apex.json   200
https://apisa.cnossfile.com/apos/fl_apex.json      200
https://tcdn.getxlx.com/apos/fl_apex.json          200
```

### 独立运行

```bash
uv run python -m apex.getinfo flapp-speed.apk --email you@example.com --password '...' --out sub.yaml
uv run python -m apex.getinfo flapp-speed.apk --dump-certs certs
```

### 验证

```text
proxies 74  groups 3  rules 14
types {'vless': 74}
servers 1   uuids 1   ports 10101-10200
```

三次独立拉取节点列表完全一致。对照 v1 兼容层：134 节点（vmess×97 + ss×37），
59 个公网 IP，`uuid` 只有 2 个，响应首行写着「本接口为SSPanel-Malio兼容层」——是替代品。

### 已知取舍

- APXS 尾部 80 字节（16B 校验 + 64B 签名）未解析，直接切掉；不影响 YAML 完整性。
- 只测了 `arm64-v8a`；`armeabi-v7a` 能提到 `api`/`oss` 两套证书，**没有
  `subscription`**，走不通订阅。
- 只在当前这一个面板验证过，其他面板的 `subscribe_path` 映射可能不同（代码读配置里
  的映射，不硬编码）。
