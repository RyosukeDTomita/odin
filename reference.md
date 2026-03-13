# HTTP セキュリティヘッダ ベストプラクティス

> **参照元：**
> - [MDN Web Docs - HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
> - [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
> - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

---

## 1. CORS 関連ヘッダ

### `Access-Control-Allow-Origin`

**ベストプラクティス**
```http
# 特定オリジンを明示する
Access-Control-Allow-Origin: https://example.com
# 動的に許可する場合は Vary も必ずセット
Vary: Origin
# 公開リソース（認証情報なし）のみワイルドカード可
Access-Control-Allow-Origin: *
```

**NG例**
```http
# ❌ null を指定する（sandboxed iframe や data: URI から悪用可能）
Access-Control-Allow-Origin: null

# ❌ ワイルドカード + 認証情報（ブラウザがエラーになる）
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# ❌ Vary: Origin を省略（キャッシュポイズニングの原因）
Access-Control-Allow-Origin: https://example.com
# Vary ヘッダなし
```

> *MDN:* "Specifying the `null` value is discouraged. ... hostile documents can use the `null` origin to bypass access-control checks."

---

### `Access-Control-Allow-Credentials`

**ベストプラクティス**
```http
# 認証情報が本当に必要な場合のみ設定 + 特定オリジンとセットで使用
Access-Control-Allow-Origin: https://trusted-partner.com
Access-Control-Allow-Credentials: true
```

**NG例**
```http
# ❌ false にするなら省略すべき（混乱を招くだけ）
Access-Control-Allow-Credentials: false

# ❌ サーバー側でリクエストの Origin をそのまま反射（CSRF リスク）
# res.setHeader('Access-Control-Allow-Origin', req.headers.origin);  ← 要ホワイトリスト検証
# res.setHeader('Access-Control-Allow-Credentials', 'true');
```

> *MDN:* "When responding to a credentialed request, the server must specify an origin in the value of the `Access-Control-Allow-Origin` header, instead of specifying the `*` wildcard."

---

### `Access-Control-Allow-Methods` / `Access-Control-Allow-Headers`

**ベストプラクティス**
```http
# 必要なメソッド・ヘッダのみを許可する
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type, Authorization
```

**NG例**
```http
# ❌ 全メソッド・全ヘッダを許可（過剰な権限）
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
Access-Control-Allow-Headers: *
```

---

## 2. Cookie 属性

> *MDN Set-Cookie:* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie

### `Secure` 属性

```http
# ✅ HTTPS でのみ送信
Set-Cookie: session=abc; Secure

# ❌ Secure なし（HTTP でも平文送信される）
Set-Cookie: session=abc
```

### `HttpOnly` 属性

```http
# ✅ JS からアクセス不可（XSS 対策）
Set-Cookie: session=abc; HttpOnly

# ❌ HttpOnly なし（XSS で document.cookie から盗まれる）
Set-Cookie: session=abc
```

### `Expires` / `Max-Age`

```http
# ✅ Max-Age を優先（より信頼性が高い）
Set-Cookie: id=abc; Max-Age=86400

# ❌ 有効期限なし（ブラウザ再起動後も残り続けるセッションクッキーになる）
Set-Cookie: id=abc
```

> *MDN:* "If both `Expires` and `Max-Age` are set, `Max-Age` has precedence."

### `Path` 属性

```http
# ✅ 必要なパスのみに限定
Set-Cookie: id=abc; Path=/app

# ❌ Path はセキュリティ境界ではなくスコープの制御に過ぎない
#    不要に広い Path=/ のまま全パスに送信しない
```

### `Domain` 属性

```http
# ✅ サブドメイン間で共有が必要な場合のみ設定
Set-Cookie: id=abc; Domain=example.com
# → example.com, subdomain.example.com に送信される

# ❌ 不要に Domain を指定しない（省略すると発行元ホストのみに限定されより安全）
# ❌ 一致しないドメインの指定はブラウザに拒否される
Set-Cookie: id=abc; Domain=other-site.com
```

> *MDN:* "If omitted, the attribute defaults to the host of the current document URL, **not including subdomains**."

### `SameSite` 属性

| 値 | 動作 | 用途 |
|---|---|---|
| `Strict` | 同一サイトのリクエストのみ送信 | 最高の CSRF 対策 |
| `Lax` | 同一サイト + トップレベルナビゲーションの GET | デフォルト推奨 |
| `None` | すべてのリクエストで送信 | 要 `Secure` |

```http
# ✅ セッションクッキーの推奨設定
Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax

# ✅ クロスサイト（例：埋め込み決済）が必要な場合
Set-Cookie: id=abc; SameSite=None; Secure

# ❌ SameSite=None なのに Secure がない（近代ブラウザは拒否）
Set-Cookie: id=abc; SameSite=None
```

### Cookie プレフィックス（推奨）

```http
# ✅ __Secure-: Secure 必須
Set-Cookie: __Secure-ID=123; Secure; Domain=example.com

# ✅ __Host-: Secure + Path=/ + Domain 指定なし（最も厳格）
Set-Cookie: __Host-ID=123; Secure; Path=/

# ❌ __Host- なのに Domain を指定（無効）
Set-Cookie: __Host-ID=123; Secure; Path=/; Domain=example.com
```

---

## 3. `X-Content-Type-Options`

> *MDN:* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options

```http
# ✅ nosniff のみが有効な値（MIME スニッフィング防止）
X-Content-Type-Options: nosniff

# ❌ ヘッダなし（ブラウザが Content-Type を無視して推測する）
# ❌ Content-Type が正しくないのに nosniff を付ける
#    → script/style リクエストがブロックされる
```

> *MDN:* "Blocks a request if the request destination is of type `style` and the MIME type is not `text/css`, or of type `script` and the MIME type is not a JavaScript MIME type."

---

## 4. `Strict-Transport-Security` (HSTS)

> *MDN:* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

```http
# ✅ 推奨設定（preload リスト登録要件を満たす）
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

# ✅ 最小限の安全設定
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**NG例**
```http
# ❌ max-age が短すぎる（保護期間が短い）
Strict-Transport-Security: max-age=3600

# ❌ includeSubDomains がない（サブドメインが保護されない）
Strict-Transport-Security: max-age=31536000

# ❌ HTTP レスポンスで送信（ブラウザは無視する）
# ❌ preload だけあって includeSubDomains がない（preload リスト要件違反）
Strict-Transport-Security: max-age=31536000; preload
```

> *MDN:* "The browser should access this server only using HTTPS for the `max-age` seconds. ... The `preload` directive is not part of the specification. ... Requires `includeSubDomains`."

**初回リクエスト問題：** 最初の HTTP リクエストは保護されない。[HSTS Preload List](https://hstspreload.org/) への登録で回避できる。

---

## 5. `X-Frame-Options` / CSP `frame-ancestors`

> *MDN:* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

```http
# ✅ 最も安全（完全にフレーム埋め込みを禁止）
X-Frame-Options: DENY

# ✅ 同一オリジンのみ許可
X-Frame-Options: SAMEORIGIN

# ✅ 現代的な代替（CSP frame-ancestors を優先すべき）
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self' https://trusted.com;
```

**NG例**
```http
# ❌ ALLOW-FROM は廃止済み（現代ブラウザは無視）
X-Frame-Options: ALLOW-FROM https://trusted.com

# ❌ <meta> タグでの指定は無効（HTTP ヘッダとしてのみ有効）
# <meta http-equiv="X-Frame-Options" content="DENY">  ← 効果なし
```

> *MDN:* "The added security is only provided if the user accessing the document is using a browser that supports `X-Frame-Options`. ... Use `Content-Security-Policy: frame-ancestors` instead."

---

## 6. `Referrer-Policy`

> *MDN:* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy

| ポリシー値 | 送信内容 | 推奨度 |
|---|---|---|
| `no-referrer` | 送信しない | プライバシー最優先 |
| `strict-origin` | オリジンのみ（HTTPS→HTTP は送信しない） | 推奨 |
| `strict-origin-when-cross-origin` | 同一オリジン: フルURL / クロスオリジン: オリジンのみ | **デフォルト推奨** |
| `same-origin` | 同一オリジンのみフルURL | 内部アナリティクス向け |
| `no-referrer-when-downgrade` | HTTPS→HTTP 以外はフルURL | 旧デフォルト・非推奨 |
| `unsafe-url` | 常にフルURL | **絶対NG** |

```http
# ✅ 一般的なウェブサイト向け推奨
Referrer-Policy: strict-origin-when-cross-origin

# ❌ URL にクエリパラメータやトークンが含まれる場合に危険
Referrer-Policy: unsafe-url
```

> *MDN:* "The `unsafe-url` policy ... leaks potentially-private information from HTTPS resource URLs to insecure origins."

---

## 7. `Permissions-Policy`

> *MDN:* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy

```http
# ✅ 不要なブラウザ機能を無効化（最小権限の原則）
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()

# ✅ 自オリジンのみ許可
Permissions-Policy: geolocation=(self)

# ✅ 特定の信頼済みパートナーにのみ許可
Permissions-Policy: camera=(self "https://trusted-partner.com")
```

**NG例**
```http
# ❌ 機密性の高い API を全オリジンに開放
Permissions-Policy: camera=*, microphone=*, geolocation=*

# ❌ ヘッダで geolocation=() なのに iframe で allow="geolocation"
#    → ヘッダ側が優先されるため iframe 設定は無効
```

> *MDN:* "A `frame-ancestors` header restriction takes precedence; the iframe attribute policy is ineffective."

---

## まとめ：セキュアな設定例

```http
# CORS（認証情報あり）
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type, Authorization
Vary: Origin

# セッションクッキー
Set-Cookie: __Host-session=abc; Secure; HttpOnly; SameSite=Lax; Path=/

# セキュリティヘッダ
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: frame-ancestors 'none'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

> **検証ツール：** [Mozilla HTTP Observatory](https://observatory.mozilla.org/) で設定が適切かスコアリング可能。
