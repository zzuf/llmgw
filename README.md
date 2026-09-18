# LLM Gateway

Apple Silicon Mac向けの、ローカルLLM用API Gatewayです。LM Studio、oMLX、mlx-serve／MLX系サーバーなどのAPIを、モデルalias、モデル単位ACL、APIキー、管理UI、ログ、統計のある1つのエンドポイントにまとめます。Gateway自身は推論しません。

Goの単一バイナリにWeb UIを埋め込んでいます。実行時にNode.js、Python、npm、SQLiteコマンドは不要です。

## 構成

```text
Client → :8080 /v1/* → IP AND API Key ACL → Public Alias
                                              ↓
                                      Native Engine Adapter
                                              ↓
                                    LM Studio / oMLX / MLX
         :8080 /admin/* → Session + CSRF → 管理・統計・バックアップ
                            ↓
                  SQLite WAL / JSONL / macOS Keychain
```

[architecture.md](architecture.md)、[DB設計](docs/database-schema.md)、[API設計](docs/api-design.md)に設計と制約を記載しています。

```text
cmd/llmgw/          CLI
internal/acl/      TCP接続元IPとAPIキーのAllow List
internal/app/      起動、停止、定期処理、listen変更、プロセスロック
internal/auth/     セッションとCSRF
internal/backup/   Snapshot、Portable Backup、安全な復元
internal/config/   ディレクトリと設定検証
internal/cryptoutil/ AES-GCM、Argon2id、乱数
internal/database/ 埋め込みmigrationとtransactional repository
internal/domain/   共通データ型
internal/engine/   Request解析、Adapter、Response/SSE正規化
internal/gateway/  公開API、管理API、UI配信
internal/keychain/ macOS Security.framework
internal/logging/  JSONL、rotation、SQLite統計、検索
internal/service/ User LaunchAgent
web/static/        HTML/CSS/JavaScript（go:embed）
scripts/check.sh   gofmt / vet / test
```

## Build

macOS Apple Silicon、Go 1.27.1以降、Apple Command Line Toolsが必要です。cgoはKeychainのネイティブAPIに使用します。SQLiteドライバはpure Goです。

```sh
xcode-select --install  # 未導入の場合のみ
go mod download
go build -trimpath -o bin/llmgw ./cmd/llmgw
./bin/llmgw version
```

生成される`bin/llmgw`はDarwin arm64の実行バイナリです。必要な共有ライブラリはmacOSのシステムライブラリだけです。`CGO_ENABLED=0`ではKeychainを利用できないため、サービスを起動できません。

ビルド時は`go`コマンドをPATHから実行できるようにしてください。ビルド済みの`bin/llmgw`はGoのインストールなしで実行できます。

## 起動と初回セットアップ

```sh
./bin/llmgw serve
# 開発用に保存先を分ける場合
./bin/llmgw serve --data-dir ./data --listen 127.0.0.1:8080
```

デフォルトは`0.0.0.0:8080`です。初回だけMac上のブラウザで[http://localhost:8080/setup](http://localhost:8080/setup)を開き、12文字以上のパスワードで管理者を作成します。初回管理者の横取り防止のため、setupはTCP接続元とHostの両方がlocalhostである必要があります。管理者が1人でも存在するとsetupは無効です。

以降は[http://localhost:8080/admin/](http://localhost:8080/admin/)へログインします。LANからは`http://mac-ip:8080/admin/`を使えます。すべての管理者は同じ権限を持ちます。セッションは24時間有効で、パスワード変更時にはその管理者の既存セッションが失効します。最後の管理者は削除できません。

最初の起動で、実行ユーザーのmacOS Keychainへマスターキーを保存します。Keychainがロックされている、アクセスが拒否されたなどの場合は起動に失敗します。OSがアクセス確認を表示した場合は、使用するバイナリを確認してください。ファイルや環境変数のマスターキーへ自動的に切り替える処理はありません。

## Engineとモデルの登録

1. **Engines**でName、Base URL、Type、認証方式を登録します。URL例は`http://192.168.1.50:1234/v1`です。URLへ秘密情報を埋め込まないでください。
2. 認証方式はNone、Bearer、x-api-keyに対応しています。この秘密情報はGatewayクライアント用キーとは別に暗号化されます。編集でSecretを空欄にすると現在値を保持します。
3. **Check / Sync**で上流のモデル一覧を取得します。定期チェックもモデル情報を更新します。
4. **Models**の未登録上流モデルからGatewayモデルを追加し、Public Alias（例：`qwen-fast`）を指定します。
5. Capability、ACL、Publishedを確認して保存します。発見しただけのモデルは公開されません。

モデルが上流から消えた場合はUnavailableになり、alias・ACL・公開設定を保持します。同じIDで再び現れればAvailableへ戻ります。通信失敗や不正なモデル一覧だけでは、モデルが消えたと判定しません。

EngineのOfflineはキャッシュされた監視状態です。利用可能として登録されているモデルへの実リクエストでは、Offlineであっても接続を1回試します。Engineを明示的にDisableした場合は転送しません。

Auto Detectはヘッダー／メタデータを使ったbest effortです。判別できない場合はGeneric OpenAIになります。Engine Type、モデルCapabilityを管理画面から明示的に上書きできます。モデルがあることだけからvision/toolsなどを推測して有効にしません。

## ACLとGateway APIキー

新規モデルのIP ACLは`127.0.0.1/32`と`::1/128`です。LANから利用する場合は、利用端末のIPまたはCIDRを追加します。

| Allowed IPs | Allowed API Keys | 条件 |
|---|---|---|
| 空 | 空 | 認証なし |
| 設定あり | 空 | IPが一致 |
| 空 | 設定あり | 有効なキーが一致 |
| 設定あり | 設定あり | IPとキーの両方が一致 |

IPv4、IPv6、CIDRに対応します。IPv4-mapped IPv6も正規化します。IP判定は`RemoteAddr`を使い、`X-Forwarded-For`や`X-Real-IP`を信頼しません。

**API Keys**でキーを作成し、名前・複数タグ・有効状態を管理します。**Models**で許可するキーを選びます。タグは分類用で、認可には使用しません。キーは一覧でマスクされ、Reveal操作だけで全文を表示します。この操作は監査ログに残ります。

APIキーACLのないモデルでは、`Authorization: Bearer dummy-key`でも、それを理由に拒否しません。ACLで参照中のキーは削除できません。先にモデルのACLを変更するか、キーをDisableしてください。空のACLが認証なしを意味するため、削除で意図せずモデルが公開されるのを防ぎます。

## API使用例

```sh
export LLMGW_API_KEY='管理画面で発行したキー'
curl http://localhost:8080/v1/models \
  -H "Authorization: Bearer $LLMGW_API_KEY"

curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $LLMGW_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen-fast","messages":[{"role":"user","content":"こんにちは"}]}'

curl -N http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $LLMGW_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen-fast","stream":true,"messages":[{"role":"user","content":"短い物語を書いて"}]}'

curl http://localhost:8080/v1/responses \
  -H "Authorization: Bearer $LLMGW_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen-fast","input":"要点を説明して"}'

curl http://localhost:8080/v1/embeddings \
  -H "Authorization: Bearer $LLMGW_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"local-embedding","input":"検索用の文章"}'
```

クライアント側でOpenAI Python SDKを使用する例です。PythonはGatewayの実行には必要ありません。

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url="http://mac-ip:8080/v1",
    api_key=os.environ["LLMGW_API_KEY"],
)
result = client.chat.completions.create(
    model="qwen-fast",
    messages=[{"role": "user", "content": "こんにちは"}],
)
print(result.choices[0].message.content)
```

正式なルートはmodels、responses、chat/completions、completions、embeddings、rerank、messagesです。POSTはすべて`model`にPublic Aliasを指定します。`/v1/messages`はAnthropic互換のネイティブMessages形式です。

レスポンス内のプロトコル上のmodelフィールドはPublic Aliasへ戻します。上流の認証キーはクライアントに渡さず、クライアントのGatewayキーも上流に転送しません。HTTPリダイレクトも追従しません。

意味を変えるChat→Responsesなどの変換は行いません。上流EngineとCapabilityが対応する機能だけを使用でき、未対応の場合は`unsupported_endpoint`または`unsupported_capability`を返します。エラーはOpenAI形式の`error.message/type/code`です。

### ブラウザからのアクセス（CORS）

公開APIの`/v1`と`/v1/*`は、すべてのOriginを`Access-Control-Allow-Origin: *`で許可します。別ホスト・別ポートのWebアプリからも利用でき、`OPTIONS`プリフライトには認証不要で204を返します。許可メソッドはGET／POST／OPTIONSです。`Authorization`、`Content-Type`、SDK独自ヘッダーなど、プリフライトで要求されたヘッダー名を許可します。通常レスポンス・エラー・SSEすべてに適用され、JavaScriptから`X-Request-ID`も読み取れます。

Cookieを使うクロスオリジン認証は許可しません。`fetch`では`credentials: 'omit'`を指定し、必要な場合はGateway APIキーをBearerヘッダーで送ってください。`apiKey`は利用者が入力したキーを渡します。

```javascript
async function chat(apiKey) {
  const response = await fetch('http://localhost:8080/v1/chat/completions', {
    method: 'POST',
    credentials: 'omit',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'qwen-fast',
      messages: [{ role: 'user', content: 'こんにちは' }],
    }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error.message);
  return result;
}
```

モデルのIP／APIキーACLは引き続き適用します。IP ACLが識別するのはブラウザの接続元IPで、WebサイトのOriginではありません。IP条件を満たす端末では、どのWebサイトからもAPIキー制限のないモデルを呼べます。キーを持つクライアントだけに限定する場合はモデルのAPIキーACLを設定してください。管理API・管理UI・setupには公開APIのCORS許可を適用せず、管理認証とCSRF保護を維持します。プリフライトもHTTPアクセスログとリクエスト統計に記録します。

ブラウザ側の制約は別途適用されます。HTTPSページからHTTP Gatewayへの接続は[混在コンテンツの制約](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content)で拒否される場合があります。[Chromeのローカルネットワークアクセス](https://developer.chrome.com/release-notes/142#local_network_access_restrictions)にはブラウザでの許可とsecure contextが必要な場合があり、CORS設定だけでこれらの制約を解除することはできません。

## 設定変更

Settingsから変更する値はSQLiteに保存されます。

| 設定 | デフォルト |
|---|---|
| Listen Address | `0.0.0.0:8080` |
| Health Check Interval | 30秒 |
| Request Timeout | 600秒（長いStreamingも含む） |
| Log Rotation Size | 100 MiB |
| Log Generations | 10 |
| Statistics Retention | 90日 |
| Backup Retention | 14日 |
| Automatic Backup | 有効、1日1回 |

変更は新しい処理から反映します。Listen変更時には先に新しいポートへbindできることを確認し、既存リクエストをdrainします。画面には新しいアドレスで再接続してください。保存先の変更とDB復元には再起動が必要です。

`--data-dir` > `LLMGW_DATA_DIR` > デフォルト保存先の順です。初回のlisten値は`--listen` > `LLMGW_LISTEN` > デフォルトです。2回目以降はDBのListen設定が優先されます。

## launchd

ログインユーザーのLaunchAgentとして登録します。root／sudoは使用しません。

```sh
./bin/llmgw install-service
# 保存先を分けて登録する場合
./bin/llmgw install-service --data-dir "$HOME/Library/Application Support/MyLLMGateway"

./bin/llmgw status
./bin/llmgw stop
./bin/llmgw start
./bin/llmgw uninstall-service
```

実行ファイルをデータディレクトリの`bin/llmgw`へコピーし、`~/Library/LaunchAgents/local.llmgw.gateway.plist`を生成してbootstrapします。ログイン時に自動起動します。ユーザーのログイン前に動くroot daemonではありません。1ユーザーにつき1つのLaunchAgentです。

初回からサービスを使う場合は、先にinstall-serviceで安定したバイナリのパスを決めてください。署名やバイナリを変更すると、macOSがKeychainへのアクセス確認を再表示する場合があります。アップグレード時はstop、uninstall-service、新バイナリのinstall-serviceの順で行います。アンインストールはDBやKeychainのキーを削除しません。

## Backup / Restore / Portable migration

管理画面のBackupsでCreate、Download、Restore、Deleteを操作できます。通常バックアップはSQLiteの一貫したsnapshotで、WALの確定済みデータを含みます。PromptのJSONLはDBバックアップに含みません。

通常バックアップ内の秘密情報は元のKeychainマスターキーで暗号化されたままです。**別Macへの移行には必ずPortable Backupを使用してください。**

Portableは12文字以上のpassphraseからArgon2idで鍵を導出し、DBと復号に必要なマスターキー全体をAES-GCMで暗号化します。passphraseを失うと復元できません。平文secretをarchiveへ書き出しません。

移行先のMacで起動・setup後、BackupsからPortableファイルをアップロードしてpassphraseを入力します。移行先Keychainのキーで秘密情報を再暗号化してから復元を準備します。サービスを再起動すると反映され、セッションはすべて失効します。移行元の管理者アカウントで再ログインしてください。

CLIでも実行できます。CLIのメンテナンス操作ではサービスを先に停止してください。同じデータディレクトリに対する多重実行はロックで拒否します。

```sh
./bin/llmgw stop
./bin/llmgw backup
./bin/llmgw backup --portable                 # passphraseを端末で非表示入力
./bin/llmgw restore --file /path/to/backup.llmgwb
./bin/llmgw start
```

非対話処理では`--passphrase-stdin`を使用できます。passphraseやパスワードをコマンド引数に指定する機能はありません。新しいMacの空のデータディレクトリへ、CLIから直接Portableを復元することもできます。

復元は認証・DB整合性・schema検証を通ったものだけを暗号化してstageし、開いているDBを直接上書きしません。適用前に現在のDBのrollbackバックアップを作成します。元DBが壊れている場合は、DBと関連ファイルを`backups/<id>.recovery/`へそのまま退避します。この緊急退避は通常の保持期限削除の対象外です。

通常の自動／手動バックアップは設定した保持日数に従い削除されます。移行用Portableファイルも保管が必要なら別の安全な場所へダウンロードしてください。Keychainキーを失った既存ディレクトリは勝手に新しいキーで上書きしません。Portableから別の新規データディレクトリへ復元してください。

管理者パスワードの復旧:

```sh
./bin/llmgw stop
./bin/llmgw admin reset-password --username admin
./bin/llmgw start
```

`--password-stdin`も使用できます。既存の管理者だけが対象です。

## LogsとStatistics

デフォルトの保存先は`~/Library/Application Support/LLMGateway/`です。

```text
llmgw.db                 SQLite設定・認証・統計・監査
logs/access.log          Promptを含む詳細JSONL
logs/access.log.*.gz     圧縮された過去のログ
logs/service.log         LaunchAgentの構造化診断ログ
backups/                 DBとPortableバックアップ
gateway.lock             多重実行防止
pending-restore.bin      暗号化された復元準備ファイル（ある場合）
```

アクセスログにはrequest ID、TCP接続元、キーID／名前／タグ、alias、上流モデル、Engine、endpoint、status、streaming、duration、TTFT、usageを記録します。キー全文は記録しません。上流エラーの診断は安全なHTTP status/codeを監査ログにも残します。上流の生エラー本文はクライアントに露出しません。

Promptはテキストを保存し、base64画像・音声・添付データを省略マーカーへ置き換えます。**通常のテキストPromptには機密情報が含まれ得ます。** JSONLは認証情報の暗号化とは別の保存物です。ファイル権限とMacのディスク保護、保存期間を適切に管理してください。

SQLiteにはPrompt全文を保存しません。詳細統計はデフォルト90日、日次集計はその後も保持します。Dashboardの「今日」と日別集計はUTC基準です。上流がusageを返さない場合はtoken数を推測せず0とし、Streamingでもusageイベントがある場合だけ記録します。TTFTは最初のdata eventまでの実測時間です。

## Test

```sh
sh scripts/check.sh
go test -race ./...
go test -cover ./...
```

httptestのMock Engineで、ACL、alias／availability、公開API、上流認証分離、JSON/SSE、timeout/error、管理認証／CSRF、暗号化、Portable移行、rotation／gzip、統計を検証します。Keychainのテストは注入したbackendを使用し、通常テストでユーザーの実Keychainを変更しません。

管理UIは実Gatewayに接続するDOM操作テストでも検証しています。詳しい実行結果と未検証範囲は[検証記録](docs/verification.md)を参照してください。

## セキュリティと既知の制限

- HTTPを使うLAN内向けです。信頼できないネットワークやインターネットへ直接公開しないでください。リバースプロキシの転送元ヘッダーには対応していません。
- 管理者全員が秘密情報の表示、Engineの宛先変更、バックアップ取得を行えます。Engine URLは管理者だけが登録できる、信頼された接続先として扱います。
- Engine・バージョン・モデルごとの完全互換性は保証しません。自動検出は保守的で、Capabilityの手動確認が必要な場合があります。実Engineの推論は同梱のMock検証とは別に確認してください。
- 公開APIは記載した7ルートです。OpenAIのFiles、Audio、Batch、Responses取得／削除などを実装するものではありません。意味を保持できないAPI変換は行いません。
- クライアントのrequest bodyサイズ、生成数、token数の上限は設けません。メモリ保護のためSSEの1イベントは8 MiB、モデルdiscoveryは32 MiB、バックアップarchiveは512 MiBまでです。非Streaming JSONとPortable archiveはメモリ上で扱います。
- JSONLへの永続化とSQLite統計は同一transactionにはできません。通常は両方を保存し、書き込み失敗は診断ログとFlush／終了時エラーで通知します。ディスク故障や強制終了直前のqueue分は復旧保証の対象外です。
- `service.log`はlaunchdの診断出力です。自動rotationの対象は詳細アクセスJSONLです。
- 本プロジェクトはロードバランシング、failover、quota、rate limit、TLS終端を提供しません。

参照した一次資料: [LM Studio互換API](https://lmstudio.ai/docs/developer/openai-compat)、[MLX LM Server](https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/SERVER.md)、[oMLX](https://github.com/jundot/omlx)。
