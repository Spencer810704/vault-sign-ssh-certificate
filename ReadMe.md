Table of contents
- [介紹](#介紹)
- [安裝](#安裝)
  - [配置範例及各項用途說明](#配置範例及各項用途說明)
- [執行及驗證](#執行及驗證)

# 介紹
因本公司的基礎架構更改 , 規定將所有的 Server 使用 SSH 的 Certificate-Based Authentication
而進行簽發的服務則使用 Hashicorp Vault + Google OAuth 驗證 , 當google OAuth驗證通過後 , 就簽發證書並提供用戶登入 Server 
當員工離職時 , 則只需要停用 google 帳號即可 , 與以往新進人員或離職人員都要透過 ansible 進行所有 Server 部署 key 方式不同 , 使用此種方式較利於管理 , 另外 SSH certificates 沒有辦法直接通過 Vault 撤銷 SSH , 所以需要限制簽名的過期時間在8小時內 。

但本人比較懶惰 , 每一次都需要開啟 Hashicorp Vault 頁面在點 Google OAuth 驗證 , 並將簽發的證書貼到我們的 SSH Certificate中
太過於麻煩 , 故寫了一個小工具只需要執行腳本以及點擊 Google OAuth 選擇對應帳號後 , 通過驗證會將簽發的證書更新至本地。

# 安裝

```
# 設定python虛擬環境 (可不執行)
virtualenv venv
source venv/bin/activate

# 安裝相依性套件(需執行)
pip install -r requirements.txt

```

## 配置範例及各項用途說明

```
{
    "vault_addr": "https://vault.admincod88.com",
    "mount_path": "google",
    "secret_engine_name": "ssh-ca-client-signer",
    "sign_role": "devops",
    "public_key_path": "./test-key.pub"
}
```

- `vault_addr`: Vault API 地址。
- `mount_path`: 驗證方法, 我司使用google oauth驗證 , 此處填寫google。
- `secret_engine_name`: 此處填寫SSH Engine名稱。
- `sign_role`: 要使用什麼角色進行簽發SSH憑證, 目前有的role
    - `ansible`
    - `devops`
- `public_key_path`: 公鑰路徑。


以上配置項目前需要更改的只有下列兩項 , 請依實際情況填寫
- `sign_role`
- `public_key_path`




# 執行及驗證

```
# 執行 , 會跳出跳窗要求用戶驗證 (無配置檔案的話 , 會使用互動視窗提供用戶輸入)
python main.py

# 驗證SSH證書 (Key ID、Valid、Principals欄位)
ssh-keygen -L -f <ssh-certificate-path>

```

