Table of contents
- [安裝配置](#安裝配置)
- [配置範例及各項用途說明](#配置範例及各項用途說明)
- [執行及驗證](#執行及驗證)


# 安裝配置

```
# 設定python虛擬環境 (可不執行)
virtualenv venv
source venv/bin/activate

# 安裝相依性套件(需執行)
pip install -r requirements.txt

```

# 配置範例及各項用途說明

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

