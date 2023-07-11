import os
import hvac
import json
import requests
import webbrowser
import http.server

from urllib import parse
from pathlib import Path

# handles the callback
def login_odic_get_token():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class HttpServ(HTTPServer):
        def __init__(self, *args, **kwargs):
            HTTPServer.__init__(self, *args, **kwargs)
            self.token = None

    class AuthHandler(BaseHTTPRequestHandler):
        token = ''

        def do_GET(self):
            params = parse.parse_qs(self.path.split('?')[1])
            self.server.token = params['code'][0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(str.encode('<div>Authentication successful, you can close the browser now.</div>'))

    server_address = ('', 8250)
    httpd = HttpServ(server_address, AuthHandler)
    httpd.handle_request()
    return httpd.token

def sign_certificate(config, vault_token):
    
    vault_addr = config.get("vault_addr")
    secret_engine_name = config.get("secret_engine_name")
    sign_role = config.get("sign_role")
    cert_ttl = config.get("cert_ttl")
    
    public_key_path = Path(os.path.expanduser(config.get("public_key_path")))
    public_key = public_key_path.read_text().replace("\n", "")
    
    ssh_certificate_path = f"{public_key_path.parent}/{public_key_path.stem}-cert.pub"

    url = f"{vault_addr}/v1/{secret_engine_name}/sign/{sign_role}"    
    headers = {'Content-Type': 'application/json', 'x-vault-token': vault_token}
    payload = {"cert_type": "user", "public_key": public_key, "ttl": cert_ttl}
    response = requests.request("POST", url, headers=headers, json=payload)

    if response.status_code == 403:
        print("token失效 , 重新獲取token")
        vault_token = get_vault_token(config=config)
        headers.update({'x-vault-token': vault_token})
        response = requests.request("POST", url, headers=headers, json=payload)
        signed_key = response.json()['data']['signed_key']

    else:
        signed_key = response.json()['data']['signed_key']
    
    # 產生證書
    ssh_certificate_path = Path(ssh_certificate_path)
    ssh_certificate_path.write_text(signed_key)
    print(f"SSH證書路徑: {ssh_certificate_path}")
    
def get_vault_token(config):
    
    try:

        redirect_uri = "http://localhost:8250/oidc/callback"
        vault_addr = config.get("vault_addr")        
        mount_path = config.get("mount_path")
        
        client = hvac.Client(url=vault_addr)

        auth_url_response = client.auth.oidc.oidc_authorization_url_request(role=None, redirect_uri=redirect_uri, path=mount_path)
        auth_url = auth_url_response['data']['auth_url'] 

        params = parse.parse_qs(auth_url.split('?')[1])
        auth_url_nonce = params['nonce'][0]
        auth_url_state = params['state'][0]

        webbrowser.open(auth_url)
        token = login_odic_get_token()
        auth_result = client.auth.oidc.oidc_callback(code=token, path=mount_path, nonce=auth_url_nonce, state=auth_url_state)
        client_token = auth_result['auth']['client_token']

        # 暫存token在本地, 以便下次再進行使用(不用每一次都進行google驗證)
        print("renew vault token")
        token_file = Path('token')
        if token_file.exists():
            token_file.write_text(client_token)
        else:
            token_file.touch(exist_ok=True)
            token_file.write_text(client_token)
        
        return client_token


    except Exception as e:
        print(f"請手動開啟 Google OAuth 網址:{e.url} 是否頁面能夠正常顯示")

def load_config_file():
    """
    檢查配置檔內容 , 檔案如不存在則自動幫用戶建立以及寫入配置
    """
    # 讀配置(不存在則建立 , 存在則讀取配置檔案內容)
    config_path = Path('config.json')
    if config_path.exists():
        config = json.loads(config_path.read_text())
    else:
        config_path.touch(exist_ok=True)
        config = {}
    
    # 檢查Vault URL配置項
    vault_addr = config.get("vault_addr", None)
    if not vault_addr:
        vault_addr = input(f"找不到 vault_addr 配置項, 請輸入Vault地址 (不清楚用途可以直接按下Enter鍵套用預設值): ").lower().strip() or "https://vault.admincod88.com"

    # 檢查Secret Engine配置項
    secret_engine_name = config.get("secret_engine_name", None)
    if not secret_engine_name:
        secret_engine_name = input(f"找不到 secret_engine_name 配置項, 請輸入Secret Engine名稱 (不清楚用途可以直接按下Enter鍵套用預設值): ").lower().strip() or "ssh-ca-client-signer"

    # 檢查Mount Path配置項
    mount_path = config.get("mount_path", None)
    if not mount_path:
        mount_path = input(f"找不到 mount_path 配置項, 請輸入 (不清楚用途可以直接按下Enter鍵套用預設值): ").lower().strip()  or "google"

    # 檢查public key路徑
    public_key_path = config.get("public_key_path", None)
    if not public_key_path:
        public_key_path = input(f"找不到 public_key_path 配置項, 請輸入Public Key路徑 (或直接按下Enter鍵, 套用預設路徑 ~/.ssh/id_ed25519.pub): ").lower().strip()  or "~/.ssh/id_ed25519.pub"

    # 檢查簽發角色配置項
    role_list = ["devops", "dba"]
    sign_role = config.get("sign_role", None)
    while(sign_role == None or sign_role == '' or sign_role not in role_list):
        sign_role = input(f"找不到 sign_role 配置項或輸入錯誤, 請手動重新輸入要被簽發的角色名稱 , 目前角色有{role_list}: ").lower().strip()

    # 
    cert_ttl = config.get("cert_ttl", None)
    if not cert_ttl:
        cert_ttl = input(f"找不到 cert_ttl 配置項或輸入錯誤, 請手動重新輸入憑證有效時間, e.g. 8h, 預設 30m: ").lower().strip() or "30m"


    # 更新dict內容
    config.update({'sign_role': sign_role})
    config.update({'vault_addr': vault_addr})
    config.update({'mount_path': mount_path})
    config.update({'public_key_path': public_key_path})
    config.update({'secret_engine_name': secret_engine_name})
    config.update({'cert_ttl': cert_ttl})
    
    # 建立配置檔
    config_path.write_text(json.dumps(config, indent=4))
    
    return config

def load_token_file():
    # 讀token
    vault_token_file = Path("./token")
    if vault_token_file.exists():
        vault_token = vault_token_file.read_text().replace("\n", "")
    else:
        vault_token_file.touch(exist_ok=True)
        vault_token = ""
        
    return vault_token

if __name__ == "__main__":
    
    # 讀配置及token
    validated_config = load_config_file()
    vault_token = load_token_file()
    
    if validated_config:
        # 簽證書
        sign_certificate(config=validated_config, vault_token=vault_token)
