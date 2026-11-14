#!/bin/bash
set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
clear
echo -e "${GREEN}=== УНИВЕРСАЛЬНЫЙ УСТАНОВЩИК VPN (БЕЗОПАСНЫЙ) ===${NC}"

read -p "Основной домен (например, agema-2026.online): " RAW_DOMAIN
DOMAIN=$(echo "$RAW_DOMAIN" | tr -cd 'a-zA-Z0-9.-')
[ -z "$DOMAIN" ] && { echo -e "${RED}Домен пуст!${NC}"; exit 1; }

read -p "ИИ-субдомены через пробел (например, chat api neural www): " RAW_SUBS
SUBDOMAINS=$(echo $RAW_SUBS)

read -p "Порт Nginx для Fallback (VLESS Target) [40000]: " NGINX_PORT
NGINX_PORT=${NGINX_PORT:-40000}

ALL_CERT_DOMAINS="$DOMAIN"
for s in $SUBDOMAINS; do ALL_CERT_DOMAINS="$ALL_CERT_DOMAINS $s.$DOMAIN"; done

IS_UPDATE=0
if [ -f "/etc/x-ui/x-ui.db" ]; then
    IS_UPDATE=1
    echo -e "${YELLOW}⚠ Обнаружена база 3x-ui! Будет безопасное обновление.${NC}"
    mkdir -p /root/xui_backups
    cp /etc/x-ui/x-ui.db "/root/xui_backups/x-ui.db.backup-$(date +%F-%H-%M)"
else
    echo -e "${YELLOW}Чистый сервер. Установка с нуля.${NC}"
fi

echo -e "${YELLOW}[1/5] Установка зависимостей...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y nginx certbot curl wget sqlite3 openssl python3 ufw

if [ "$IS_UPDATE" -eq 0 ]; then
    echo -e "${YELLOW}Установка 3x-ui...${NC}"
    wget -qO /tmp/xui-install.sh https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh
    printf "1\nn\n4\ny\n" | bash /tmp/xui-install.sh
    sleep 5
    systemctl start x-ui; sleep 3; systemctl stop x-ui
fi

echo -e "${YELLOW}[2/5] Настройка хука автообновления...${NC}"
mkdir -p /etc/letsencrypt/renewal-hooks/deploy/
cat > /etc/letsencrypt/renewal-hooks/deploy/restart-xui.sh << 'HOOK'
#!/bin/bash
systemctl reload nginx
systemctl restart x-ui
HOOK
chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-xui.sh

echo -e "${YELLOW}[3/5] Выпуск SSL-сертификата Let's Encrypt...${NC}"
mkdir -p /var/www/certbot
rm -f /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf
cat > /etc/nginx/conf.d/acme-temp.conf << NGINX
server {
    listen 80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
NGINX
systemctl restart nginx

CERTBOT_ARGS=""
for d in $ALL_CERT_DOMAINS; do CERTBOT_ARGS="$CERTBOT_ARGS -d $d"; done
certbot certonly --webroot -w /var/www/certbot $CERTBOT_ARGS --expand --non-interactive --agree-tos -m "admin@$DOMAIN" --deploy-hook "systemctl reload nginx"

if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] && [ ! -f "/etc/letsencrypt/live/$DOMAIN-0001/fullchain.pem" ]; then
    echo -e "${RED}ОШИБКА! Сертификат не выпущен. Проверьте DNS.${NC}"
    exit 1
fi

if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
else
    CERT_DIR=$(ls -d /etc/letsencrypt/live/$DOMAIN-* | head -n 1)
fi
CERT_PATH="$CERT_DIR/fullchain.pem"
KEY_PATH="$CERT_DIR/privkey.pem"

echo -e "${YELLOW}[4/5] Обновление базы данных Xray...${NC}"
export DB_DOMAIN="$DOMAIN" DB_SUBS="$SUBDOMAINS" DB_CP="$CERT_PATH" DB_KP="$KEY_PATH" DB_NGINX_PORT="$NGINX_PORT" DB_IS_UPDATE="$IS_UPDATE"

python3 << 'PYEOF'
import os, sqlite3, json, secrets, uuid, subprocess, time
DOMAIN=os.environ['DB_DOMAIN']; SUBS=os.environ['DB_SUBS'].split()
CERT_PATH=os.environ['DB_CP']; KEY_PATH=os.environ['DB_KP']
NGINX_PORT=os.environ['DB_NGINX_PORT']; IS_UPDATE=int(os.environ['DB_IS_UPDATE'])
ALL_NAMES=[DOMAIN]+[f"{s}.{DOMAIN}" for s in SUBS]
HY_DOMAIN = f"{SUBS[0]}.{DOMAIN}" if len(SUBS) > 0 else DOMAIN
MS_DOMAIN = f"{SUBS[1]}.{DOMAIN}" if len(SUBS) > 1 else DOMAIN

conn=sqlite3.connect('/etc/x-ui/x-ui.db'); c=conn.cursor(); now=int(time.time()*1000)

if IS_UPDATE == 0:
    for tbl in ["client_inbounds", "client_traffics", "clients", "inbounds", "settings"]:
        c.execute(f"DELETE FROM {tbl}")
    WEB_PATH = "/" + secrets.token_hex(16) + "/"
    SUB_PATH = "/" + secrets.token_hex(16) + "/"
    settings = [
        ('webPort', "2053"), ('webBasePath', WEB_PATH), ('webListen', '127.0.0.1'),
        ('subPort', "2096"), ('subPath', SUB_PATH), ('subListen', '127.0.0.1'),
        ('subEnable', 'true'), ('subDomain', DOMAIN), ('subURI', f"https://{DOMAIN}{SUB_PATH}"),
    ]
    for k,v in settings: c.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k,v))
    for name in ["user1", "user2"]:
        c.execute("INSERT INTO clients (email,sub_id,uuid,enable) VALUES (?,?,?,1)",(name, secrets.token_hex(8), str(uuid.uuid4())))

c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('subDomain', ?)", (DOMAIN,))
c.execute("SELECT id, email, sub_id, uuid FROM clients")
clients = c.fetchall()

c.execute("SELECT id, protocol, stream_settings FROM inbounds")
for iid, proto, stream_str in c.fetchall():
    if not stream_str: continue
    try: stream = json.loads(stream_str)
    except: continue
    
    if proto == 'vless':
        if 'realitySettings' not in stream: stream['realitySettings'] = {}
        stream['realitySettings']['serverNames'] = ALL_NAMES
        stream['realitySettings']['target'] = f"127.0.0.1:{NGINX_PORT}"
    elif proto == 'hysteria':
        if 'tlsSettings' not in stream: stream['tlsSettings'] = {}
        stream['tlsSettings']['serverName'] = HY_DOMAIN
        stream['tlsSettings']['certificates'] = [{"certificateFile": CERT_PATH, "keyFile": KEY_PATH, "useFile": True}]
    elif proto == 'masque':
        if 'tlsSettings' not in stream: stream['tlsSettings'] = {}
        stream['tlsSettings']['serverName'] = MS_DOMAIN
        stream['tlsSettings']['certificates'] = [{"certificateFile": CERT_PATH, "keyFile": KEY_PATH, "useFile": True}]
    c.execute("UPDATE inbounds SET stream_settings=? WHERE id=?", (json.dumps(stream), iid))

if IS_UPDATE == 0:
    xb=subprocess.check_output("find /usr/local/x-ui/bin/ -name 'xray*' -type f | head -n 1",shell=True).decode().strip()
    k=subprocess.check_output(f"{xb} x25519",shell=True).decode()
    pk=[l.split()[-1] for l in k.split('\n') if 'Private' in l][0]
    pub=[l.split()[-1] for l in k.split('\n') if 'Password' in l or 'Public' in l][0]
    
    vless_clients = [{"id":u,"email":e,"subId":s,"enable":True} for i,e,s,u in clients]
    
    # ВАШ НОВЫЙ JSON
    vless_stream = {
        "network": "xhttp",
        "xhttpSettings": {
            "path": "/api/v1/ws",
            "host": "",
            "mode": "stream-one",
            "xPaddingBytes": "10-100",
            "xPaddingObfsMode": True,
            "xPaddingKey": "",
            "xPaddingHeader": "",
            "xPaddingPlacement": "cookie",
            "xPaddingMethod": "repeat-x",
            "sessionIDPlacement": "",
            "sessionIDKey": "",
            "sessionIDTable": "Base62",
            "sessionIDLength": "8-16",
            "seqPlacement": "",
            "seqKey": "",
            "uplinkDataPlacement": "",
            "uplinkDataKey": "",
            "scMaxEachPostBytes": "",
            "noSSEHeader": False,
            "scMaxBufferedPosts": 30,
            "scStreamUpServerSecs": "20-80",
            "serverMaxHeaderBytes": 0,
            "uplinkHTTPMethod": "POST",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept": "text/event-stream"
            },
            "scMinPostsIntervalMs": "",
            "uplinkChunkSize": 0,
            "noGRPCHeader": False,
            "xmux": {
                "maxConcurrency": "16-32",
                "maxConnections": 0,
                "cMaxReuseTimes": 0,
                "hMaxRequestTimes": "600-900",
                "hMaxReusableSecs": "1800-3000",
                "hKeepAlivePeriod": 0
            },
            "enableXmux": True
        },
        "security": "reality",
        "realitySettings": {
            "show": False,
            "xver": 0,
            "target": f"127.0.0.1:{NGINX_PORT}",
            "serverNames": ALL_NAMES,
            "privateKey": pk,
            "minClientVer": "",
            "maxClientVer": "",
            "maxTimediff": 0,
            "shortIds": [secrets.token_hex(4), secrets.token_hex(8)],
            "mldsa65Seed": "",
            "settings": {
                "publicKey": pub,
                "fingerprint": "firefox",
                "serverName": "",
                "spiderX": "/",
                "mldsa65Verify": ""
            }
        },
        "sockopt": {
            "tcpFastOpen": True,
            "tcpcongestion": "bbr",
            "acceptProxyProtocol": False,
            "mark": 0,
            "tproxy": "off",
            "tcpMptcp": False,
            "penetrate": False,
            "domainStrategy": "AsIs",
            "tcpMaxSeg": 0,
            "dialerProxy": "",
            "tcpKeepAliveInterval": 0,
            "tcpKeepAliveIdle": 0,
            "tcpUserTimeout": 0,
            "V6Only": False,
            "tcpWindowClamp": 0,
            "interface": "",
            "trustedXForwardedFor": [],
            "addressPortStrategy": "none",
            "customSockopt": []
        }
    }
    
    c.execute("INSERT INTO inbounds (user_id,remark,port,protocol,settings,stream_settings,enable) VALUES (1,'VLESS-AI',443,'vless',?,?,1)",(json.dumps({"clients":vless_clients,"decryption":"none"}), json.dumps(vless_stream)))

    hy_clients = [{"id":u,"email":e,"subId":s,"auth":u,"enable":True} for i,e,s,u in clients]
    hy_stream = {"network": "hysteria", "security": "tls", "tlsSettings": {"serverName": HY_DOMAIN, "certificates": [{"certificateFile": CERT_PATH, "keyFile": KEY_PATH, "useFile": True}], "alpn": ["h3"]}}
    c.execute("INSERT INTO inbounds (user_id,remark,port,protocol,settings,stream_settings,enable) VALUES (1,'Hysteria2',443,'hysteria',?,?,1)",(json.dumps({"clients":hy_clients,"version":2}), json.dumps(hy_stream)))

conn.commit(); conn.close()
PYEOF

echo -e "${YELLOW}[5/5] Настройка Nginx и создание заглушек...${NC}"
WEB_PATH=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key='webBasePath';")
SUB_PATH=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key='subPath';")
WEB_PORT=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key='webPort';")
SUB_PORT=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key='subPort';")

# Создаем красивую заглушку для главного домена
mkdir -p /var/www/decoy
cat > /var/www/decoy/index.html << 'HTML'
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Private Server</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#1c1c22;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#24242c;border:1px solid #333340;border-radius:12px;padding:40px 36px;width:100%;max-width:400px;color:#e6e6ee}
.icon{text-align:center;font-size:32px;margin-bottom:14px;opacity:.85}
h1{font-size:18px;font-weight:600;text-align:center;margin-bottom:6px}
.sub{text-align:center;color:#8a8a98;font-size:13px;margin-bottom:28px}
label{display:block;font-size:12px;color:#a0a0ac;margin-bottom:6px;letter-spacing:.3px}
input{width:100%;padding:11px 13px;background:#1a1a20;border:1px solid #333340;border-radius:6px;color:#e6e6ee;font-size:14px;margin-bottom:14px;outline:none}
input:focus{border-color:#5a8f7a}
button{width:100%;padding:12px;background:#5a8f7a;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;margin-top:4px}
button:disabled{opacity:.6;cursor:not-allowed}
.err{color:#ff7a7a;background:rgba(255,122,122,.08);border:1px solid rgba(255,122,122,.25);border-radius:6px;padding:10px;font-size:12px;margin-top:14px;display:none;line-height:1.5}
.foot{margin-top:22px;text-align:center;font-size:11px;color:#5a5a68}
</style>
</head>
<body>
<div class="card">
  <div class="icon">🔒</div>
  <h1>Вход в систему</h1>
  <div class="sub">Private instance · authorized access only</div>
  <form id="f">
    <label>Логин</label><input type="text" required>
    <label>Пароль</label><input type="password" required>
    <button type="submit" id="b">Войти</button>
    <div id="e" class="err"></div>
  </form>
  <div class="foot">self-hosted · private use</div>
</div>
<script>
document.getElementById('f').addEventListener('submit',function(ev){
  ev.preventDefault();
  var b=document.getElementById('b'),e=document.getElementById('e');
  b.disabled=true;b.innerText='Проверка...';e.style.display='none';
  setTimeout(function(){
    b.disabled=false;b.innerText='Войти';
    e.style.display='block';
    e.innerText='Не удалось войти: сервис авторизации недоступен. Попробуйте позже.';
  },1500);
});
</script>
</body>
</html>
HTML

# Создаем заглушки для субдоменов
for s in $SUBDOMAINS; do
    mkdir -p /var/www/$s
    cat > /var/www/$s/index.html << HTML
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Workspace</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#1c1c22;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#24242c;border:1px solid #333340;border-radius:12px;padding:40px 36px;width:100%;max-width:400px;color:#e6e6ee}
.icon{text-align:center;font-size:32px;margin-bottom:14px;opacity:.85}
h1{font-size:18px;font-weight:600;text-align:center;margin-bottom:6px}
.sub{text-align:center;color:#8a8a98;font-size:13px;margin-bottom:28px}
label{display:block;font-size:12px;color:#a0a0ac;margin-bottom:6px;letter-spacing:.3px}
input{width:100%;padding:11px 13px;background:#1a1a20;border:1px solid #333340;border-radius:6px;color:#e6e6ee;font-size:14px;margin-bottom:14px;outline:none}
input:focus{border-color:#5a8f7a}
button{width:100%;padding:12px;background:#5a8f7a;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;margin-top:4px}
button:disabled{opacity:.6;cursor:not-allowed}
.err{color:#ff7a7a;background:rgba(255,122,122,.08);border:1px solid rgba(255,122,122,.25);border-radius:6px;padding:10px;font-size:12px;margin-top:14px;display:none;line-height:1.5}
.foot{margin-top:22px;text-align:center;font-size:11px;color:#5a5a68}
</style>
</head>
<body>
<div class="card">
  <div class="icon">🧠</div>
  <h1>AI Workspace</h1>
  <div class="sub">Access to ${s}.${DOMAIN}</div>
  <form id="f">
    <label>API Key / Логин</label><input type="text" required>
    <label>Пароль</label><input type="password" required>
    <button type="submit" id="b">Sign In</button>
    <div id="e" class="err"></div>
  </form>
  <div class="foot">secure gateway · authorized only</div>
</div>
<script>
document.getElementById('f').addEventListener('submit',function(ev){
  ev.preventDefault();
  var b=document.getElementById('b'),e=document.getElementById('e');
  b.disabled=true;b.innerText='Авторизация...';e.style.display='none';
  setTimeout(function(){
    b.disabled=false;b.innerText='Sign In';
    e.style.display='block';
    e.innerText='Ошибка авторизации: неверный ключ доступа или сервис временно недоступен.';
  },1200);
});
</script>
</body>
</html>
HTML
done

NGINX_CONF="server {
    listen 80; server_name $ALL_CERT_DOMAINS;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 127.0.0.1:$NGINX_PORT ssl http2;
    server_name $DOMAIN;
    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    
    # --- ИСПРАВЛЕНИЕ ДЛЯ REALITY ---
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519;
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    # -------------------------------

    location / { root /var/www/decoy; index index.html; }
    location $WEB_PATH { proxy_pass http://127.0.0.1:$WEB_PORT; proxy_set_header Host \$host; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection \"upgrade\"; }
    location $SUB_PATH { proxy_pass http://127.0.0.1:$SUB_PORT; proxy_set_header Host \$host; }
}"

for s in $SUBDOMAINS; do
    NGINX_CONF="$NGINX_CONF
server {
    listen 127.0.0.1:$NGINX_PORT ssl http2;
    server_name $s.$DOMAIN;
    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    
    # --- ИСПРАВЛЕНИЕ ДЛЯ REALITY ---
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519;
    # -------------------------------

    location / { root /var/www/$s; index index.html; }
}"
done

echo "$NGINX_CONF" > /etc/nginx/conf.d/decoy-master.conf
rm -f /etc/nginx/conf.d/acme-temp.conf

ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 443/udp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

if nginx -t; then
    systemctl restart nginx
    systemctl restart x-ui
    echo -e "${GREEN}Nginx и Xray успешно перезапущены!${NC}"
else
    echo -e "${RED}ОШИБКА В КОНФИГЕ NGINX!${NC}"
fi

echo -e "${GREEN}=== ГОТОВО ===${NC}"
if [ "$IS_UPDATE" -eq 1 ]; then
    echo -e "${YELLOW}Режим: ОБНОВЛЕНИЕ (данные сохранены)${NC}"
else
    echo -e "${YELLOW}Режим: НОВАЯ УСТАНОВКА${NC}"
    echo "Панель: https://$DOMAIN$WEB_PATH"
fi
echo "Hysteria: ${HY_DOMAIN}"
echo "Masque: ${MS_DOMAIN}"
echo "VLESS SNI: $ALL_NAMES"
