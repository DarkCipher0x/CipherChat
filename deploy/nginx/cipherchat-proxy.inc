# CipherChat by DarkCipher Systems: proxy settings for every CipherChat location (installed by cipherchat-setup as
# /etc/nginx/snippets/cipherchat-proxy.inc). The server sets its own security headers (CSP, HSTS, frame and referrer
# policy) on every response; it trusts X-Real-IP only because nginx connects from loopback.
proxy_pass http://cipherchat;
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For "";
proxy_connect_timeout 3s;
