"""Local partner content and internal inventory service."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import json
import secrets

INVENTORY_TOKEN = secrets.token_hex(16)

class PartnerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path == '/health':
            body, kind = '{"status":"ok"}', 'application/json'
        elif path == '/catalog-info':
            body, kind = '拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。', 'text/plain'
        elif path == '/templates/season.php':
            body, kind = '<?php echo "<h2>合作方 · 秋日生活提案</h2><p>让生活慢下来，把好物带回家。</p>"; ?>', 'text/plain'
        elif path in ('/', '/welcome'):
            body, kind = '<!doctype html><meta charset="utf-8"><title>拾光合作伙伴</title><h1>拾光合作伙伴</h1><p>合作内容与商品信息服务已就绪。</p>', 'text/html'
        else:
            self.send_error(404, 'Content not found')
            return
        self.send_body(body, kind)

    def send_body(self, body, kind):
        raw = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

class InventoryHandler(PartnerHandler):
    def do_GET(self):
        if self.path == '/internal/status':
            self.send_body(json.dumps({'service': 'private-inventory', 'warehouse_key': INVENTORY_TOKEN, 'stock_synced': True}), 'application/json')
        else:
            self.send_error(404)

if __name__ == '__main__':
    internal = ThreadingHTTPServer(('0.0.0.0', 8082), InventoryHandler)
    Thread(target=internal.serve_forever, daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0', 8080), PartnerHandler).serve_forever()
