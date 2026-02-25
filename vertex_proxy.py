#!/usr/bin/env python3
import json
import os
import subprocess
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get('VERTEX_PROXY_HOST', '127.0.0.1')
PORT = int(os.environ.get('VERTEX_PROXY_PORT', '8787'))


def _get_access_token() -> str:
    env_token = (os.environ.get('VERTEX_ACCESS_TOKEN') or '').strip()
    if env_token:
        return env_token

    cmd = ['gcloud', 'auth', 'application-default', 'print-access-token']
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        raise RuntimeError(f'Unable to get ADC access token via gcloud: {stderr or "unknown error"}')
    token = (result.stdout or '').strip()
    if not token:
        raise RuntimeError('gcloud returned an empty access token')
    return token


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict):
    body = json.dumps(payload).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Access-Control-Allow-Origin', '*')
    handler.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    handler.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    handler.send_header('Content-Length', str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class VertexProxyHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.end_headers()

    def do_GET(self):
        if self.path == '/health':
            _json_response(self, 200, {'ok': True})
            return
        _json_response(self, 404, {'error': 'not_found'})

    def do_POST(self):
        if self.path != '/vertex/generate':
            _json_response(self, 404, {'error': 'not_found'})
            return

        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            raw = self.rfile.read(content_length) if content_length > 0 else b'{}'
            req = json.loads(raw.decode('utf-8'))

            project_id = (req.get('projectId') or '').strip()
            # Normalize location to lowercase and default to us-central1
            location = ((req.get('location') or '').strip() or 'us-central1').lower()
            model = (req.get('model') or '').strip()
            payload = req.get('payload')

            if not project_id or not model or not isinstance(payload, dict):
                _json_response(self, 400, {'error': 'projectId, location, model, and payload are required'})
                return

            token = _get_access_token()
            host = 'aiplatform.googleapis.com' if location == 'global' else f'{location}-aiplatform.googleapis.com'
            url = (
                f'https://{host}/v1/'
                f'projects/{project_id}/locations/{location}/publishers/google/models/{model}:generateContent'
            )

            outbound = urllib.request.Request(
                url=url,
                method='POST',
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {token}'
                },
                data=json.dumps(payload).encode('utf-8')
            )

            with urllib.request.urlopen(outbound, timeout=60) as resp:
                body = resp.read().decode('utf-8')
                data = json.loads(body) if body else {}
                _json_response(self, resp.getcode(), data)
                return

        except urllib.error.HTTPError as e:
            try:
                details = e.read().decode('utf-8')
                parsed = json.loads(details) if details else {'error': 'upstream_error'}
            except Exception:
                parsed = {'error': 'upstream_error', 'details': str(e)}
            _json_response(self, e.code or 502, parsed)
            return
        except Exception as e:
            _json_response(self, 500, {'error': 'proxy_error', 'message': str(e)})
            return


if __name__ == '__main__':
    server = ThreadingHTTPServer((HOST, PORT), VertexProxyHandler)
    print(f'Vertex proxy listening on http://{HOST}:{PORT}')
    print('Endpoints: GET /health, POST /vertex/generate')
    server.serve_forever()
