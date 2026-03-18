import time
import random
import threading
import socket
import requests
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor
from racer.request_runner import send_synchronized_request, send_turbo_request, _parse_raw_request
from racer.h2_engine import H2RaceEngine

# Optimization: Disable Nagle's algorithm globally for requests/urllib3
from urllib3.connection import HTTPConnection
HTTPConnection.default_socket_options += [
    (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
]

class RaceTestManager:
    def __init__(self, test_config, results_queue):
        self.config = test_config
        self.results_queue = results_queue
        self.raw_request = self.config['raw_request']
        self.num_requests = self.config['num_requests']
        self.strategy = self.config['strategy'] # 'Simultaneous', 'Staggered', 'HTTP/2 Single Packet'
        self.delay = self.config.get('delay_ms', 0) / 1000.0
        # The Starting Gun
        self.barrier = threading.Barrier(self.num_requests)

    def run_test(self):
        try:
            # 1. Parse request once to avoid overhead in threads
            method, url, headers, body = _parse_raw_request(self.raw_request)
            body_bytes = body.encode('utf-8')

            # --- HTTP/2 Single Packet Strategy ---
            if self.strategy == 'HTTP/2 Single Packet':
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                path = parsed.path + ("?" + parsed.query if parsed.query else "")
                
                engine = H2RaceEngine(host, port, parsed.scheme)
                # Convert headers dict to list of tuples for H2
                h_list = list(headers.items()) if isinstance(headers, dict) else headers
                
                results = engine.run_race(method, path, h_list, body_bytes, self.num_requests)
                for res in results:
                    self.results_queue.put(res)
                return

            # --- Standard/Turbo Strategies ---
            # 2. Setup shared session with huge pool
            session = requests.Session()
            adapter = HTTPAdapter(
                pool_connections=self.num_requests + 5, 
                pool_maxsize=self.num_requests + 5,
                pool_block=False
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            # 3. Aggressive Connection Warming 
            # We send a few requests to ensure the server-side keep-alive is ready
            warmers = []
            with ThreadPoolExecutor(max_workers=5) as warmer_exec:
                for _ in range(min(5, self.num_requests)):
                    warmers.append(warmer_exec.submit(session.request, "OPTIONS", url, timeout=5, verify=False))
            
            # Wait for warmers to finish
            for w in warmers: 
                try: w.result()
                except: pass

            # 4. Setup proxies once
            proxies = None
            proxy_config = self.config.get('proxy_config')
            use_proxy = False
            if proxy_config and proxy_config.get('use_proxy'):
                use_proxy = True
                p_url = f"http://{proxy_config['host']}:{proxy_config['port']}"
                proxies = {"http": p_url, "https": p_url}

            # Prepare Turbo Params if valid
            turbo_ready = False
            if self.strategy == 'Simultaneous' and not use_proxy:
                parsed = urlparse(url)
                turbo_host = parsed.hostname
                turbo_scheme = parsed.scheme
                turbo_port = parsed.port
                if not turbo_port:
                    turbo_port = 443 if turbo_scheme == 'https' else 80
                
                # Reconstruct full HTTP/1.1 payload
                path = parsed.path
                if parsed.query: path += "?" + parsed.query
                if not path: path = "/"
                
                # Normalize and clean headers to prevent duplicates
                # We remove existing sensitive headers before adding our own
                final_headers = {}
                for k, v in headers.items():
                    k_lower = k.lower()
                    if k_lower not in ['host', 'content-length', 'connection']:
                        final_headers[k] = v
                
                # Add the 'Correct' versions
                final_headers['Host'] = turbo_host
                final_headers['Content-Length'] = str(len(body_bytes))
                final_headers['Connection'] = 'keep-alive'
                
                head = f"{method} {path} HTTP/1.1\r\n"
                for k, v in final_headers.items():
                    head += f"{k}: {v}\r\n"
                head += "\r\n"
                
                turbo_payload = head.encode('latin-1') + body_bytes
                turbo_ready = True

            # 5. The Race
            with ThreadPoolExecutor(max_workers=self.num_requests) as executor:
                if self.strategy == 'Simultaneous':
                    for i in range(self.num_requests):
                        if turbo_ready:
                            # Use Turbo Socket Engine (Last-Byte Sync)
                            executor.submit(
                                send_turbo_request,
                                request_id=i,
                                host=turbo_host,
                                port=turbo_port,
                                scheme=turbo_scheme,
                                payload=turbo_payload,
                                barrier=self.barrier
                            ).add_done_callback(lambda f, idx=i: self._handle_result(f, idx))
                        else:
                            # Fallback to requests (if proxy enabled)
                            thread_headers = headers.copy()
                            executor.submit(
                                send_synchronized_request,
                                request_id=i,
                                method=method,
                                url=url,
                                headers=thread_headers,
                                body=body_bytes,
                                barrier=self.barrier,
                                session=session,
                                proxies=proxies
                            ).add_done_callback(lambda f, idx=i: self._handle_result(f, idx))
                else:
                    # Staggered logic
                    for i in range(self.num_requests):
                        # For staggered, we don't use the barrier (or use a barrier of 1)
                        pass
        except Exception as e:
            # Handle parsing or setup errors
            self.results_queue.put({
                "request_id": -1,
                "status_code": "SETUP_ERROR",
                "error_message": f"Race setup failed: {e}"
            })

    def _handle_result(self, future, request_id):
        try:
            result = future.result()
            self.results_queue.put(result)
        except Exception as e:
            self.results_queue.put({
                "request_id": request_id,
                "status_code": "ERROR", 
                "error_message": str(e)
            })
