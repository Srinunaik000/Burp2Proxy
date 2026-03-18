import socket
import ssl
import time
import h2.connection
import h2.events
import h2.config
from typing import List, Dict, Tuple

class H2RaceEngine:
    """
    Burp Pro style HTTP/2 Race Engine.
    Uses Last-Frame Synchronization to send multiple requests in a single TCP packet.
    """
    def __init__(self, host: str, port: int, scheme: str):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.config = h2.config.H2Configuration(client_side=True)
        
    def run_race(self, method: str, path: str, headers: List[Tuple[str, str]], body: bytes, count: int):
        results = []
        try:
            # 1. Setup Socket & SSL
            sock = socket.create_connection((self.host, self.port))
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            if self.scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(['h2'])
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            
            # 2. H2 Handshake
            conn = h2.connection.H2Connection(config=self.config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            # 3. Open Streams and send 99% of data
            stream_ids = []
            for i in range(count):
                stream_id = conn.get_next_available_stream_id()
                stream_ids.append(stream_id)
                
                h2_headers = [
                    (':method', method),
                    (':authority', self.host),
                    (':scheme', self.scheme),
                    (':path', path),
                ] + [(k.lower(), v) for k, v in headers if k.lower() not in (':method', ':authority', ':scheme', ':path', 'connection', 'host', 'content-length')]
                
                # Send Headers
                conn.send_headers(stream_id, h2_headers, end_stream=(not body))
                
                # If there is a body, send all but the last byte
                if body:
                    if len(body) > 1:
                        conn.send_data(stream_id, body[:-1], end_stream=False)
                
            sock.sendall(conn.data_to_send())

            # 4. THE SINGLE PACKET ATTACK
            for stream_id in stream_ids:
                if body:
                    conn.send_data(stream_id, body[-1:], end_stream=True)
                else:
                    # For GET/No-body, we could use a different sync frame but for now
                    # closing headers was done above.
                    pass
            
            # Release the floodgate!
            start_time = time.perf_counter()
            sock.sendall(conn.data_to_send())

            # 5. Collect Responses
            responses = {sid: {"status": 0, "body": b"", "headers": []} for sid in stream_ids}
            finished_streams = 0
            sock.settimeout(10.0)
            
            while finished_streams < count:
                try:
                    data = sock.recv(65535)
                    if not data: break
                    
                    events = conn.receive_data(data)
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            sid = event.stream_id
                            if sid in responses:
                                for k, v in event.headers:
                                    if k == b':status':
                                        responses[sid]["status"] = int(v)
                                    else:
                                        responses[sid]["headers"].append((k.decode(), v.decode()))
                        
                        elif isinstance(event, h2.events.DataReceived):
                            sid = event.stream_id
                            if sid in responses:
                                responses[sid]["body"] += event.data
                        
                        elif isinstance(event, h2.events.StreamEnded):
                            finished_streams += 1
                    
                    to_send = conn.data_to_send()
                    if to_send:
                        sock.sendall(to_send)
                except socket.timeout:
                    break
                except Exception:
                    break

            end_time = time.perf_counter()
            duration = int((end_time - start_time) * 1000)

            # 6. Format results for the GUI
            for idx, sid in enumerate(stream_ids):
                resp = responses[sid]
                
                # Decompression Logic
                body = resp["body"]
                encoding = ""
                for k, v in resp["headers"]:
                    if k.lower() == "content-encoding":
                        encoding = v.lower()
                        break
                
                try:
                    if "gzip" in encoding or "deflate" in encoding:
                        import gzip
                        import io
                        with gzip.GzipFile(fileobj=io.BytesIO(body)) as f:
                            body = f.read()
                    elif "br" in encoding:
                        import brotli
                        body = brotli.decompress(body)
                    elif "zstd" in encoding:
                        import zstandard
                        body = zstandard.decompress(body)
                except Exception as de_err:
                    print(f"Decompression error on stream {sid}: {de_err}")

                headers_str = "\n".join([f"{k}: {v}" for k, v in resp["headers"]])
                full_resp = f"HTTP/2 {resp['status']}\n{headers_str}\n\n{body.decode('utf-8', 'replace')}"
                
                results.append({
                    "request_id": idx,
                    "status_code": resp["status"],
                    "response_length": len(body),
                    "execution_time_ms": duration,
                    "raw_response": full_resp,
                    "raw_request": f"{method} {path} HTTP/2 (Single Packet Attack)"
                })

        except Exception as e:
            results.append({"request_id": -1, "status_code": "ERR", "error_message": f"H2 Turbo Error: {e}"})
        
        finally:
            try: sock.close()
            except: pass
            
        return results
