import time
import requests
import urllib.parse
import threading
import urllib3
import socket
import ssl

# Suppress insecure request warnings from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _parse_raw_request(raw_request: str):
    """Robustly parses a raw HTTP request string into parts."""
    parts = raw_request.split('\n\n', 1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ''
    head_lines = head.split('\n')
    request_line = head_lines[0].strip()
    
    request_parts = request_line.split(' ')
    if len(request_parts) < 2: 
        # Fallback for malformed request line, assuming GET /
        method = "GET"
        path = "/"
    else:
        method = request_parts[0]
        path = request_parts[1]
    
    headers = {}
    for line in head_lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()
            
    # Reconstruct URL
    # Check if the path already contains a full URL (e.g., in proxy requests)
    if path.startswith('http://') or path.startswith('https://'):
        url = path
    else:
        host = headers.get('Host') or headers.get('host')
        if not host:
            # If no host header and path is not a full URL, we can't form a valid URL
            raise ValueError("Host header missing and path is not a full URL.")
        
        scheme = 'https' if ':443' in host else 'http'
        if not path.startswith('/'):
            path = '/' + path
        url = f"{scheme}://{host}{path}"

    return method, url, headers, body

def send_synchronized_request(request_id, method, url, headers, body, barrier, session, proxies):
    """
    Classic Request Runner (kept for proxy support/compatibility).
    """
    try:
        headers['X-Proxy-Tool-Internal'] = 'racer-request'
        
        # Capture raw request for logging
        headers_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
        try:
            body_str = body.decode('utf-8', errors='replace')
        except:
            body_str = str(body)
        raw_request_sent = f"{method} {url} HTTP/1.1\n{headers_str}\n\n{body_str}"

        try:
            barrier.wait(timeout=15)
        except threading.BrokenBarrierError:
            pass

        start_time = time.perf_counter()
        resp = session.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            proxies=proxies,
            verify=False,
            allow_redirects=False, 
            timeout=15
        )
        end_time = time.perf_counter()
        
        status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}"
        resp_headers = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
        raw_response = f"{status_line}\n{resp_headers}\n\n{resp.text}"

        return {
            "request_id": request_id,
            "status_code": resp.status_code,
            "response_length": len(resp.content),
            "execution_time_ms": int((end_time - start_time) * 1000),
            "raw_response": raw_response,
            "raw_request": raw_request_sent
        }
    except Exception as e:
        return {"request_id": request_id, "status_code": "ERR", "error_message": str(e)}

def send_turbo_request(request_id, host, port, scheme, payload, barrier, timeout=15):
    """
    Low-Level Socket Runner with Last-Byte Synchronization.
    This bypasses the requests library for maximum timing precision.
    """
    s = None
    try:
        # 1. Establish Socket Connection
        raw_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_s.settimeout(timeout)
        
        # Enable TCP_NODELAY to disable Nagle's Algorithm (Crucial for speed)
        raw_s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        if scheme == 'https':
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(raw_s, server_hostname=host)
        else:
            s = raw_s

        s.connect((host, port))

        # 2. Split Payload for Last-Byte Sync
        if len(payload) > 0:
            initial_payload = payload[:-1]
            last_byte = payload[-1:]
        else:
            initial_payload = payload
            last_byte = b''

        s.sendall(initial_payload)

        # 3. Wait at the Gate
        # Using a spin-wait or high-precision sync here
        try:
            barrier.wait(timeout=15)
        except threading.BrokenBarrierError:
            pass

        # 4. FIRE! (Send the last byte)
        # Minimize logic between the 'release' and the 'send'
        if last_byte:
            s.send(last_byte) # Use .send instead of .sendall for the single byte
        
        start_time = time.perf_counter()
        
        # 5. Read Response
        # We start timing AFTER the byte is released to get the most accurate 'Server Time'
        response_bytes = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                response_bytes += chunk
            except:
                break
        
        end_time = time.perf_counter()
        s.close()

        # 6. Parse Basic Response Info
        status_code = 0
        decoded_response = ""
        try:
            import gzip
            import io
            
            resp_str = response_bytes.decode('latin-1', errors='replace')
            headers_end = resp_str.find('\r\n\r\n')
            
            if ' ' in resp_str:
                first_line = resp_str.split('\r\n')[0]
                parts = first_line.split(' ')
                if len(parts) > 1: status_code = int(parts[1])

            if headers_end != -1:
                headers_part = resp_str[:headers_end].lower()
                body_part = response_bytes[headers_end+4:]
                
                # Handle Chunked Transfer Encoding
                if 'transfer-encoding: chunked' in headers_part:
                    try:
                        new_body = b""
                        pointer = 0
                        while pointer < len(body_part):
                            line_end = body_part.find(b"\r\n", pointer)
                            if line_end == -1: break
                            chunk_size_str = body_part[pointer:line_end].strip()
                            if not chunk_size_str: break
                            chunk_size = int(chunk_size_str, 16)
                            if chunk_size == 0: break
                            pointer = line_end + 2
                            new_body += body_part[pointer:pointer+chunk_size]
                            pointer += chunk_size + 2
                        body_part = new_body
                    except:
                        pass # Fallback to raw if parsing fails

                # Handle Gzip
                if 'content-encoding: gzip' in headers_part:
                    try:
                        with gzip.GzipFile(fileobj=io.BytesIO(body_part)) as f:
                            decoded_body = f.read().decode('utf-8', errors='replace')
                        decoded_response = resp_str[:headers_end+4] + decoded_body
                    except:
                        decoded_response = resp_str[:headers_end+4] + body_part.decode('utf-8', 'replace')
                else:
                    decoded_response = resp_str[:headers_end+4] + body_part.decode('utf-8', 'replace')
            else:
                decoded_response = resp_str
        except:
            decoded_response = response_bytes.decode('utf-8', errors='replace')

        return {
            "request_id": request_id,
            "status_code": status_code,
            "response_length": len(response_bytes),
            "execution_time_ms": int((end_time - start_time) * 1000),
            "raw_response": decoded_response,
            "raw_request": payload.decode('utf-8', errors='replace')
        }

    except Exception as e:
        if s: s.close()
        return {"request_id": request_id, "status_code": "ERR", "error_message": f"Turbo Error: {e}"}
