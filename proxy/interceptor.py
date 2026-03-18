import asyncio
from mitmproxy import http, connection, master
from mitmproxy.http import Headers
import queue
import threading
import uuid
import re 
from crawler.extractor import Extractor # Added for passive discovery
from proxy.linter import SecurityLinter

class Interceptor:
    def __init__(self, gui_queue: queue.Queue, proxy_queue: queue.Queue, scope_rules: list, match_replace_rules: list): 
        self.gui_queue = gui_queue
        self.proxy_queue = proxy_queue
        self.scope_rules = scope_rules 
        self.match_replace_rules = match_replace_rules
        self.intercept_enabled = threading.Event()
        self.active_flow = None  # The flow currently being intercepted in the GUI
        self.pending_flows = asyncio.Queue()  # Flows waiting to be intercepted

    def _apply_match_replace(self, flow: http.HTTPFlow):
        """Applies match and replace rules (supporting Regex) to the request."""
        if not self.match_replace_rules:
            return []

        applied_rules = []
        for i, rule in enumerate(self.match_replace_rules):
            if not rule.get("enabled", True):
                continue

            target = rule["type"] # "Request Header", "Request Body", "URL"
            action = rule.get("action", "Replace")
            is_test_only = (action == "Test Only")
            match_pattern = rule["match"]
            replace_str = rule["replace"]

            try:
                rule_applied = False
                if target == "URL" or target == "All":
                    if re.search(match_pattern, flow.request.url):
                        if not is_test_only:
                            flow.request.url = re.sub(match_pattern, replace_str, flow.request.url)
                        rule_applied = True
                
                if target == "Request Body" or target == "All":
                    content = flow.request.get_content(strict=False)
                    if content:
                        decoded = self.decode_content(content, flow.request.headers)
                        if re.search(match_pattern, decoded):
                            if not is_test_only:
                                new_content = re.sub(match_pattern, replace_str, decoded)
                                try:
                                    flow.request.content = new_content.encode('utf-8')
                                except:
                                    flow.request.content = new_content.encode('latin-1')
                            rule_applied = True

                if target == "Request Header" or target == "All":
                    # For headers, we check both key and value
                    if ":" in match_pattern:
                        h_name_pat, h_val_pat = match_pattern.split(":", 1)
                        h_name_pat = h_name_pat.strip()
                        h_val_pat = h_val_pat.strip()
                        
                        for name, value in flow.request.headers.items():
                            # Normalize whitespace for more robust matching
                            if re.search(h_name_pat, name.strip(), re.IGNORECASE) and re.search(h_val_pat, value.strip()):
                                if not is_test_only:
                                    flow.request.headers[name] = re.sub(h_val_pat, replace_str, value.strip())
                                rule_applied = True
                    else:
                        # Search in all header values
                        for name, value in flow.request.headers.items():
                            if re.search(match_pattern, value.strip()):
                                if not is_test_only:
                                    flow.request.headers[name] = re.sub(match_pattern, replace_str, value.strip())
                                rule_applied = True
                
                if rule_applied:
                    applied_rules.append(rule)
                    # Strip caching headers to force a fresh response from the server
                    # This prevents seeing stale/cached data after a swap.
                    if 'If-Modified-Since' in flow.request.headers:
                        del flow.request.headers['If-Modified-Since']
                    if 'If-None-Match' in flow.request.headers:
                        del flow.request.headers['If-None-Match']
                    # Also try to prevent browser from caching the response
                    flow.request.headers["Cache-Control"] = "no-cache"
                    flow.request.headers["Pragma"] = "no-cache"
            except Exception as e:
                pass
        
        return applied_rules

    def _is_in_scope(self, url: str) -> bool:
        """
        Checks if a given URL is within the defined scope rules.
        Logic:
        1. If there are no rules, everything is in scope.
        2. If there are 'Exclude' rules, and the URL matches any, it's out of scope.
        3. If there are 'Include' rules, and the URL matches one, it's in scope.
        4. If there are 'Include' rules, and the URL does not match any, it's out of scope.
        """
        if not self.scope_rules:
            return True # No rules, so everything is in scope

        is_explicitly_included = False
        has_include_rules = any(rule["type"] == "Include" for rule in self.scope_rules)

        for rule in self.scope_rules:
            try:
                if re.search(rule["pattern"], url):
                    if rule["type"] == "Exclude":
                        return False # Matches an exclude rule, so out of scope
                    elif rule["type"] == "Include":
                        is_explicitly_included = True # Matches an include rule
            except re.error:
                # Log or handle invalid regex pattern
                print(f"Warning: Invalid regex pattern in scope rule: {rule['pattern']}")
                continue # Skip this invalid rule

        if has_include_rules and not is_explicitly_included:
            return False # Has include rules, but URL didn't match any
            
        return True # Default to in-scope if not explicitly excluded or doesn't need to match an include

    def decode_content(self, content_bytes: bytes, headers: Headers) -> str:
        """Robust decoding that preserves binary data via latin-1 fallback and avoids footers."""
        if not content_bytes:
            return ""
        # Try UTF-8 first for best readability of modern text.
        # Fallback to latin-1 ensures NO bytes are lost or replaced with \ufffd, 
        # which prevents '400 Bad Request' errors when forwarding.
        try:
            return content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return content_bytes.decode('latin-1')

    def load(self, loader):
        loader.add_command("intercept.toggle", self.toggle_intercept)
        asyncio.create_task(self.process_proxy_queue())

    def toggle_intercept(self, value: bool):
        """Command to toggle interception on/off from another thread."""
        if value:
            self.intercept_enabled.set()
        else:
            self.intercept_enabled.clear()
            # Resume all flows and clear the queue
            asyncio.create_task(self._clear_and_resume_all())
            # Tell GUI to clear the intercept tab
            self.gui_queue.put({"type": "clear_intercept"})

    def update_scope_rules(self, new_rules: list):
        """Updates the scope rules dynamically."""
        self.scope_rules = new_rules

    def update_match_replace_rules(self, new_rules: list):
        """Updates the match and replace rules dynamically."""
        self.match_replace_rules = new_rules

    async def _clear_and_resume_all(self):
        """Resumes all pending and active flows."""
        # Resume the currently active flow
        if self.active_flow:
            try:
                self.active_flow.resume()
            except Exception as e:
                print(f"interceptor.py: Failed to resume active flow {self.active_flow.id}: {e}")
            self.active_flow = None

        # Resume all flows waiting in the queue
        while not self.pending_flows.empty():
            flow = await self.pending_flows.get()
            try:
                flow.resume()
            except Exception as e:
                print(f"interceptor.py: Failed to resume pending flow {flow.id}: {e}")

    async def _send_flow_to_gui(self, flow: http.HTTPFlow):
        """Puts the flow details onto the GUI queue."""
        request_content_bytes = flow.request.get_content(strict=False) or b''
        decoded_request_content = self.decode_content(request_content_bytes, flow.request.headers) # Reuse decode_content

        gui_item = {
            "type": "intercept_request",
            "flow_id": flow.id,
            "data": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": list(flow.request.headers.items()),
                "content": decoded_request_content, # Send decoded content
            }
        }
        self.gui_queue.put(gui_item)

    async def process_proxy_queue(self):
        while True:
            try:
                item = await asyncio.to_thread(self.proxy_queue.get)
                
                if not isinstance(item, dict):
                    continue
                
                flow_id = item.get("flow_id")
                command = item.get("command")

                # Ensure the command is for the currently active flow
                if self.active_flow and flow_id == self.active_flow.id:
                    if command == "forward":
                        updated_data = item["data"]
                        
                        # 1. Update core fields first. 
                        # Mitmproxy's .url setter automatically updates pseudo-headers for H2.
                        self.active_flow.request.method = updated_data["method"]
                        self.active_flow.request.url = updated_data["url"]
                        
                        content = updated_data["content"]
                        if isinstance(content, str):
                            try:
                                self.active_flow.request.content = content.encode('utf-8')
                            except:
                                self.active_flow.request.content = content.encode('latin-1')
                        else:
                            self.active_flow.request.content = content
                        
                        # 2. Surgical header update
                        # We MUST preserve pseudo-headers (:authority, etc.) for H2 integrity.
                        headers = self.active_flow.request.headers
                        
                        # Identify if this is likely an H2 request by checking if it has pseudo-headers
                        # or by checking flow.request.http_version.
                        is_h2 = (getattr(self.active_flow.request, "http_version", "") == "HTTP/2.0") or \
                                any(k.startswith(':') for k in headers.keys())
                        
                        # Remove all existing standard (non-pseudo) headers.
                        for k in [k for k in headers.keys() if not k.startswith(':')]:
                            del headers[k]
                        
                        # Add headers from the GUI.
                        for k, v in updated_data["headers"]:
                            # Skip pseudo-headers (mitmproxy already updated them via .url setter)
                            if k.startswith(':'): continue
                            
                            k_lower = k.lower()
                            
                            # H2 SPEC: Avoid sending 'Host' if ':authority' exists.
                            if is_h2 and k_lower == "host":
                                continue

                            # Skip Content-Length - mitmproxy will re-add it correctly when resuming.
                            if k_lower == "content-length":
                                continue
                            
                            try:
                                # Strip whitespace from user-provided values from the GUI
                                headers.add(k.strip(), v.strip())
                            except Exception as he:
                                # Fallback for binary/special characters
                                try:
                                    headers.add(k.strip().encode('latin-1'), v.strip().encode('latin-1'))
                                except: pass
                        
                        # Final scrub before resuming
                        self._scrub_headers(self.active_flow.request.headers)
                        self.active_flow.resume()
                        
                    elif command == "drop":
                        self.active_flow.response = http.Response.make(
                            403,
                            b"Dropped by Proxy Tool",
                            {
                                b"Content-Type": b"text/plain",
                                b"Content-Length": str(len(b"Dropped by Proxy Tool")).encode(),
                            }
                        )
                        self.active_flow.resume()

                    # The flow is handled, clear the active slot
                    self.active_flow = None

                    # Check for the next pending flow
                    if not self.pending_flows.empty():
                        next_flow = await self.pending_flows.get()
                        self.active_flow = next_flow
                        await self._send_flow_to_gui(self.active_flow)

            except Exception as e:
                import traceback
                traceback.print_exc()

    def _scrub_headers(self, headers: Headers):
        """Removes leading/trailing whitespace from header keys and values to prevent H2 protocol errors."""
        # Create a list of current headers to avoid modification issues during iteration
        header_items = list(headers.items())
        headers.clear()
        for k, v in header_items:
            # Strip whitespace from both key and value
            clean_k = k.strip()
            clean_v = v.strip()
            # Ensure we don't accidentally remove pseudo-headers like :authority
            if clean_k:
                headers.add(clean_k, clean_v)

    def configure(self, updated):
        """Monitor configuration changes to the mitmproxy core."""
        if "http2" in updated:
            pass # We can react to option changes if needed

    def clientconnect(self, layer):
        """Fired when a client connects to the proxy."""
        # This is a low-level hook. If we wanted to force protocol at the socket level,
        # we could modify the layer here. However, mitmproxy's options usually handle this.
        pass

    async def request(self, flow: http.HTTPFlow):
        # Ignore requests sent from our own repeater
        if 'X-Proxy-Tool-Internal' in flow.request.headers:
            flow.in_scope = False # Mark as out of scope for logging in response
            return

        # Scrub headers to prevent H2 protocol errors (e.g., trailing whitespace)
        self._scrub_headers(flow.request.headers)

        flow.id = str(uuid.uuid4())
        # Capture client address to distinguish between sessions
        client_addr = flow.client_conn.address[0] + ":" + str(flow.client_conn.address[1])
        flow.metadata["client_addr"] = client_addr

        # We still calculate in_scope so the GUI can use it for optional filtering
        flow.in_scope = self._is_in_scope(flow.request.pretty_url)

        # 1. Capture original request BEFORE any modifications
        original_req_data = {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": list(flow.request.headers.items()),
            "content": self.decode_content(flow.request.get_content(strict=False) or b'', flow.request.headers)
        }
        flow.metadata["original_request_for_log"] = original_req_data

        # 2. Apply Match and Replace rules (Regex)
        applied_rules = self._apply_match_replace(flow)
        if applied_rules:
            flow.metadata["applied_match_replace_rules"] = applied_rules

        # If intercept is enabled, we intercept EVERYTHING. 
        if self.intercept_enabled.is_set():
            flow.intercept() 
        # The user specifically requested that scope should NOT block interception.
        if self.intercept_enabled.is_set():
            flow.intercept()  # Always intercept the flow first

            if not self.active_flow:
                # If no flow is active, make this the active one and send to GUI
                self.active_flow = flow
                await self._send_flow_to_gui(flow)
            else:
                # If a flow is already active, add this one to the pending queue
                await self.pending_flows.put(flow)

    def response(self, flow: http.HTTPFlow):
        # Ensure flow has an ID
        if not hasattr(flow, 'id'):
            flow.id = str(uuid.uuid4())
        
        # Scrub headers in response to prevent issues when forwarding to the client
        if flow.response:
            self._scrub_headers(flow.response.headers)
        
        # We no longer return early if not in scope. 
        # History will now capture everything, allowing the user to filter in the UI.
        
        request_content_bytes = flow.request.get_content(strict=False) or b''
        decoded_request_content = self.decode_content(request_content_bytes, flow.request.headers)

        response_content_bytes = flow.response.get_content(strict=False) or b''
        decoded_response_content = self.decode_content(response_content_bytes, flow.response.headers)

        full_flow = {
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": list(flow.request.headers.items()),
                "content": decoded_request_content,
            },
            "response": {
                "status_code": flow.response.status_code if flow.response else "ERR",
                "headers": list(flow.response.headers.items()) if flow.response else [],
                "content": decoded_response_content,
            } if flow.response else None
        }

        gui_item = {
            "type": "flow_summary",
            "flow_id": flow.id,
            "data": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "status_code": flow.response.status_code if flow.response else "ERR",
                "content_length": len(response_content_bytes),
                "in_scope": getattr(flow, "in_scope", True), # Include in_scope flag
                "client": flow.metadata.get("client_addr", "Unknown")
            },
            "full_flow": full_flow
        }
        self.gui_queue.put(gui_item)

        # Check if Match and Replace rules were applied
        applied_rules = flow.metadata.get("applied_match_replace_rules", [])
        if applied_rules:
            gui_item_mr = {
                "type": "match_replace_log",
                "flow_id": flow.id,
                "applied_rules": applied_rules,
                "data": gui_item["data"],
                "full_flow": full_flow,
                "original_request": flow.metadata.get("original_request_for_log"),
                "client": flow.metadata.get("client_addr", "Unknown")
            }
            self.gui_queue.put(gui_item_mr)

        # --- PASSIVE SECURITY SCANNING ---
        # Run the security linter on the flow
        security_issues = SecurityLinter.run_checks(flow)
        if security_issues:
            self.gui_queue.put({
                "type": "passive_security_alert",
                "flow_id": flow.id,
                "url": flow.request.pretty_url,
                "issues": security_issues
            })

        # --- PASSIVE DISCOVERY ---
        # Scan HTML or JavaScript for new links to build the site map automatically
        if flow.response and flow.response.headers.get("Content-Type", ""):
            ct = flow.response.headers.get("Content-Type", "").lower()
            if "text/html" in ct or "javascript" in ct:
                decoded_response_content = self.decode_content(flow.response.get_content(strict=False) or b'', flow.response.headers)
                discovered_links = Extractor.extract_links(decoded_response_content, flow.request.pretty_url)
                if discovered_links:
                    # Identify 'Interesting' files
                    sensitive_patterns = [r"\.env", r"\.git", r"\.sql", r"config", r"backup", r"admin", r"password", r"secret"]
                    flagged_links = []
                    for link in discovered_links:
                        is_interesting = any(re.search(pat, link, re.I) for pat in sensitive_patterns)
                        flagged_links.append({"url": link, "interesting": is_interesting})

                    self.gui_queue.put({
                        "type": "passive_discovery",
                        "base_url": flow.request.pretty_url,
                        "flagged_links": flagged_links
                    })

    def websocket_start(self, flow: http.HTTPFlow):
        """Called when a WebSocket connection is established."""
        if not hasattr(flow, 'id'):
            flow.id = str(uuid.uuid4())
        
        # Process all websockets regardless of scope (GUI will filter if needed)
        gui_item = {
            "type": "websocket_flow",
            "flow_id": flow.id,
            "data": {
                "event": "start",
                "url": flow.request.pretty_url
            }
        }
        self.gui_queue.put(gui_item)

    def websocket_message(self, flow: http.HTTPFlow):
        """Called when a WebSocket message is received or sent."""
        if not hasattr(flow, 'id'):
            return

        message = flow.websocket.messages[-1]
        
        gui_item = {
            "type": "websocket_flow",
            "flow_id": flow.id,
            "data": {
                "event": "message",
                "from_client": message.from_client,
                "content": message.content,
                "timestamp": message.timestamp
            }
        }
        self.gui_queue.put(gui_item)

    def websocket_end(self, flow: http.HTTPFlow):
        """Called when a WebSocket connection is closed."""
        if not hasattr(flow, 'id'):
            return

        gui_item = {
            "type": "websocket_flow",
            "flow_id": flow.id,
            "data": {
                "event": "end"
            }
        }
        self.gui_queue.put(gui_item)
