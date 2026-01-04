import asyncio
from mitmproxy import http, connection, master
from mitmproxy.http import Headers
import queue
import threading
import uuid

class Interceptor:
    def __init__(self, gui_queue: queue.Queue, proxy_queue: queue.Queue):
        self.gui_queue = gui_queue
        self.proxy_queue = proxy_queue
        self.intercept_enabled = threading.Event()  # FIXED: Back to Event()
        self.live_flows = {}

    def load(self, loader):
        loader.add_command("intercept.toggle", self.toggle_intercept)
        asyncio.create_task(self.process_proxy_queue())

    def toggle_intercept(self, value: bool):
        """Command to toggle interception on/off from another thread."""
        self.intercept_enabled.clear()
        if value:
            self.intercept_enabled.set()
        else:
            # INSTANT CLEAR: Resume all pending flows + clear GUI
            self._resume_all_pending_flows()
            # Tell GUI to clear intercept tab
            self.gui_queue.put({"type": "clear_intercept"})

    def _resume_all_pending_flows(self):
        """INSTANTLY resume all pending flows (no delay) + clear dict."""
        pending_flows = list(self.live_flows.values())
        resumed_count = 0
        for flow in pending_flows:
            try:
                flow.resume()
                resumed_count += 1
            except Exception as e:
                print(f"interceptor.py: Failed to resume flow {flow.id}: {e}")
        self.live_flows.clear()

    async def process_proxy_queue(self):
        while True:
            try:
                item = await asyncio.to_thread(self.proxy_queue.get)
                
                if not isinstance(item, dict):
                    print(f"interceptor.py: WARNING - expected dict from proxy_queue, got {type(item)}. Ignoring.")
                    continue
                
                flow_id = item.get("flow_id")
                command = item.get("command")

                if command == "forward" and flow_id in self.live_flows:
                    flow = self.live_flows.pop(flow_id)
                    updated_data = item["data"]
                    
                    flow.request.method = updated_data["method"]
                    flow.request.content = updated_data["content"]
                    
                    new_url = updated_data["url"]
                    if "192.168.1.7:5001" in new_url or "127.0.0.1" in new_url or "localhost" in new_url:
                        if new_url.startswith("https://"):
                            new_url = new_url.replace("https://", "http://")
                    
                    flow.request.url = new_url
                    flow.request.headers = Headers([(k.encode("utf-8"), v.encode("utf-8")) for k, v in updated_data["headers"]])
                    
                    flow.resume()
                    
                elif command == "drop" and flow_id in self.live_flows:
                    flow = self.live_flows.pop(flow_id)
                    
                    flow.response = http.Response.make(
                        403,
                        b"Dropped by Proxy Tool",
                        {
                            b"Content-Type": b"text/plain",
                            b"Content-Length": str(len(b"Dropped by Proxy Tool")).encode(),
                        }
                    )
                    flow.resume()

            except Exception as e:
                print(f"Error in proxy queue processor: {e}")
                import traceback
                traceback.print_exc()

    async def request(self, flow: http.HTTPFlow):
        # Ignore requests sent from our own repeater
        if 'X-Proxy-Tool-Internal' in flow.request.headers:
            return

        flow.id = str(uuid.uuid4())

        if self.intercept_enabled.is_set() and "127.0.0.1" not in flow.request.host:  # FIXED
            self.live_flows[flow.id] = flow
            
            gui_item = {
                "type": "intercept_request",
                "flow_id": flow.id,
                "data": {
                    "method": flow.request.method,
                    "url": flow.request.pretty_url,
                    "headers": list(flow.request.headers.items()),
                    "content": flow.request.get_content(strict=False) or b'',
                }
            }
            self.gui_queue.put(gui_item)
            flow.intercept()

    def response(self, flow: http.HTTPFlow):
        if not hasattr(flow, 'id'):
            flow.id = str(uuid.uuid4())

        gui_item = {
            "type": "flow_summary",
            "flow_id": flow.id,
            "data": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "status_code": flow.response.status_code if flow.response else "ERR",
                "content_length": len(flow.response.content) if flow.response and flow.response.content else 0,
            },
            "full_flow": {
                "request": {
                    "method": flow.request.method,
                    "url": flow.request.pretty_url,
                    "headers": list(flow.request.headers.items()),
                    "content": flow.request.get_content(strict=False) or b'',
                },
                "response": {
                    "status_code": flow.response.status_code if flow.response else "ERR",
                    "headers": list(flow.response.headers.items()) if flow.response else [],
                    "content": flow.response.get_content(strict=False) or b'',
                } if flow.response else None
            }
        }
        self.gui_queue.put(gui_item)
