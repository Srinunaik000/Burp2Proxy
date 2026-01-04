import asyncio
import threading
from queue import Queue

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from proxy.interceptor import Interceptor

class ProxyManager:
    """
    Manages the mitmproxy instance in a separate thread.
    """
    def __init__(self, gui_queue: Queue, proxy_queue: Queue, host: str, port: int):
        self.gui_queue = gui_queue
        self.proxy_queue = proxy_queue
        self.host = host
        self.port = port
        self._proxy_thread = None
        self.master = None
        self.loop = None

    def start(self):
        """Starts the proxy in a new thread."""
        if self._proxy_thread is not None:
            return  # Already running

        self._proxy_thread = threading.Thread(target=self._run_proxy, daemon=True) # Revert to daemon=True
        self._proxy_thread.start()

    def stop(self):
        """Stops the proxy."""
        pass

    def _run_proxy(self):
        """The target method for the proxy thread."""
        
        async def main():
            opts = Options(
                listen_host=self.host,
                listen_port=self.port,
                http2=True,
                ssl_insecure=True,
            )
            self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self.loop = asyncio.get_running_loop()
            
            interceptor_addon = Interceptor(self.gui_queue, self.proxy_queue)
            self.master.addons.add(interceptor_addon)

            print(f"Starting proxy server on {self.host}:{self.port}")
            try:
                await self.master.run()
            except asyncio.CancelledError:
                print("Mitmproxy master run cancelled.")
            finally:
                # Ensure all tasks are cancelled before the loop is closed by the runner
                tasks = [t for t in asyncio.all_tasks(self.loop) if t is not asyncio.current_task(self.loop)]
                for task in tasks:
                    task.cancel()
                
                # Wait for tasks to complete, with a timeout
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                
                # The runner will close the loop, so no need to self.loop.close() here.
                
        self.loop = None # Reset loop reference
        try:
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            self.loop = new_loop # Assign the loop to self.loop
            
            self.loop.run_until_complete(main()) # Run the main coroutine
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("Proxy server shutting down.")
        finally:
            if self.master and self.master.running:
                self.master.shutdown()
            if self.loop and self.loop.is_running(): # Check if loop is still running before stopping
                self.loop.stop()
            if self.loop and not self.loop.is_closed():
                self.loop.close()
            print("Proxy thread _run_proxy finished.") # Added print

    def toggle_intercept(self, value: bool):
        """Thread-safe way to call the addon's toggle command."""
        if self.master and self.loop:
            self.loop.call_soon_threadsafe(self.master.commands.call, "intercept.toggle", value)

