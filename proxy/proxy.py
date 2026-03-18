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
    def __init__(self, gui_queue: Queue, proxy_queue: Queue, host: str, port: int, scope_rules: list, match_replace_rules: list, http2: bool = True):
        self.gui_queue = gui_queue
        self.proxy_queue = proxy_queue
        self.host = host
        self.port = port
        self.http2 = http2
        self.scope_rules = scope_rules 
        self.match_replace_rules = match_replace_rules
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
        # Check if master is running and try to shut it down gracefully
        if self.master:
            if self.loop and self.loop.is_running():
                self.loop.call_soon_threadsafe(self.master.shutdown)
            else:
                self.master.shutdown()
        # Ensure the thread is given a chance to finish, or just let it die if daemon
        if self._proxy_thread and self._proxy_thread.is_alive():
            # Forcing a stop for a mitmproxy thread can be tricky.
            # Relying on master.shutdown() and daemon thread for now.
            pass

    def _run_proxy(self):
        """The target method for the proxy thread."""
        
        async def main():
            opts = Options(
                listen_host=self.host,
                listen_port=self.port,
                http2=self.http2,
                ssl_insecure=True,
            )
            self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self.loop = asyncio.get_running_loop()
            
            self.interceptor_addon = Interceptor(self.gui_queue, self.proxy_queue, self.scope_rules, self.match_replace_rules) 
            self.master.addons.add(self.interceptor_addon)

            try:
                await self.master.run()
            except asyncio.CancelledError:
                pass
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
            pass
        finally:
            if self.master and self.master.running:
                self.master.shutdown()
            if self.loop and self.loop.is_running(): # Check if loop is still running before stopping
                self.loop.stop()
            if self.loop and not self.loop.is_closed():
                self.loop.close()

    def get_scope_rules(self) -> list:
        """Returns the current list of scope rules."""
        return self.scope_rules

    def toggle_intercept(self, value: bool):
        """Thread-safe way to call the addon's toggle command."""
        if self.master and self.loop:
            # Check if master is running before calling commands, to prevent errors during shutdown
            if self.master.running:
                self.loop.call_soon_threadsafe(self.master.commands.call, "intercept.toggle", value)

    def update_scope_rules(self, new_rules: list):
        """Updates the scope rules in the running interceptor."""
        self.scope_rules = new_rules
        if self.master and self.loop and self.master.running:
             # We need to access the interceptor_addon directly. 
             # Since it's an instance variable, we can access it, but we should do it safely.
             # The interceptor's update_scope_rules simply sets a list, which is atomic enough for this purpose,
             # but running it on the loop is better practice if we were doing more.
             # For simple list assignment, direct access is often fine, but let's be safe and use call_soon_threadsafe
             # if we want to be strictly correct with asyncio, although accessing the addon directly is easier if we made it available.
             
             # Actually, we can just call the method on the addon instance directly if we are careful.
             # But since Interceptor is running in the asyncio loop, let's schedule the update on that loop.
             
             def _update():
                 if self.interceptor_addon:
                     self.interceptor_addon.update_scope_rules(new_rules)
            
             self.loop.call_soon_threadsafe(_update)

    def update_match_replace_rules(self, new_rules: list):
        """Updates the match and replace rules in the running interceptor."""
        self.match_replace_rules = new_rules
        if self.master and self.loop and self.master.running:
             def _update():
                 if self.interceptor_addon:
                     self.interceptor_addon.update_match_replace_rules(new_rules)
            
             self.loop.call_soon_threadsafe(_update)

    def is_url_in_scope(self, url: str) -> bool:
        """
        Public method to check if a URL is in scope using the interceptor's logic.
        This allows the GUI to apply scope filtering consistent with the proxy's behavior.
        """
        if self.interceptor_addon:
            return self.interceptor_addon._is_in_scope(url)
        return True # Default to in-scope if interceptor not initialized (should not happen in normal operation)

