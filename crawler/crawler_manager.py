import threading
import queue
import requests
import time
import random
import urllib3
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from crawler.extractor import Extractor

# Suppress SSL warnings for the crawler
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CrawlerManager:
    def __init__(self, base_domain, scope_rules, results_callback, log_callback, max_depth=3, max_threads=5, headers=None, proxy_url=None, delay_ms=100):
        self.base_domain = base_domain.lower()
        self.scope_rules = scope_rules
        self.results_callback = results_callback 
        self.log_callback = log_callback 
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.delay_ms = delay_ms
        
        self.visited_urls = set()
        self.queue = queue.Queue()
        self.is_running = False
        self.stop_event = threading.Event()
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProxyTool-Crawler/1.1",
            "X-Proxy-Tool-Internal": "true" # Identify crawler traffic in proxy
        })
        if headers:
            self.session.headers.update(headers)
        
        if proxy_url:
            self.session.proxies = {"http": proxy_url, "https": proxy_url}
        
        self.session.verify = False 
        self.active_tasks = 0
        self.task_lock = threading.Lock()

    def _is_in_scope(self, url):
        """Checks if the URL matches the target domain or subdomains."""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            return netloc == self.base_domain or netloc.endswith("." + self.base_domain)
        except:
            return False

    def start(self, start_url):
        if self.is_running:
            return
        
        self.is_running = True
        self.stop_event.clear()
        self.visited_urls.clear()
        self.queue.put((start_url, 0)) 
        
        threading.Thread(target=self._run_crawler, daemon=True).start()

    def stop(self):
        self.stop_event.set()
        self.is_running = False

    def _run_crawler(self):
        self.log_callback(f"Starting crawl for domain: {self.base_domain}")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while not self.stop_event.is_set():
                try:
                    # Non-blocking get to check stop_event frequently
                    url, depth = self.queue.get(timeout=0.5)
                except queue.Empty:
                    # If queue is empty and no tasks are running, we are done
                    with self.task_lock:
                        if self.active_tasks == 0:
                            break
                    continue

                if url in self.visited_urls or depth > self.max_depth:
                    continue

                self.visited_urls.add(url)
                
                with self.task_lock:
                    self.active_tasks += 1
                
                executor.submit(self._crawl_wrapper, url, depth)

        self.is_running = False
        self.log_callback("Crawl finished.")

    def _crawl_wrapper(self, url, depth):
        """Wrapper to track active tasks."""
        try:
            self._crawl_page(url, depth)
        finally:
            with self.task_lock:
                self.active_tasks -= 1

    def _crawl_page(self, url, depth):
        if self.stop_event.is_set():
            return

        try:
            # 1. Respect the delay with jitter to avoid IP blocks
            if self.delay_ms > 0:
                # Add +/- 20% jitter
                jitter = random.uniform(0.8, 1.2)
                actual_sleep = (self.delay_ms / 1000.0) * jitter
                time.sleep(actual_sleep)

            # We don't log every single CSS/JS etc if the extractor already filters them, 
            # but let's log the attempt
            response = self.session.get(url, timeout=5, allow_redirects=True)
            
            # 2. Extract parameters and report
            # We analyze HTML and also URLs with query strings
            html = response.text if "text/html" in response.headers.get("Content-Type", "").lower() else ""
            
            param_data = Extractor.extract_parameters(html, url)
            if param_data["get_params"] or param_data["post_params"]:
                self.results_callback(param_data)
                self.log_callback(f"[!] Found Params: {url}")

            # 3. Extract links for further crawling
            if depth < self.max_depth and html:
                links = Extractor.extract_links(html, url)
                for link in links:
                    if self._is_in_scope(link) and link not in self.visited_urls:
                        if not Extractor.is_static_asset(link):
                            self.queue.put((link, depth + 1))

        except Exception as e:
            # Silent fail for individual pages to keep crawl moving
            pass
