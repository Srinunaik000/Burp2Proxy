
import brotli # Added for Brotli decompression
import zstandard # Added for ZSTD decompression

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import queue
import threading
import config
import os
import jwt
import json
import base64
import asyncio # Added for Playwright
import time # Added for the new browser waiting loop
import urllib.parse # Added for URL encoding/decoding
import re # Added for regular expression validation

from proxy.proxy import ProxyManager
from crawler.crawler_manager import CrawlerManager # Added for crawling support

import webbrowser
import tempfile

from tkhtmlview import HTMLScrolledText
from playwright.sync_api import sync_playwright # Added for Playwright
import random
from tkinter import filedialog
import csv
import google.genai as genai
import requests

import secrets # Added for generating secure HS256 keys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Burp2Proxy")
        self.root.geometry("900x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Load configuration
        self.config = config.load_config()

        # Communication queues
        self.gui_queue = queue.Queue()
        self.proxy_queue = queue.Queue()

        # Proxy Manager
        self.proxy_manager = ProxyManager(
            self.gui_queue,
            self.proxy_queue,
            host=self.config["host"],
            port=self.config["port"],
            scope_rules=self.config["scope_rules"],
            match_replace_rules=self.config.get("match_replace_rules", []),
            http2=self.config.get("http2", True)
        )
        self.proxy_manager.start()

        # Initialize AI
        self.ai_enabled = False
        self.ai_history = [] # For chat memory
        self._setup_ai_client()

        # Store full flow data
        self.flows = {}
        # Store flows where match & replace rules were applied
        self.match_replace_flows = {}
        # Store detected vulnerabilities
        self.vulnerabilities = {}
        self.vuln_counter = 0
        # Store all flow summaries for filtering
        self.all_flows_summary = []
        self.current_filter_domain = None
        self.current_filter_method = None
        self.repeater_tabs = {}
        self.repeater_tab_counter = 0
        self.intercepted_flow = None
        self.intercept_search_matches = [] # To store indices of all found matches
        self.current_intercept_match_index = -1 # To keep track of the currently highlighted match

        # UI Setup
        self._init_ui()
        
        # Start processing the queue from the proxy
        self.process_gui_queue()

    def _init_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.proxy_tab = ttk.Frame(self.notebook)
        self.target_tab = ttk.Frame(self.notebook)
        self.repeater_tab = ttk.Frame(self.notebook)
        self.intruder_tab = ttk.Frame(self.notebook) # New Intruder Tab
        self.decoder_tab = ttk.Frame(self.notebook)
        self.ai_tab = ttk.Frame(self.notebook)
        self.racer_tab = ttk.Frame(self.notebook) # New Race Condition Tab
        self.vulnerability_tab = ttk.Frame(self.notebook) # New Vulnerabilities Tab
        self.match_replace_log_tab = ttk.Frame(self.notebook) # New Match & Replace Log Tab
        self.config_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.proxy_tab, text="Proxy")
        self.notebook.add(self.target_tab, text="Target")
        self.notebook.add(self.repeater_tab, text="Repeater")
        self.notebook.add(self.intruder_tab, text="Intruder") # Added Intruder
        self.notebook.add(self.decoder_tab, text="Decoder")
        self.notebook.add(self.ai_tab, text="AI Assistant")
        self.notebook.add(self.racer_tab, text="Race Condition")
        self.notebook.add(self.vulnerability_tab, text="Vulnerabilities") # Added Vulnerabilities
        self.notebook.add(self.match_replace_log_tab, text="Match & Replace Log")
        self.notebook.add(self.config_tab, text="Configuration")

        # --- Proxy Tab ---
        self._init_proxy_tab()

        # --- Target Tab ---
        self._init_target_tab()
        
        # --- Repeater Tab ---
        self._init_repeater_tab()

        # --- Decoder Tab ---
        self._init_decoder_tab()

        # --- Intruder Tab ---
        self._init_intruder_tab()

        # --- AI Assistant Tab ---
        self._init_ai_tab()

        # --- Racer Tab ---
        self._init_racer_tab()

        # --- Vulnerabilities Tab ---
        self._init_vulnerability_tab()

        # --- Match & Replace Log Tab ---
        self._init_match_replace_log_tab()

        # --- Config Tab ---
        self._init_config_tab()

    def launch_browser_via_proxy(self):
        """Launches a Playwright browser configured to use the proxy."""
        host = self.config["host"]
        port = self.config["port"]
        proxy_server = f"http://{host}:{port}"

        def _launch():
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(
                        proxy={"server": proxy_server},
                        headless=False, # Run in headful mode
                        args=["--ignore-certificate-errors", "--proxy-bypass-list=''"]
                    )
                    page = browser.new_page()
                    page.goto("https://www.google.com") # Default page
                    
                    # Wait for the browser to be disconnected by the user
                    while browser.is_connected():
                        time.sleep(1)

            except Exception as e:
                # Ensure error is shown in the main GUI thread
                self.root.after(0, messagebox.showerror, "Browser Launch Error", f"Failed to launch browser: {e}")

        # Run in a separate thread to avoid blocking the GUI
        threading.Thread(target=_launch, daemon=True).start()

    def _setup_ai_client(self):
        """Sets up the AI client based on current provider."""
        self.ai_enabled = False
        api_key = self.config.get("gemini_api_key")
        provider = self.config.get("ai_provider", "Gemini")
        
        if not api_key:
            return

        try:
            if provider == "Gemini":
                genai.configure(api_key=api_key)
                model_name = self.config.get("ai_model_name", "gemini-2.0-flash")
                self.ai_model = genai.GenerativeModel(model_name)
                self.ai_enabled = True
            else:
                # Groq / OpenAI Style
                # We don't need a persistent model object for requests-based providers
                self.ai_enabled = True 
        except Exception as e:
            print(f"Failed to initialize AI: {e}")



    def change_request_method(self, widget, new_method):
        """Surgically changes the HTTP method and migrates parameters between URL and body."""
        raw_content = widget.get("1.0", tk.END).strip()
        if not raw_content: return
        
        try:
            # 1. Parse current parts
            if "\r\n\r\n" in raw_content:
                head, body = raw_content.split("\r\n\r\n", 1)
            elif "\n\n" in raw_content:
                head, body = raw_content.split("\n\n", 1)
            else:
                head = raw_content
                body = ""
            
            lines = head.split("\n")
            request_line = lines[0]
            header_lines = [h.strip() for h in lines[1:] if h.strip()]
            
            rl_parts = request_line.split(" ", 2)
            if len(rl_parts) < 2: return
            old_method = rl_parts[0].upper()
            new_method = new_method.upper()
            url = rl_parts[1]
            version = rl_parts[2] if len(rl_parts) > 2 else "HTTP/1.1"

            # 2. Extract parameters intelligently
            # From URL
            parsed_url = urllib.parse.urlparse(url)
            url_params_raw = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            url_params = {k: v[0] for k, v in url_params_raw.items() if v}

            # From Body based on Content-Type
            body_params = {}
            current_ct = ""
            for h in header_lines:
                if h.lower().startswith("content-type:"):
                    current_ct = h.split(":", 1)[1].strip().lower()
                    break
            
            clean_body = body.strip()
            if clean_body:
                if "application/json" in current_ct or (clean_body.startswith("{") and clean_body.endswith("}")):
                    try:
                        loaded = json.loads(clean_body)
                        if isinstance(loaded, dict):
                            body_params = {k: str(v) for k, v in loaded.items()}
                    except: pass
                
                # Fallback to form-encoded if JSON failed or not detected
                if not body_params:
                    body_params_raw = urllib.parse.parse_qs(clean_body, keep_blank_values=True)
                    body_params = {k: v[0] for k, v in body_params_raw.items() if v}

            # Merge all params (URL params take precedence or append)
            all_params = {**body_params, **url_params}

            # 3. Apply Migration Logic
            new_url_path = parsed_url.path
            if not new_url_path: new_url_path = "/"
            new_body = ""
            new_headers = []

            if new_method == "GET":
                if all_params:
                    new_query = urllib.parse.urlencode(all_params)
                    url = f"{parsed_url.scheme}://{parsed_url.netloc}{new_url_path}?{new_query}" if parsed_url.netloc else f"{new_url_path}?{new_query}"
                else:
                    url = f"{parsed_url.scheme}://{parsed_url.netloc}{new_url_path}" if parsed_url.netloc else new_url_path
                new_body = ""
                new_headers = [h for h in header_lines if not h.lower().startswith(("content-type", "content-length"))]
            
            elif new_method in ["POST", "PUT", "PATCH"]:
                if all_params:
                    new_body = json.dumps(all_params, indent=4)
                url = f"{parsed_url.scheme}://{parsed_url.netloc}{new_url_path}" if parsed_url.netloc else new_url_path
                
                # Update/Add application/json header
                has_ct = False
                for h in header_lines:
                    if h.lower().startswith("content-type:"):
                        new_headers.append("Content-Type: application/json")
                        has_ct = True
                    elif not h.lower().startswith("content-length:"):
                        new_headers.append(h)
                if not has_ct:
                    new_headers.append("Content-Type: application/json")
            
            else:
                # Other methods
                new_body = body
                new_headers = header_lines

            # 4. Reconstruct and Refresh
            new_request_line = f"{new_method} {url} {version}"
            final_head = new_request_line + "\n" + "\n".join(new_headers)
            final_request = final_head.strip() + "\n\n" + new_body
            
            self.safe_insert_text(widget, final_request)

        except Exception as e:
            print(f"Error in method migration: {e}")

    def _init_proxy_tab(self):
        proxy_notebook = ttk.Notebook(self.proxy_tab)
        proxy_notebook.pack(fill=tk.BOTH, expand=True)

        interceptor_tab = ttk.Frame(proxy_notebook)
        http_history_tab = ttk.Frame(proxy_notebook)
        self.websockets_tab = ttk.Frame(proxy_notebook)

        proxy_notebook.add(interceptor_tab, text="Interceptor")
        proxy_notebook.add(http_history_tab, text="HTTP History")
        proxy_notebook.add(self.websockets_tab, text="WebSockets")

        # --- Interceptor Tab ---
        interceptor_controls_frame = ttk.Frame(interceptor_tab)
        interceptor_controls_frame.pack(fill=tk.X, padx=5, pady=5)

        self.intercept_button = ttk.Button(
            interceptor_controls_frame, text="Intercept: OFF", command=self.toggle_intercept
        )
        self.intercept_button.pack(side=tk.LEFT)
        self.is_intercepting = False

        self.forward_button = ttk.Button(
            interceptor_controls_frame, text="Forward", command=self.forward_intercepted_request, state="disabled"
        )
        self.forward_button.pack(side=tk.LEFT, padx=(5, 0))

        self.drop_button = ttk.Button(
            interceptor_controls_frame, text="Drop", command=self.drop_intercepted_request, state="disabled"
        )
        self.drop_button.pack(side=tk.LEFT, padx=(5, 0))

        # --- Interceptor Search Controls ---
        interceptor_search_frame = ttk.Frame(interceptor_tab)
        interceptor_search_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(interceptor_search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.intercept_search_keyword_var = tk.StringVar()
        self.intercept_search_entry = ttk.Entry(interceptor_search_frame, textvariable=self.intercept_search_keyword_var, width=40)
        self.intercept_search_entry.pack(side=tk.LEFT, padx=(0, 5), expand=True, fill=tk.X)
        self.intercept_search_entry.bind("<Return>", self.search_intercepted_request)

        self.intercept_prev_button = ttk.Button(interceptor_search_frame, text="<", command=self.prev_intercept_match, width=3, state="disabled")
        self.intercept_prev_button.pack(side=tk.LEFT, padx=(0, 2))

        self.intercept_next_button = ttk.Button(interceptor_search_frame, text=">", command=self.next_intercept_match, width=3, state="disabled")
        self.intercept_next_button.pack(side=tk.LEFT, padx=(0, 2))

        self.intercept_search_status_label = ttk.Label(interceptor_search_frame, text="")
        self.intercept_search_status_label.pack(side=tk.LEFT, padx=(5,0))

        self.intercepted_request_text = scrolledtext.ScrolledText(interceptor_tab, wrap=tk.WORD, height=10)
        self.intercepted_request_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure tags for highlighting
        self.intercepted_request_text.tag_configure('search_highlight', background='yellow', foreground='black')
        self.intercepted_request_text.tag_configure('active_search_highlight', background='orange', foreground='black')

        # --- Interceptor Context Menu ---
        self.interceptor_context_menu = tk.Menu(self.root, tearoff=0)
        self.interceptor_context_menu.add_command(label="Copy URL", command=self.copy_intercepted_url)
        self.interceptor_context_menu.add_command(label="Send to Repeater", command=self.send_intercepted_to_repeater)
        self.interceptor_context_menu.add_command(label="Send to Intruder", command=self.send_intercepted_to_intruder)
        self.interceptor_context_menu.add_command(label="Send to Race Condition", command=self.send_intercepted_to_racer)
        
        method_menu = tk.Menu(self.interceptor_context_menu, tearoff=0)
        for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
            method_menu.add_command(label=m, command=lambda x=m: self.change_request_method(self.intercepted_request_text, x))
        self.interceptor_context_menu.add_cascade(label="Change Method", menu=method_menu)
        
        self.intercepted_request_text.bind("<Button-3>", self.show_interceptor_context_menu)

        # --- Repeater Context Menu ---
        self.repeater_context_menu = tk.Menu(self.root, tearoff=0)
        self.repeater_context_menu.add_command(label="Copy URL", command=self.copy_repeater_url)
        self.repeater_context_menu.add_command(label="Send to Intruder", command=self.send_repeater_to_intruder)
        self.repeater_context_menu.add_command(label="Send to Race Condition", command=self.send_repeater_to_racer)
        
        rep_method_menu = tk.Menu(self.repeater_context_menu, tearoff=0)
        for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
            # Need to find current active repeater widget at runtime
            rep_method_menu.add_command(label=m, command=lambda x=m: self._change_repeater_method(x))
        self.repeater_context_menu.add_cascade(label="Change Method", menu=rep_method_menu)

        # --- HTTP History Tab ---
        history_controls_frame = ttk.Frame(http_history_tab)
        history_controls_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(history_controls_frame, text="Filter Domain:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_domain_var = tk.StringVar()
        self.filter_domain_entry = ttk.Entry(history_controls_frame, textvariable=self.filter_domain_var, width=30)
        self.filter_domain_entry.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Label(history_controls_frame, text="Method:").pack(side=tk.LEFT, padx=(5, 5))
        self.filter_method_var = tk.StringVar()
        self.filter_method_combo = ttk.Combobox(
            history_controls_frame,
            textvariable=self.filter_method_var,
            values=["ALL", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
            width=10
        )
        self.filter_method_combo.set("ALL")
        self.filter_method_combo.pack(side=tk.LEFT, padx=(0, 5))

        filter_button = ttk.Button(history_controls_frame, text="Filter", command=self.apply_filter)
        filter_button.pack(side=tk.LEFT, padx=(0, 2))

        clear_filter_button = ttk.Button(history_controls_frame, text="Clear Filter", command=self.clear_filter)
        clear_filter_button.pack(side=tk.LEFT, padx=(0, 2))

        clear_history_button = ttk.Button(history_controls_frame, text="Clear All History", command=self.clear_history)
        clear_history_button.pack(side=tk.LEFT)

        self.filter_history_by_scope_var = tk.BooleanVar(value=False)
        filter_scope_checkbox = ttk.Checkbutton(
            history_controls_frame,
            text="Filter by Scope",
            variable=self.filter_history_by_scope_var,
            command=self._repopulate_history_table
        )
        filter_scope_checkbox.pack(side=tk.LEFT, padx=(10, 0))

        # History Table (Treeview)
        table_frame = ttk.Frame(http_history_tab)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.history_table = ttk.Treeview(
            table_frame,
            columns=("id", "method", "url", "status"),
            show="headings",
            selectmode="extended" # Allows selecting multiple rows with Shift/Ctrl
        )
        self.history_table.heading("id", text="ID")
        self.history_table.heading("method", text="Method")
        self.history_table.heading("url", text="URL")
        self.history_table.heading("status", text="Status")

        self.history_table.column("id", width=50, anchor=tk.W)
        self.history_table.column("method", width=80, anchor=tk.W)
        self.history_table.column("url", width=500, anchor=tk.W)
        self.history_table.column("status", width=80, anchor=tk.CENTER)
        
        # Hide the 'id' column from view, but use it for data mapping
        self.history_table['displaycolumns'] = ('method', 'url', 'status')

        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.history_table.yview)
        self.history_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure Method Tags for History
        self.history_table.tag_configure("meth_GET", foreground="#0000FF") # Blue
        self.history_table.tag_configure("meth_POST", foreground="#008000") # Green
        self.history_table.tag_configure("meth_PUT", foreground="#cc7a00") # Orange
        self.history_table.tag_configure("meth_DELETE", foreground="#ff0000") # Red
        self.history_table.tag_configure("meth_OTHER", foreground="#800080") # Purple

        # Context Menu for HTTP History
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy URL", command=self.copy_history_url)
        self.context_menu.add_command(label="Send to Repeater", command=self.send_to_repeater)
        self.context_menu.add_command(label="Send to Intruder", command=self.send_to_intruder)
        self.context_menu.add_command(label="Send to Race Condition", command=self.send_to_racer_from_history) # Added

        self.context_menu.add_command(label="Analyze with AI", command=self.analyze_history_with_ai)
        self.history_table.bind("<Button-3>", self.show_context_menu)

        # --- WebSockets Tab ---
        self.ws_log = scrolledtext.ScrolledText(self.websockets_tab, wrap=tk.WORD, state="disabled")
        self.ws_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _change_repeater_method(self, new_method):
        tab_id = self.get_current_repeater_tab_id()
        if tab_id and tab_id in self.repeater_tabs:
            self.change_request_method(self.repeater_tabs[tab_id]["req_text"], new_method)

    def _init_config_tab(self):
        config_notebook = ttk.Notebook(self.config_tab)
        config_notebook.pack(fill=tk.BOTH, expand=True)

        listen_settings_tab = ttk.Frame(config_notebook)
        match_replace_tab = ttk.Frame(config_notebook)

        config_notebook.add(listen_settings_tab, text="Proxy Settings")
        config_notebook.add(match_replace_tab, text="Match and Replace")

        # --- Proxy Settings Sub-Tab ---
        config_frame = ttk.LabelFrame(listen_settings_tab, text="Proxy Listen Settings")
        config_frame.pack(fill=tk.X, padx=10, pady=10)

        # Host
        ttk.Label(config_frame, text="Listen Host:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.host_var = tk.StringVar(value=self.config["host"])
        self.host_entry = ttk.Entry(config_frame, textvariable=self.host_var, width=40)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        # Port
        ttk.Label(config_frame, text="Listen Port:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.port_var = tk.StringVar(value=self.config["port"])
        self.port_entry = ttk.Entry(config_frame, textvariable=self.port_var, width=10)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Timeout
        ttk.Label(config_frame, text="Timeout (seconds):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.timeout_var = tk.StringVar(value=self.config.get("timeout", 30))
        self.timeout_entry = ttk.Entry(config_frame, textvariable=self.timeout_var, width=10)
        self.timeout_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

        # HTTP/2 Toggle
        self.http2_var = tk.BooleanVar(value=self.config.get("http2", True))
        self.http2_checkbox = ttk.Checkbutton(config_frame, text="Enable HTTP/2", variable=self.http2_var)
        self.http2_checkbox.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)

        # AI API Key
        ttk.Label(config_frame, text="AI API Key:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.gemini_key_var = tk.StringVar(value=self.config.get("gemini_api_key", ""))
        self.gemini_key_entry = ttk.Entry(config_frame, textvariable=self.gemini_key_var, width=40, show="*")
        self.gemini_key_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)

        # AI Provider
        ttk.Label(config_frame, text="AI Provider:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.ai_provider_var = tk.StringVar(value=self.config.get("ai_provider", "Gemini"))
        self.ai_provider_combo = ttk.Combobox(config_frame, textvariable=self.ai_provider_var, values=["Gemini", "Groq / OpenAI Style"], state="readonly")
        self.ai_provider_combo.grid(row=5, column=1, padx=5, pady=5, sticky=tk.EW)
        self.ai_provider_var.trace_add("write", self._on_ai_provider_change)

        # AI Model Name
        ttk.Label(config_frame, text="AI Model Name:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
        self.ai_model_var = tk.StringVar(value=self.config.get("ai_model_name", "gemini-2.0-flash"))
        self.ai_model_entry = ttk.Entry(config_frame, textvariable=self.ai_model_var, width=40)
        self.ai_model_entry.grid(row=6, column=1, padx=5, pady=5, sticky=tk.EW)

        # AI Base URL
        ttk.Label(config_frame, text="API Base URL:").grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)
        self.ai_base_url_var = tk.StringVar(value=self.config.get("ai_base_url", "https://api.groq.com/openai/v1"))
        self.ai_base_url_entry = ttk.Entry(config_frame, textvariable=self.ai_base_url_var, width=40)
        self.ai_base_url_entry.grid(row=7, column=1, padx=5, pady=5, sticky=tk.EW)
        
        config_frame.columnconfigure(1, weight=1)

        # Save Button
        save_button = ttk.Button(
            listen_settings_tab,
            text="Save & Restart Proxy",
            command=self.save_and_restart_proxy
        )
        save_button.pack(pady=10, padx=10, fill=tk.X)

        launch_browser_button = ttk.Button(
            listen_settings_tab,
            text="Launch Browser (via Proxy)",
            command=self.launch_browser_via_proxy
        )
        launch_browser_button.pack(pady=5, padx=10, fill=tk.X)

        # --- Scope Rules ---
        # Moved to Target > Scope

        self.status_label = ttk.Label(listen_settings_tab, text=f"Proxy is running on {self.config['host']}:{self.config['port']}")
        self.status_label.pack(pady=5, padx=10)

        # --- Match and Replace Sub-Tab ---
        self._init_match_replace_ui(match_replace_tab)

    def _on_ai_provider_change(self, *args):
        """Helper to set reasonable defaults when the AI provider is changed."""
        provider = self.ai_provider_var.get()
        if provider == "Gemini":
            self.ai_model_var.set("gemini-2.0-flash")
            self.ai_base_url_var.set("") # Not used by Gemini
        elif "Groq" in provider:
            self.ai_model_var.set("llama-3.3-70b-versatile")
            self.ai_base_url_var.set("https://api.groq.com/openai/v1")

    def save_and_restart_proxy(self):
        """Saves the new config and restarts the proxy server."""
        new_host = self.host_var.get().strip()
        new_port_str = self.port_var.get().strip()
        new_timeout_str = self.timeout_var.get().strip()

        # 1. Input Validation
        if not new_host:
            messagebox.showerror("Configuration Error", "Host cannot be empty.")
            return
        try:
            new_port = int(new_port_str)
            if not (1 <= new_port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Configuration Error", "Port must be an integer between 1 and 65535.")
            return
        try:
            new_timeout = int(new_timeout_str)
            if new_timeout <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Configuration Error", "Timeout must be a positive integer.")
            return

        # Update current config
        self.config["host"] = new_host
        self.config["port"] = new_port
        self.config["timeout"] = new_timeout
        self.config["http2"] = self.http2_var.get()
        self.config["gemini_api_key"] = self.gemini_key_var.get().strip()
        self.config["ai_model_name"] = self.ai_model_var.get().strip()
        self.config["ai_provider"] = self.ai_provider_var.get()
        self.config["ai_base_url"] = self.ai_base_url_var.get().strip()
        config.save_config(self.config)

        # Update AI settings
        self._setup_ai_client()

        # 2. Update UI for Restart
        self.status_label.config(text="Restarting proxy, please wait...")
        self.host_entry.config(state='disabled')
        self.port_entry.config(state='disabled')
        self.timeout_entry.config(state='disabled')
        self.http2_checkbox.config(state='disabled')
        self.notebook.tab(self.notebook.index(self.config_tab), state='disabled') # Disable config tab
        self.root.update_idletasks() # Force GUI update

        # 3. Execute Restart in a New Thread
        restart_thread = threading.Thread(
            target=self._perform_proxy_restart,
            args=(new_host, new_port),
            daemon=True
        )
        restart_thread.start()

    def _perform_proxy_restart(self, new_host, new_port):
        """Helper method to stop and start the proxy in a separate thread."""
        try:
            # Stop the old proxy
            self.proxy_manager.stop()
            
            # Create and start a new proxy manager
            self.proxy_manager = ProxyManager(
                self.gui_queue,
                self.proxy_queue,
                host=new_host,
                port=new_port,
                scope_rules=self.config["scope_rules"],
                match_replace_rules=self.config.get("match_replace_rules", []),
                http2=self.config.get("http2", True)
            )
            self.proxy_manager.start()

            # Schedule GUI update on the main thread
            self.root.after(0, self._update_ui_after_restart, True, new_host, new_port)

        except Exception as e:
            self.root.after(0, self._update_ui_after_restart, False, new_host, new_port, str(e))

    def _update_ui_after_restart(self, success, host, port, error_msg=None):
        """Updates the GUI on the main thread after proxy restart."""
        self.host_entry.config(state='normal')
        self.port_entry.config(state='normal')
        self.timeout_entry.config(state='normal')
        self.http2_checkbox.config(state='normal')
        self.notebook.tab(self.notebook.index(self.config_tab), state='normal') # Re-enable config tab

        if success:
            self.status_label.config(text=f"Proxy is running on {host}:{port}")
            messagebox.showinfo("Proxy Restart", f"Proxy successfully restarted on {host}:{port}")
        else:
            self.status_label.config(text=f"Proxy failed to restart. Error: {error_msg}")
            messagebox.showerror("Proxy Restart Error", f"Failed to restart proxy: {error_msg}")

    def _init_scope_rules_ui(self, parent_tab):
        """Initializes the UI for managing scope rules."""
        scope_frame = ttk.Labelframe(parent_tab, text="Scope Rules")
        scope_frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)

        # Input for new rules
        input_frame = ttk.Frame(scope_frame)
        input_frame.pack(fill=tk.X, pady=5)
        input_frame.columnconfigure(1, weight=1)

        ttk.Label(input_frame, text="Type:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.scope_type_var = tk.StringVar(value="Include")
        ttk.Combobox(input_frame, textvariable=self.scope_type_var, values=["Include", "Exclude"], state="readonly", width=10).grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)

        ttk.Label(input_frame, text="Domain / Subdomain:").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.scope_pattern_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.scope_pattern_var).grid(row=1, column=1, padx=5, pady=2, sticky=tk.EW)

        add_button = ttk.Button(input_frame, text="Add Rule", command=self.add_scope_rule)
        add_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.EW)

        # Display existing rules
        rules_frame = ttk.Frame(scope_frame)
        rules_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.scope_rules_treeview = ttk.Treeview(rules_frame, columns=("Type", "Pattern"), show="headings")
        self.scope_rules_treeview.heading("Type", text="Type")
        self.scope_rules_treeview.heading("Pattern", text="Pattern")
        self.scope_rules_treeview.column("Type", width=80, anchor=tk.CENTER)
        self.scope_rules_treeview.column("Pattern", anchor=tk.W)

        # Scrollbar
        scrollbar = ttk.Scrollbar(rules_frame, orient=tk.VERTICAL, command=self.scope_rules_treeview.yview)
        self.scope_rules_treeview.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.scope_rules_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        remove_button = ttk.Button(scope_frame, text="Remove Selected Rule(s)", command=self.remove_scope_rule)
        remove_button.pack(fill=tk.X, pady=5)

        # Populate with existing rules
        self._populate_scope_rules_treeview()

    def _populate_scope_rules_treeview(self):
        """Populates the scope rules Treeview with data from self.config."""
        # Update heading to reflect new input type
        self.scope_rules_treeview.heading("Pattern", text="Domain / Subdomain")
        
        for item in self.scope_rules_treeview.get_children():
            self.scope_rules_treeview.delete(item)
        
        for idx, rule in enumerate(self.config["scope_rules"]):
            display_value = rule.get("original_input", rule["pattern"])
            self.scope_rules_treeview.insert("", tk.END, iid=str(idx), values=(rule["type"], display_value))

    def add_scope_rule(self):
        """Adds a new scope rule based on user input, automatically generating the regex."""
        rule_type = self.scope_type_var.get()
        user_input = self.scope_pattern_var.get().strip()

        if not user_input:
            messagebox.showerror("Error", "Domain / Subdomain cannot be empty.")
            return
        
        # Generate regex for domain and its subdomains
        # Matches: example.com, www.example.com, api.example.com
        # Protocol and path agnostic
        try:
            escaped_input = re.escape(user_input)
            # Pattern: (:// | \.) escaped_domain (: | / | $)
            # This ensures we match the domain itself or as a subdomain, but not as a suffix of another domain (e.g., myexample.com)
            # and effectively handles the start of the host part.
            # Simplified robust version:
            pattern = f"https?://([a-zA-Z0-9.-]+\\.)?{escaped_input}(:[0-9]+)?(/.*)?$"
            re.compile(pattern) # Validate regex
        except re.error as e:
            messagebox.showerror("Error", f"Error generating regex: {e}")
            return
        
        new_rule = {"type": rule_type, "pattern": pattern, "original_input": user_input} # Store original for display if needed
        self.config["scope_rules"].append(new_rule)
        config.save_config(self.config) # Save to file
        
        # Dynamic Update
        self.proxy_manager.update_scope_rules(self.config["scope_rules"])
        
        self._populate_scope_rules_treeview() # Refresh UI
        self.scope_pattern_var.set("") # Clear input field
        # message removed for seamless UX as requested
        # messagebox.showinfo("Success", "Rule added.")

    def remove_scope_rule(self):
        """Removes selected scope rule(s)."""
        selected_items = self.scope_rules_treeview.selection()
        if not selected_items:
            messagebox.showinfo("Info", "No rule selected to remove.")
            return

        # Get original indices and sort in descending order to avoid issues when removing
        indices_to_remove = sorted([int(item) for item in selected_items], reverse=True)

        for idx in indices_to_remove:
            if 0 <= idx < len(self.config["scope_rules"]):
                del self.config["scope_rules"][idx]
        
        config.save_config(self.config) # Save to file
        
        # Dynamic Update
        self.proxy_manager.update_scope_rules(self.config["scope_rules"])
        
        self._populate_scope_rules_treeview() # Refresh UI
        # messagebox.showinfo("Success", "Rule(s) removed.")

    def _init_match_replace_ui(self, parent_tab):
        """Initializes the UI for managing match and replace rules."""
        main_frame = ttk.Frame(parent_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Input Frame
        input_frame = ttk.LabelFrame(main_frame, text="Add New Rule")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="Type:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.mr_type_var = tk.StringVar(value="Request Header")
        self.mr_type_combo = ttk.Combobox(input_frame, textvariable=self.mr_type_var, values=["All", "Request Header", "Request Body", "URL"], state="readonly")
        self.mr_type_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(input_frame, text="Action:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.mr_action_var = tk.StringVar(value="Replace")
        self.mr_action_combo = ttk.Combobox(input_frame, textvariable=self.mr_action_var, values=["Replace", "Test Only"], state="readonly")
        self.mr_action_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(input_frame, text="Match:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.mr_match_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.mr_match_var).grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(input_frame, text="Replace:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.mr_replace_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.mr_replace_var).grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)

        add_btn = ttk.Button(input_frame, text="Add Rule", command=self.add_match_replace_rule)
        add_btn.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        
        input_frame.columnconfigure(1, weight=1)

        # Table Frame
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)

        self.mr_tree = ttk.Treeview(table_frame, columns=("Enabled", "Type", "Action", "Match", "Replace"), show="headings")
        self.mr_tree.heading("Enabled", text="Enabled")
        self.mr_tree.heading("Type", text="Type")
        self.mr_tree.heading("Action", text="Action")
        self.mr_tree.heading("Match", text="Match")
        self.mr_tree.heading("Replace", text="Replace")

        self.mr_tree.column("Enabled", width=70, anchor=tk.CENTER)
        self.mr_tree.column("Type", width=120)
        self.mr_tree.column("Action", width=100)
        self.mr_tree.column("Match", width=200)
        self.mr_tree.column("Replace", width=200)

        scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.mr_tree.yview)
        self.mr_tree.configure(yscroll=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.mr_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        remove_btn = ttk.Button(main_frame, text="Remove Selected Rule(s)", command=self.remove_match_replace_rule)
        remove_btn.pack(fill=tk.X, pady=(10, 0))

        self._populate_match_replace_treeview()

    def _populate_match_replace_treeview(self):
        for item in self.mr_tree.get_children():
            self.mr_tree.delete(item)
        
        rules = self.config.get("match_replace_rules", [])
        for idx, rule in enumerate(rules):
            enabled = "Yes" if rule.get("enabled", True) else "No"
            action = rule.get("action", "Replace")
            self.mr_tree.insert("", tk.END, iid=str(idx), values=(enabled, rule["type"], action, rule["match"], rule["replace"]))

    def add_match_replace_rule(self):
        rule_type = self.mr_type_var.get()
        rule_action = self.mr_action_var.get()
        match_str = self.mr_match_var.get().strip()
        replace_str = self.mr_replace_var.get().strip()

        if not match_str:
            messagebox.showerror("Error", "Match string cannot be empty.")
            return

        new_rule = {
            "type": rule_type,
            "action": rule_action,
            "match": match_str,
            "replace": replace_str,
            "enabled": True
        }

        if "match_replace_rules" not in self.config:
            self.config["match_replace_rules"] = []
        
        self.config["match_replace_rules"].append(new_rule)
        config.save_config(self.config)
        
        # Explicitly update the proxy manager with the ENTIRE rule list
        self.proxy_manager.update_match_replace_rules(self.config["match_replace_rules"])
        self._populate_match_replace_treeview()
        
        self.mr_match_var.set("")
        self.mr_replace_var.set("")
        messagebox.showinfo("Success", f"Match & Replace rule for '{match_str}' added and active!")

    def remove_match_replace_rule(self):
        selected = self.mr_tree.selection()
        if not selected: return

        indices = sorted([int(item) for item in selected], reverse=True)
        rules = self.config.get("match_replace_rules", [])
        
        for idx in indices:
            if 0 <= idx < len(rules):
                del rules[idx]
        
        self.config["match_replace_rules"] = rules
        config.save_config(self.config)
        
        # Aggressively push the updated (potentially empty) list to the proxy
        self.proxy_manager.update_match_replace_rules(self.config["match_replace_rules"])
        self._populate_match_replace_treeview()
        messagebox.showinfo("Success", "Rule(s) removed and proxy rules updated.")

    def copy_to_clipboard(self, text):
        """Copies text to the system clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def _setup_syntax_tags(self, widget):
        """Configures tags for HTTP and HTML syntax highlighting with method-specific colors."""
        # Method-specific Tags
        widget.tag_configure("meth_GET", foreground="#0000FF", font=("Courier", 10, "bold")) # Blue
        widget.tag_configure("meth_POST", foreground="#008000", font=("Courier", 10, "bold")) # Green
        widget.tag_configure("meth_PUT", foreground="#cc7a00", font=("Courier", 10, "bold")) # Orange
        widget.tag_configure("meth_DELETE", foreground="#FF0000", font=("Courier", 10, "bold")) # Red
        
        # Default Method Tag (for others)
        widget.tag_configure("http_method", foreground="#800080", font=("Courier", 10, "bold")) # Purple
        
        # Status-specific Tags
        widget.tag_configure("status_2xx", foreground="#008000", font=("Courier", 10, "bold")) # Green
        widget.tag_configure("status_4xx", foreground="#FF0000", font=("Courier", 10, "bold")) # Red
        widget.tag_configure("status_5xx", foreground="#800080", font=("Courier", 10, "bold")) # Purple
        
        widget.tag_configure("http_path", foreground="#0000FF") # Blue
        widget.tag_configure("http_version", foreground="#808080") # Gray
        widget.tag_configure("http_header_key", foreground="#000080", font=("Courier", 10, "bold")) # Dark Blue
        widget.tag_configure("http_header_val", foreground="#008000") # Green
        
        # HTML/XML Tags
        widget.tag_configure("html_tag", foreground="#800000", font=("Courier", 10, "bold")) # Maroon
        widget.tag_configure("html_attr", foreground="#FF4500") # OrangeRed
        widget.tag_configure("html_str", foreground="#0000FF") # Blue
        widget.tag_configure("html_comm", foreground="#008000", font=("Courier", 10, "italic")) # Green (Comments)

    def _highlight_http_text(self, widget):
        """Applies syntax highlighting to the content of a text widget, including HTML/JSON/Form bodies."""
        self._setup_syntax_tags(widget)
        content = widget.get("1.0", tk.END)
        lines = content.split("\n")
        
        # 1. Highlight Request/Status Line
        if lines:
            first_line = lines[0]
            parts = first_line.split(" ")
            
            # Identify if it's a REQUEST (e.g., POST /path HTTP/1.1)
            if len(parts) >= 3 and not parts[0].startswith("HTTP/"):
                method = parts[0].upper()
                tag = f"meth_{method}"
                # If we don't have a specific tag for this method, use default purple
                if tag not in ["meth_GET", "meth_POST", "meth_PUT", "meth_DELETE"]:
                    tag = "http_method"
                
                widget.tag_add(tag, "1.0", f"1.{len(parts[0])}")
                widget.tag_add("http_path", f"1.{len(parts[0])+1}", f"1.{len(parts[0])+1+len(parts[1])}")
                widget.tag_add("http_version", f"1.{len(parts[0])+1+len(parts[1])+1}", f"1.{len(first_line)}")
            
            # Identify if it's a RESPONSE (e.g., HTTP/1.1 200 OK)
            elif len(parts) >= 2 and parts[0].startswith("HTTP/"):
                widget.tag_add("http_version", "1.0", f"1.{len(parts[0])}")
                
                status_code = parts[1]
                s_tag = "http_method" # default
                if status_code.startswith("2"): s_tag = "status_2xx"
                elif status_code.startswith("4"): s_tag = "status_4xx"
                elif status_code.startswith("5"): s_tag = "status_5xx"
                
                widget.tag_add(s_tag, f"1.{len(parts[0])+1}", f"1.{len(first_line)}")

        # 2. Highlight Headers and Find Body Start
        body_start_line = len(lines) + 1
        for i, line in enumerate(lines[1:], start=2):
            if not line.strip():
                body_start_line = i + 1
                break
            
            if ":" in line:
                key, val = line.split(":", 1)
                widget.tag_add("http_header_key", f"{i}.0", f"{i}.{len(key)}")
                widget.tag_add("http_header_val", f"{i}.{len(key)}", f"{i}.{len(line)}")

        # 3. Highlight Body
        body_content = "\n".join(lines[body_start_line-1:])
        if not body_content.strip(): return

        is_html = "<html" in body_content.lower() or "<!doctype" in body_content.lower() or "<body" in body_content.lower()

        for i, line in enumerate(lines[body_start_line-1:], start=body_start_line):
            if not line.strip(): continue
            
            if is_html:
                # HTML Highlighting
                # Comments: <!-- ... -->
                for match in re.finditer(r"<!--.*?-->", line):
                    start, end = match.span()
                    widget.tag_add("html_comm", f"{i}.{start}", f"{i}.{end}")
                
                # Tags: <tag ... >
                for match in re.finditer(r"<[^>!]+>", line):
                    start, end = match.span()
                    widget.tag_add("html_tag", f"{i}.{start}", f"{i}.{end}")
                    
                    # Attributes inside tags: key="val"
                    tag_inner = match.group()
                    for attr_match in re.finditer(r'([a-zA-Z0-9_-]+)=("[^"]*"|\'[^\']*\')', tag_inner):
                        a_start, a_end = attr_match.span(1)
                        v_start, v_end = attr_match.span(2)
                        widget.tag_add("html_attr", f"{i}.{start+a_start}", f"{i}.{start+a_end}")
                        widget.tag_add("html_str", f"{i}.{start+v_start}", f"{i}.{start+v_end}")
            else:
                # JSON/Form Highlighting
                # Simple JSON key detection: "key":
                json_matches = re.finditer(r'("[^"]+")\s*:', line)
                found_something = False
                for match in json_matches:
                    start, end = match.span(1)
                    widget.tag_add("http_header_key", f"{i}.{start}", f"{i}.{end}")
                    found_something = True
                
                # Simple Form-encoded or Query detection: key=
                if not found_something:
                    form_matches = re.finditer(r'([^&?=\s]+)=([^&?\s]*)', line)
                    for match in form_matches:
                        start_k, end_k = match.span(1)
                        start_v, end_v = match.span(2)
                        widget.tag_add("http_header_key", f"{i}.{start_k}", f"{i}.{end_k}")
                        widget.tag_add("http_header_val", f"{i}.{start_v}", f"{i}.{end_v}")

    def safe_insert_text(self, widget, text, max_size=500000):
        """Safely inserts text with truncation, pretty-printing, and syntax highlighting."""
        widget.config(state='normal')
        widget.delete("1.0", tk.END)
        
        display_text = text
        if len(text) > max_size:
            display_text = text[:max_size] + f"\n\n... [TRUNCATED: Content too large ({len(text)} bytes) for full display] ..."
        else:
            # Attempt Pretty Printing for JSON
            if text.strip().startswith(("{", "[")):
                try:
                    import json
                    parsed = json.loads(text)
                    display_text = json.dumps(parsed, indent=4)
                except: pass
            # Attempt Pretty Printing for XML
            elif text.strip().startswith("<"):
                try:
                    import xml.dom.minidom
                    dom = xml.dom.minidom.parseString(text)
                    display_text = dom.toprettyxml(indent="    ")
                except: pass

        widget.insert("1.0", display_text)
        
        # Apply highlighting
        self._highlight_http_text(widget)

    def on_repeater_key(self, widget):
        """Handles dynamic syntax highlighting as the user types in the Repeater."""
        # Clear existing HTTP and HTML tags to re-calculate them
        tags_to_clear = [
            "http_method", "http_path", "http_version", "http_header_key", "http_header_val", 
            "http_body", "html_tag", "html_attr", "html_str", "html_comm"
        ]
        for tag in tags_to_clear:
            widget.tag_remove(tag, "1.0", tk.END)
        self._highlight_http_text(widget)

    # --- Multipart Form Data Support ---
    def parse_multipart(self, body: bytes, boundary: str):
        """Parses multipart/form-data body into a list of parameter dictionaries."""
        parts = []
        full_boundary = b'--' + boundary.encode('utf-8')
        raw_parts = body.split(full_boundary)
        
        for raw_part in raw_parts:
            raw_part = raw_part.strip()
            if not raw_part or raw_part == b'--':
                continue
            
            header_end = raw_part.find(b'\r\n\r\n')
            if header_end == -1: continue
            
            headers_raw = raw_part[:header_end].decode('utf-8', errors='replace')
            content = raw_part[header_end+4:]
            
            name = None
            filename = None
            part_headers = []
            for line in headers_raw.split('\n'):
                line = line.strip()
                if not line: continue
                part_headers.append(line)
                if line.lower().startswith('content-disposition:'):
                    match_name = re.search(r'name="([^"]+)"', line)
                    if match_name: name = match_name.group(1)
                    match_file = re.search(r'filename="([^"]+)"', line)
                    if match_file: filename = match_file.group(1)
            
            parts.append({
                'name': name,
                'filename': filename,
                'headers': part_headers,
                'value': content
            })
        return parts

    def build_multipart(self, parts, boundary: str) -> bytes:
        """Reassembles a multipart/form-data body from parameter parts."""
        body = b''
        full_boundary = b'--' + boundary.encode('utf-8')
        for part in parts:
            body += full_boundary + b'\r\n'
            body += ('\r\n'.join(part['headers'])).encode('utf-8') + b'\r\n\r\n'
            val = part['value']
            body += val if isinstance(val, bytes) else val.encode('utf-8')
            body += b'\r\n'
        body += full_boundary + b'--\r\n'
        return body

    def show_multipart_editor(self):
        """UI for parsing and editing multipart/form-data in the Repeater."""
        tab_id = self.get_current_repeater_tab_id()
        if not tab_id: return
        
        raw_request = self.repeater_tabs[tab_id]["req_text"].get("1.0", tk.END)
        method, url, headers, body = self._parse_raw_request(raw_request)
        
        boundary = None
        for k, v in headers.items():
            if k.lower() == 'content-type' and 'multipart/form-data' in v.lower():
                if 'boundary=' in v:
                    boundary = v.split('boundary=')[1].split(';')[0].strip().strip('"')
        
        if not boundary:
            messagebox.showinfo("Info", "No multipart boundary found in Content-Type header.")
            return

        try:
            parts = self.parse_multipart(body, boundary)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse multipart body: {e}")
            return

        editor_win = tk.Toplevel(self.root)
        editor_win.title("Multipart Parameter Editor")
        editor_win.geometry("600x500")
        
        main_frame = ttk.Frame(editor_win, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        entries = []
        for i, part in enumerate(parts):
            p_frame = ttk.LabelFrame(scrollable_frame, text=f"Part {i+1}: {part['name'] or 'unnamed'}")
            p_frame.pack(fill=tk.X, pady=5, padx=5)
            
            if part['filename']:
                ttk.Label(p_frame, text=f"File: {part['filename']}").pack(anchor=tk.W)
                # Keep file data as-is (read-only in this simple editor)
                entries.append(None)
            else:
                text_val = part['value'].decode('utf-8', errors='replace')
                txt = scrolledtext.ScrolledText(p_frame, height=3, wrap=tk.WORD)
                txt.insert("1.0", text_val)
                txt.pack(fill=tk.X, expand=True)
                entries.append(txt)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def save_changes():
            for i, entry in enumerate(entries):
                if entry:
                    parts[i]['value'] = entry.get("1.0", tk.END).strip().encode('utf-8')
            
            new_body = self.build_multipart(parts, boundary)
            # Update headers
            headers['Content-Length'] = str(len(new_body))
            
            headers_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
            new_request_str = f"{method} {url} HTTP/1.1\n{headers_str}\n\n"
            
            self.repeater_tabs[tab_id]["req_text"].delete("1.0", tk.END)
            self.repeater_tabs[tab_id]["req_text"].insert("1.0", new_request_str)
            self.repeater_tabs[tab_id]["req_text"].insert(tk.END, new_body.decode('utf-8', errors='replace'))
            editor_win.destroy()

        ttk.Button(main_frame, text="Save & Update Request", command=save_changes).pack(fill=tk.X, pady=10)

    def copy_intercepted_url(self):
        """Copies the URL of the currently intercepted request."""
        if self.intercepted_flow:
            url = self.intercepted_flow["data"]["url"]
            self.copy_to_clipboard(url)

    def copy_history_url(self):
        """Copies the URL of the selected item in history."""
        selected_items = self.history_table.selection()
        if not selected_items:
            return
        selected_id = selected_items[0]
        if selected_id in self.flows:
            url = self.flows[selected_id]["request"]["url"]
            self.copy_to_clipboard(url)

    def search_response_body(self, tab_id=None):
        """Searches for a keyword in the repeater response body and highlights it."""
        if not tab_id:
            tab_id = self.get_current_repeater_tab_id()
        if not tab_id:
            return

        widgets = self.repeater_tabs[tab_id]
        keyword = widgets["search_keyword_var"].get()
        resp_text_widget = widgets["resp_text"]
        status_label = widgets["search_status_label"]
        prev_button = widgets["prev_search_button"]
        next_button = widgets["next_search_button"]

        # Reset previous search
        widgets["search_matches"] = []
        widgets["current_search_index"] = -1
        resp_text_widget.config(state='normal')
        resp_text_widget.tag_remove('search', '1.0', tk.END)

        if not keyword:
            self.clear_response_search(tab_id)
            resp_text_widget.config(state='disabled')
            return

        count = 0
        start_index = '1.0'
        
        # Configure the tag for highlighting
        resp_text_widget.tag_configure('search', background='yellow', foreground='black')

        while True:
            start_index = resp_text_widget.search(keyword, start_index, stopindex=tk.END, nocase=True)
            if not start_index:
                break
            
            end_index = resp_text_widget.index(f"{start_index}+{len(keyword)}c")
            resp_text_widget.tag_add('search', start_index, end_index)
            widgets["search_matches"].append(start_index)
            count += 1
            start_index = end_index
        
        resp_text_widget.config(state='disabled')
        
        if count > 0:
            widgets["current_search_index"] = 0
            # Highlight the first match as active
            first_match_start = widgets["search_matches"][0]
            first_match_end = resp_text_widget.index(f"{first_match_start}+{len(keyword)}c")
            resp_text_widget.tag_add('active_search', first_match_start, first_match_end)
            resp_text_widget.see(first_match_start)
            
            prev_button.config(state='normal')
            next_button.config(state='normal')
            status_label.config(text=f"1 of {count} matches found")
        else:
            prev_button.config(state='disabled')
            next_button.config(state='disabled')
            status_label.config(text="0 of 0 matches found")
            messagebox.showinfo("Search", f"No matches found for '{keyword}'")

    def clear_response_search(self, tab_id=None):
        """Clears the search keyword and removes all highlighting."""
        if not tab_id:
            tab_id = self.get_current_repeater_tab_id()
        if not tab_id:
            return

        widgets = self.repeater_tabs[tab_id]
        widgets["search_keyword_var"].set("")
        resp_text_widget = widgets["resp_text"]
        
        resp_text_widget.config(state='normal')
        resp_text_widget.tag_remove('search', '1.0', tk.END)
        resp_text_widget.tag_remove('active_search', '1.0', tk.END)
        resp_text_widget.config(state='disabled')
        
        widgets["search_status_label"].config(text="")
        widgets["prev_search_button"].config(state='disabled')
        widgets["next_search_button"].config(state='disabled')
        widgets["search_matches"] = []
        widgets["current_search_index"] = -1

    def search_intercepted_request(self, event=None):
        """Searches for a keyword in the intercepted request body and highlights it."""
        keyword = self.intercept_search_keyword_var.get()
        intercept_text_widget = self.intercepted_request_text
        status_label = self.intercept_search_status_label
        prev_button = self.intercept_prev_button
        next_button = self.intercept_next_button

        # Reset previous search
        self.intercept_search_matches = []
        self.current_intercept_match_index = -1
        intercept_text_widget.tag_remove('search_highlight', '1.0', tk.END)
        intercept_text_widget.tag_remove('active_search_highlight', '1.0', tk.END)

        if not keyword:
            self.clear_intercept_search()
            return

        count = 0
        start_index = '1.0'
        
        while True:
            start_index = intercept_text_widget.search(keyword, start_index, stopindex=tk.END, nocase=True)
            if not start_index:
                break
            
            end_index = intercept_text_widget.index(f"{start_index}+{len(keyword)}c")
            intercept_text_widget.tag_add('search_highlight', start_index, end_index)
            self.intercept_search_matches.append(start_index)
            count += 1
            start_index = end_index
        
        if count > 0:
            self.current_intercept_match_index = 0
            # Highlight the first match as active
            first_match_start = self.intercept_search_matches[0]
            first_match_end = intercept_text_widget.index(f"{first_match_start}+{len(keyword)}c")
            intercept_text_widget.tag_add('active_search_highlight', first_match_start, first_match_end)
            intercept_text_widget.see(first_match_start)
            
            prev_button.config(state='normal')
            next_button.config(state='normal')
            status_label.config(text=f"1 of {count} matches found")
        else:
            prev_button.config(state='disabled')
            next_button.config(state='disabled')
            status_label.config(text="0 of 0 matches found")
            messagebox.showinfo("Search", f"No matches found for '{keyword}'")

    def go_to_next_match(self, tab_id):
        """Scrolls to the next search match and highlights it as active."""
        if not tab_id or not self.repeater_tabs[tab_id]["search_matches"]:
            return
        
        widgets = self.repeater_tabs[tab_id]
        matches = widgets["search_matches"]
        keyword = widgets["search_keyword_var"].get()
        resp_text_widget = widgets["resp_text"]

        # Remove active tag from the old match
        old_index = widgets["current_search_index"]
        if old_index != -1:
            old_match_start = matches[old_index]
            old_match_end = resp_text_widget.index(f"{old_match_start}+{len(keyword)}c")
            resp_text_widget.tag_remove('active_search', old_match_start, old_match_end)

        # Calculate new index
        new_index = (old_index + 1) % len(matches)
        widgets["current_search_index"] = new_index
        
        # Add active tag to the new match and scroll to it
        new_match_start = matches[new_index]
        new_match_end = resp_text_widget.index(f"{new_match_start}+{len(keyword)}c")
        resp_text_widget.tag_add('active_search', new_match_start, new_match_end)
        resp_text_widget.see(new_match_start)
        
        widgets["search_status_label"].config(text=f"{new_index + 1} of {len(matches)} matches found")

    def next_intercept_match(self):
        """Scrolls to the next search match in the interceptor and highlights it as active."""
        if not self.intercept_search_matches:
            return
        
        intercept_text_widget = self.intercepted_request_text
        keyword = self.intercept_search_keyword_var.get()

        # Remove active tag from the old match
        old_index = self.current_intercept_match_index
        if old_index != -1:
            old_match_start = self.intercept_search_matches[old_index]
            old_match_end = intercept_text_widget.index(f"{old_match_start}+{len(keyword)}c")
            intercept_text_widget.tag_remove('active_search_highlight', old_match_start, old_match_end)

        # Calculate new index
        new_index = (old_index + 1) % len(self.intercept_search_matches)
        self.current_intercept_match_index = new_index
        
        # Add active tag to the new match and scroll to it
        new_match_start = self.intercept_search_matches[new_index]
        new_match_end = intercept_text_widget.index(f"{new_match_start}+{len(keyword)}c")
        intercept_text_widget.tag_add('active_search_highlight', new_match_start, new_match_end)
        intercept_text_widget.see(new_match_start)
        
        self.intercept_search_status_label.config(text=f"{new_index + 1} of {len(self.intercept_search_matches)} matches found")

    def go_to_previous_match(self, tab_id):
        """Scrolls to the previous search match and highlights it as active."""
        if not tab_id or not self.repeater_tabs[tab_id]["search_matches"]:
            return

        widgets = self.repeater_tabs[tab_id]
        matches = widgets["search_matches"]
        keyword = widgets["search_keyword_var"].get()
        resp_text_widget = widgets["resp_text"]

        # Remove active tag from the old match
        old_index = widgets["current_search_index"]
        if old_index != -1:
            old_match_start = matches[old_index]
            old_match_end = resp_text_widget.index(f"{old_match_start}+{len(keyword)}c")
            resp_text_widget.tag_remove('active_search', old_match_start, old_match_end)

        # Calculate new index
        new_index = (old_index - 1 + len(matches)) % len(matches)
        widgets["current_search_index"] = new_index

        # Add active tag to the new match and scroll to it
        new_match_start = matches[new_index]
        new_match_end = resp_text_widget.index(f"{new_match_start}+{len(keyword)}c")
        resp_text_widget.tag_add('active_search', new_match_start, new_match_end)
        resp_text_widget.see(new_match_start)
        
        widgets["search_status_label"].config(text=f"{new_index + 1} of {len(matches)} matches found")
    
    def prev_intercept_match(self):
        """Scrolls to the previous search match in the interceptor and highlights it as active."""
        if not self.intercept_search_matches:
            return

        intercept_text_widget = self.intercepted_request_text
        keyword = self.intercept_search_keyword_var.get()

        # Remove active tag from the old match
        old_index = self.current_intercept_match_index
        if old_index != -1:
            old_match_start = self.intercept_search_matches[old_index]
            old_match_end = intercept_text_widget.index(f"{old_match_start}+{len(keyword)}c")
            intercept_text_widget.tag_remove('active_search_highlight', old_match_start, old_match_end)

        # Calculate new index
        new_index = (old_index - 1 + len(self.intercept_search_matches)) % len(self.intercept_search_matches)
        self.current_intercept_match_index = new_index

        # Add active tag to the new match and scroll to it
        new_match_start = self.intercept_search_matches[new_index]
        new_match_end = intercept_text_widget.index(f"{new_match_start}+{len(keyword)}c")
        intercept_text_widget.tag_add('active_search_highlight', new_match_start, new_match_end)
        intercept_text_widget.see(new_match_start)
        
        self.intercept_search_status_label.config(text=f"{new_index + 1} of {len(self.intercept_search_matches)} matches found")

    def clear_intercept_search(self):
        """Clears the search keyword, removes all highlighting, and resets search status in the interceptor."""
        self.intercept_search_keyword_var.set("")
        intercept_text_widget = self.intercepted_request_text
        
        intercept_text_widget.tag_remove('search_highlight', '1.0', tk.END)
        intercept_text_widget.tag_remove('active_search_highlight', '1.0', tk.END)
        
        self.intercept_search_status_label.config(text="")
        self.intercept_prev_button.config(state='disabled')
        self.intercept_next_button.config(state='disabled')
        self.intercept_search_matches = []
        self.current_intercept_match_index = -1

    # --- Repeater Request Search Methods ---
    def search_repeater_request_body(self, tab_id, event=None):
        """Searches for a keyword in the repeater request body and highlights it."""
        if not tab_id or tab_id not in self.repeater_tabs:
            return

        widgets = self.repeater_tabs[tab_id]
        keyword = widgets["req_search_keyword_var"].get()
        req_text_widget = widgets["req_text"]
        status_label = widgets["req_search_status_label"]
        prev_button = widgets["req_prev_search_button"]
        next_button = widgets["req_next_search_button"]

        # Reset previous search
        widgets["req_search_matches"] = []
        widgets["current_req_search_index"] = -1
        req_text_widget.tag_remove('search_highlight', '1.0', tk.END)
        req_text_widget.tag_remove('active_search_highlight', '1.0', tk.END)

        if not keyword:
            self.clear_repeater_request_search(tab_id)
            return

        count = 0
        start_index = '1.0'
        
        while True:
            start_index = req_text_widget.search(keyword, start_index, stopindex=tk.END, nocase=True)
            if not start_index:
                break
            
            end_index = req_text_widget.index(f"{start_index}+{len(keyword)}c")
            req_text_widget.tag_add('search_highlight', start_index, end_index)
            widgets["req_search_matches"].append(start_index)
            count += 1
            start_index = end_index
        
        if count > 0:
            widgets["current_req_search_index"] = 0
            # Highlight the first match as active
            first_match_start = widgets["req_search_matches"][0]
            first_match_end = req_text_widget.index(f"{first_match_start}+{len(keyword)}c")
            req_text_widget.tag_add('active_search_highlight', first_match_start, first_match_end)
            req_text_widget.see(first_match_start)
            
            prev_button.config(state='normal')
            next_button.config(state='normal')
            status_label.config(text=f"1 of {count} matches found")
        else:
            prev_button.config(state='disabled')
            next_button.config(state='disabled')
            status_label.config(text="0 of 0 matches found")
            messagebox.showinfo("Search", f"No matches found for '{keyword}' in Request")

    def next_repeater_request_match(self, tab_id):
        """Scrolls to the next search match in the repeater request and highlights it as active."""
        if not tab_id or not self.repeater_tabs[tab_id]["req_search_matches"]:
            return
        
        widgets = self.repeater_tabs[tab_id]
        matches = widgets["req_search_matches"]
        keyword = widgets["req_search_keyword_var"].get()
        req_text_widget = widgets["req_text"]

        # Remove active tag from the old match
        old_index = widgets["current_req_search_index"]
        if old_index != -1:
            old_match_start = matches[old_index]
            old_match_end = req_text_widget.index(f"{old_match_start}+{len(keyword)}c")
            req_text_widget.tag_remove('active_search_highlight', old_match_start, old_match_end)

        # Calculate new index
        new_index = (old_index + 1) % len(matches)
        widgets["current_req_search_index"] = new_index
        
        # Add active tag to the new match and scroll to it
        new_match_start = matches[new_index]
        new_match_end = req_text_widget.index(f"{new_match_start}+{len(keyword)}c")
        req_text_widget.tag_add('active_search_highlight', new_match_start, new_match_end)
        req_text_widget.see(new_match_start)
        
        widgets["req_search_status_label"].config(text=f"{new_index + 1} of {len(matches)} matches found")

    def prev_repeater_request_match(self, tab_id):
        """Scrolls to the previous search match in the repeater request and highlights it as active."""
        if not tab_id or not self.repeater_tabs[tab_id]["req_search_matches"]:
            return

        widgets = self.repeater_tabs[tab_id]
        matches = widgets["req_search_matches"]
        keyword = widgets["req_search_keyword_var"].get()
        req_text_widget = widgets["req_text"]

        # Remove active tag from the old match
        old_index = widgets["current_req_search_index"]
        if old_index != -1:
            old_match_start = matches[old_index]
            old_match_end = req_text_widget.index(f"{old_match_start}+{len(keyword)}c")
            req_text_widget.tag_remove('active_search_highlight', old_match_start, old_match_end)

        # Calculate new index
        new_index = (old_index - 1 + len(matches)) % len(matches)
        widgets["current_req_search_index"] = new_index

        # Add active tag to the new match and scroll to it
        new_match_start = matches[new_index]
        new_match_end = req_text_widget.index(f"{new_match_start}+{len(keyword)}c")
        req_text_widget.tag_add('active_search_highlight', new_match_start, new_match_end)
        req_text_widget.see(new_match_start)
        
        widgets["req_search_status_label"].config(text=f"{new_index + 1} of {len(matches)} matches found")

    def clear_repeater_request_search(self, tab_id=None):
        """Clears the search keyword, removes all highlighting, and resets search status in the repeater request."""
        if not tab_id or tab_id not in self.repeater_tabs:
            return

        widgets = self.repeater_tabs[tab_id]
        widgets["req_search_keyword_var"].set("")
        req_text_widget = widgets["req_text"]
        
        req_text_widget.tag_remove('search_highlight', '1.0', tk.END)
        req_text_widget.tag_remove('active_search_highlight', '1.0', tk.END)
        
        widgets["req_search_status_label"].config(text="")
        widgets["req_prev_search_button"].config(state='disabled')
        widgets["req_next_search_button"].config(state='disabled')
        widgets["req_search_matches"] = []
        widgets["current_req_search_index"] = -1

    def show_context_menu(self, event):
        """Display the context menu on right-click."""
        selection = self.history_table.identify_row(event.y)
        if selection:
            self.history_table.selection_set(selection)
            self.context_menu.post(event.x_root, event.y_root)

    def show_interceptor_context_menu(self, event):
        """Display the interceptor's context menu on right-click."""
        # Only show if there is an active intercepted flow
        if self.intercepted_flow:
            self.interceptor_context_menu.post(event.x_root, event.y_root)

    def show_repeater_context_menu(self, event):
        """Display the repeater's context menu on right-click."""
        self.repeater_context_menu.post(event.x_root, event.y_root)

    def copy_repeater_url(self):
        """Copies the URL of the current request in the active Repeater tab."""
        tab_id = self.get_current_repeater_tab_id()
        if not tab_id:
            return
        
        raw_request = self.repeater_tabs[tab_id]["req_text"].get("1.0", tk.END)
        try:
            _, url, _, _ = self._parse_raw_request(raw_request)
            if url:
                self.copy_to_clipboard(url)
        except Exception:
            pass

    def send_intercepted_to_repeater(self):
        """Sends the currently intercepted request to the Repeater tab."""
        if not self.intercepted_flow:
            return
        
        full_request_str = self.intercepted_request_text.get("1.0", tk.END)
        if not full_request_str.strip():
            return

        # Create a new tab with the request data
        self._create_new_repeater_tab(full_request_str)
        
        # Switch to the repeater tab
        self.notebook.select(self.repeater_tab)

    def send_intercepted_to_intruder(self):
        """Sends the currently intercepted request to the Intruder tab."""
        if not self.intercepted_flow:
            return
        full_request_str = self.intercepted_request_text.get("1.0", tk.END).strip()
        if not full_request_str:
            return
        self.intruder_req_text.delete("1.0", tk.END)
        self.intruder_req_text.insert("1.0", full_request_str)
        self._on_intruder_key() # Highlighting
        self.notebook.select(self.intruder_tab)

    def send_intercepted_to_racer(self):
        """Sends the currently intercepted request to the Racer tab."""
        if not self.intercepted_flow:
            return
        
        full_request_str = self.intercepted_request_text.get("1.0", tk.END).strip()
        if not full_request_str:
            return

        self.racer_raw_req_text.delete("1.0", tk.END)
        self.racer_raw_req_text.insert("1.0", full_request_str)
        self.notebook.select(self.racer_tab)

    def send_repeater_to_intruder(self):
        """Sends the current active repeater request to the Intruder tab."""
        tab_id = self.get_current_repeater_tab_id()
        if not tab_id or tab_id not in self.repeater_tabs:
            return
        full_request_str = self.repeater_tabs[tab_id]["req_text"].get("1.0", tk.END).strip()
        if not full_request_str:
            return
        self.intruder_req_text.delete("1.0", tk.END)
        self.intruder_req_text.insert("1.0", full_request_str)
        self._on_intruder_key() # Highlighting
        self.notebook.select(self.intruder_tab)

    def send_repeater_to_racer(self):
        """Sends the current active repeater request to the Racer tab."""
        tab_id = self.get_current_repeater_tab_id()
        if not tab_id or tab_id not in self.repeater_tabs:
            return
        
        full_request_str = self.repeater_tabs[tab_id]["req_text"].get("1.0", tk.END).strip()
        if not full_request_str:
            return

        self.racer_raw_req_text.delete("1.0", tk.END)
        self.racer_raw_req_text.insert("1.0", full_request_str)
        self.notebook.select(self.racer_tab)

    def send_to_repeater(self):
        """Sends the selected flow's request to the Repeater tab."""
        selected_items = self.history_table.selection()
        if not selected_items:
            return
        selected_id = selected_items[0]

        if not selected_id or selected_id not in self.flows:
            return

        request_data = self.flows[selected_id].get("request")
        if not request_data:
            return

        # Format the request for the repeater text widget
        method = request_data['method']
        url = request_data['url']
        headers = request_data['headers']
        content = request_data['content']

        headers_str = "\n".join([f"{k}: {v}" for k, v in headers])
        
        try:
            body_str = content.decode('utf-8')
        except:
            body_str = str(content)

        full_request_str = f"{method} {url} HTTP/1.1\n{headers_str}\n\n{body_str}"

        # Create a new tab with the request data
        self._create_new_repeater_tab(full_request_str)
        
        # Switch to the repeater tab
        self.notebook.select(self.repeater_tab)

    def send_to_intruder(self):
        """Sends the selected flow's request to the Intruder tab."""
        selected_items = self.history_table.selection()
        if not selected_items:
            return
        selected_id = selected_items[0]

        if not selected_id or selected_id not in self.flows:
            return

        request_data = self.flows[selected_id].get("request")
        if not request_data:
            return

        full_request_str = self._get_full_request_str(request_data)
        self.intruder_req_text.delete("1.0", tk.END)
        self.intruder_req_text.insert("1.0", full_request_str)
        self._on_intruder_key() # Highlighting
        self.notebook.select(self.intruder_tab)

    def _init_repeater_tab(self):
        """Initializes the UI for the Repeater tab."""
        repeater_controls = ttk.Frame(self.repeater_tab)
        repeater_controls.pack(fill=tk.X, padx=5, pady=2)
        
        new_tab_button = ttk.Button(repeater_controls, text="+ New Tab", command=self._create_new_repeater_tab)
        new_tab_button.pack(side=tk.LEFT)

        self.repeater_notebook = ttk.Notebook(self.repeater_tab)
        self.repeater_notebook.pack(fill=tk.BOTH, expand=True)
        # Create an initial empty tab
        self._create_new_repeater_tab()

    def get_current_repeater_tab_id(self):
        """Returns the ID of the currently selected repeater tab."""
        try:
            selected_frame = self.repeater_notebook.select()
            if not selected_frame:
                return None
            for tab_id, widgets in self.repeater_tabs.items():
                if str(widgets["frame"]) == selected_frame:
                    return tab_id
        except Exception:
            pass
        return None

    def _create_new_repeater_tab(self, request_str=""):
        """Creates a new tab for a manual request in the Repeater."""
        self.repeater_tab_counter += 1
        tab_id = f"repeater_{self.repeater_tab_counter}"
        tab_title = f"Repeater {self.repeater_tab_counter}"

        tab_frame = ttk.Frame(self.repeater_notebook)
        self.repeater_notebook.add(tab_frame, text=tab_title)

        # Paned window for Request and Response
        main_pane = ttk.PanedWindow(tab_frame, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Request Section ---
        req_container = ttk.Frame(main_pane)
        main_pane.add(req_container, weight=1)

        req_controls = ttk.Frame(req_container)
        req_controls.pack(fill=tk.X, padx=5, pady=5)

        send_button = ttk.Button(req_controls, text="Send", command=self.send_repeater_request)
        send_button.pack(side=tk.LEFT)

        multipart_button = ttk.Button(req_controls, text="Multipart", command=self.show_multipart_editor)
        multipart_button.pack(side=tk.LEFT, padx=(5, 0))

        tab_time_label = ttk.Label(req_controls, text="Time: 0 ms", font=("Helvetica", 9, "italic"))
        tab_time_label.pack(side=tk.LEFT, padx=10)

        close_button = ttk.Button(req_controls, text="Close", command=lambda: self.close_repeater_tab(tab_id))
        close_button.pack(side=tk.LEFT, padx=(5, 0))

        back_button = ttk.Button(req_controls, text="Back", command=lambda: self.go_back_in_repeater(tab_id))
        # Hidden by default
        
        follow_redirect_button = ttk.Button(req_controls, text="Follow Redirect", command=lambda: self.follow_redirect(tab_id))
        # Hidden by default

        # Request Search Controls
        req_search_frame = ttk.Frame(req_container)
        req_search_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(req_search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        req_search_keyword_var = tk.StringVar()
        req_search_entry = ttk.Entry(req_search_frame, textvariable=req_search_keyword_var, width=40)
        req_search_entry.pack(side=tk.LEFT, padx=(0, 5), expand=True, fill=tk.X)
        req_search_entry.bind("<Return>", lambda e: self.search_repeater_request_body(tab_id))

        req_prev_search_button = ttk.Button(req_search_frame, text="<", command=lambda: self.prev_repeater_request_match(tab_id), width=3, state="disabled")
        req_prev_search_button.pack(side=tk.LEFT, padx=(0, 2))
        req_next_search_button = ttk.Button(req_search_frame, text=">", command=lambda: self.next_repeater_request_match(tab_id), width=3, state="disabled")
        req_next_search_button.pack(side=tk.LEFT, padx=(0, 2))
        req_search_status_label = ttk.Label(req_search_frame, text="")
        req_search_status_label.pack(side=tk.LEFT, padx=(5, 0))

        req_text = scrolledtext.ScrolledText(req_container, wrap=tk.WORD, height=10)
        req_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        req_text.bind("<Button-3>", self.show_repeater_context_menu)
        req_text.bind("<KeyRelease>", lambda e: self.on_repeater_key(req_text))
        if request_str:
            self.safe_insert_text(req_text, request_str)
        
        # Tags for search highlighting
        req_text.tag_configure('search_highlight', background='yellow', foreground='black')
        req_text.tag_configure('active_search_highlight', background='orange', foreground='black')

        # --- Response Section ---
        resp_container = ttk.Frame(main_pane)
        main_pane.add(resp_container, weight=1)

        resp_notebook = ttk.Notebook(resp_container)
        resp_notebook.pack(fill=tk.BOTH, expand=True)

        # Response Controls
        resp_controls = ttk.Frame(resp_container)
        resp_controls.pack(fill=tk.X, padx=5, pady=2)
        
        open_browser_button = ttk.Button(resp_controls, text="Open in Browser", command=lambda: self.open_response_in_browser(tab_id))
        open_browser_button.pack(side=tk.RIGHT)

        # Raw Response Tab
        raw_tab = ttk.Frame(resp_notebook)
        resp_notebook.add(raw_tab, text="Raw")

        # Response Search Controls
        resp_search_frame = ttk.Frame(raw_tab)
        resp_search_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(resp_search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        search_keyword_var = tk.StringVar()
        resp_search_entry = ttk.Entry(resp_search_frame, textvariable=search_keyword_var, width=40)
        resp_search_entry.pack(side=tk.LEFT, padx=(0, 5), expand=True, fill=tk.X)
        resp_search_entry.bind("<Return>", lambda e: self.search_response_body(tab_id))

        prev_search_button = ttk.Button(resp_search_frame, text="<", command=lambda: self.go_to_previous_match(tab_id), width=3, state="disabled")
        prev_search_button.pack(side=tk.LEFT, padx=(0, 2))
        next_search_button = ttk.Button(resp_search_frame, text=">", command=lambda: self.go_to_next_match(tab_id), width=3, state="disabled")
        next_search_button.pack(side=tk.LEFT, padx=(0, 2))
        search_status_label = ttk.Label(resp_search_frame, text="")
        search_status_label.pack(side=tk.LEFT, padx=(5, 0))

        resp_text = scrolledtext.ScrolledText(raw_tab, wrap=tk.WORD, height=10, state='disabled')
        resp_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tags for search highlighting
        resp_text.tag_configure('search', background='yellow', foreground='black')
        resp_text.tag_configure('active_search', background='orange', foreground='black')

        # Render Tab
        render_tab = ttk.Frame(resp_notebook)
        resp_notebook.add(render_tab, text="Render")
        render_frame = HTMLScrolledText(render_tab)
        render_frame.pack(fill=tk.BOTH, expand=True)

        # Store widgets for this tab
        self.repeater_tabs[tab_id] = {
            "frame": tab_frame,
            "req_text": req_text,
            "resp_text": resp_text,
            "render_frame": render_frame,
            "send_button": send_button,
            "time_label": tab_time_label, # Store the local tab label
            "close_button": close_button,
            "open_browser_button": open_browser_button,
            "back_button": back_button,
            "follow_redirect_button": follow_redirect_button,
            "req_search_keyword_var": req_search_keyword_var,
            "req_prev_search_button": req_prev_search_button,
            "req_next_search_button": req_next_search_button,
            "req_search_status_label": req_search_status_label,
            "req_search_matches": [],
            "current_req_search_index": -1,
            "search_keyword_var": search_keyword_var,
            "prev_search_button": prev_search_button,
            "next_search_button": next_search_button,
            "search_status_label": search_status_label,
            "search_matches": [],
            "current_search_index": -1,
            "decoded_body": "",
            "redirect_location": None,
            "previous_request": None
        }

        self.repeater_notebook.select(tab_frame)

    def _init_target_tab(self):
        """Initializes the UI for the Target tab with a hierarchical Site Map."""
        target_notebook = ttk.Notebook(self.target_tab)
        target_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        site_map_tab = ttk.Frame(target_notebook)
        scope_tab = ttk.Frame(target_notebook)

        target_notebook.add(site_map_tab, text="Site Map")
        target_notebook.add(scope_tab, text="Scope")

        # --- Site Map Tab ---
        # Main Paned Window for Tree and Details
        site_map_pane = ttk.PanedWindow(site_map_tab, orient=tk.HORIZONTAL)
        site_map_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left: Treeview
        tree_container = ttk.Frame(site_map_pane)
        site_map_pane.add(tree_container, weight=1)

        tree_controls = ttk.Frame(tree_container)
        tree_controls.pack(fill=tk.X, padx=2, pady=2)
        
        # Site Map Search Bar
        search_frame = ttk.Frame(tree_container)
        search_frame.pack(fill=tk.X, padx=2, pady=2)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.site_map_search_var = tk.StringVar()
        self.site_map_search_entry = ttk.Entry(search_frame, textvariable=self.site_map_search_var)
        self.site_map_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        self.site_map_search_entry.bind("<Return>", lambda e: self.apply_site_map_filter())
        ttk.Button(search_frame, text="Filter", command=self.apply_site_map_filter).pack(side=tk.LEFT)

        refresh_button = ttk.Button(tree_controls, text="Refresh Site Map", command=self.refresh_site_map)
        refresh_button.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ai_recon_button = ttk.Button(tree_controls, text="AI Recon", command=self.perform_site_map_recon)
        ai_recon_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0))

        tree_frame = ttk.Frame(tree_container)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.site_map_tree = ttk.Treeview(tree_frame, columns=("Type",), show="tree")
        self.site_map_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure Interesting Tag for Sitemap
        self.site_map_tree.tag_configure("interesting", foreground="red", font=("Helvetica", 10, "bold"))

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.site_map_tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.site_map_tree.configure(yscroll=tree_scroll.set)
        
        self.site_map_tree.bind("<<TreeviewSelect>>", self.on_site_map_select)

        # Context Menu for Site Map
        self.site_map_context_menu = tk.Menu(self.root, tearoff=0)
        self.site_map_context_menu.add_command(label="Copy URL", command=self.copy_site_map_url)
        self.site_map_context_menu.add_command(label="Send to Repeater", command=self.send_site_map_to_repeater)
        self.site_map_context_menu.add_command(label="Send to Race Condition", command=self.send_to_racer_from_sitemap) # Added

        self.site_map_context_menu.add_command(label="Analyze with AI", command=self.analyze_site_map_with_ai)
        self.site_map_tree.bind("<Button-3>", self.show_site_map_context_menu)

        # Right: Details (Request/Response)
        details_frame = ttk.Frame(site_map_pane)
        site_map_pane.add(details_frame, weight=2)

        details_notebook = ttk.Notebook(details_frame)
        details_notebook.pack(fill=tk.BOTH, expand=True)

        self.site_map_req_text = scrolledtext.ScrolledText(details_notebook, wrap=tk.WORD, height=10)
        self.site_map_resp_text = scrolledtext.ScrolledText(details_notebook, wrap=tk.WORD, height=10)

        details_notebook.add(self.site_map_req_text, text="Request")
        details_notebook.add(self.site_map_resp_text, text="Response")

        # Internal data for Site Map: { host: { path_segments: flow_id } }
        self.site_map_data = {}
        self.site_map_nodes = {} # { path_string: node_id }

        # --- Scope Tab ---
        self._init_scope_rules_ui(scope_tab)

    def show_site_map_context_menu(self, event):
        """Display the site map context menu on right-click."""
        item = self.site_map_tree.identify_row(event.y)
        if item:
            self.site_map_tree.selection_set(item)
            self.site_map_context_menu.post(event.x_root, event.y_root)

    def apply_site_map_filter(self):
        """Filters the Site Map tree based on the search keyword."""
        keyword = self.site_map_search_var.get().lower().strip()
        
        # Clear and rebuild tree based on filter
        for item in self.site_map_tree.get_children():
            self.site_map_tree.delete(item)
        
        self.site_map_nodes = {}
        # node_to_flow already exists, we'll rebuild it as well
        self.node_to_flow = {}
        
        for summary in self.all_flows_summary:
            url = summary["url"]
            if keyword in url.lower():
                # Apply scope if needed
                if not self.filter_history_by_scope_var.get() or self.proxy_manager.is_url_in_scope(url):
                    # Flag interesting files
                    sensitive_patterns = [r"\.env", r"\.git", r"\.sql", r"config", r"backup", r"admin", r"password", r"secret"]
                    is_int = any(re.search(pat, url, re.I) for pat in sensitive_patterns)
                    self.add_to_site_map(summary["flow_id"], {"url": url}, is_interesting=is_int)

    def refresh_site_map(self):
        """Clears and rebuilds the hierarchical site map based on current scope and existing flow data."""
        # Clear the tree
        for item in self.site_map_tree.get_children():
            self.site_map_tree.delete(item)
        
        # Reset internal mapping
        self.site_map_nodes = {}
        self.node_to_flow = {}
        
        # Re-populate from all_flows_summary, applying CURRENT scope
        for summary in self.all_flows_summary:
            if self.proxy_manager.is_url_in_scope(summary["url"]):
                # We need to reconstruct the small data dict expected by add_to_site_map
                data = {"url": summary["url"]}
                self.add_to_site_map(summary["flow_id"], data)

    def _extract_param_names(self, req):
        """Helper to extract unique parameter names from URL and Body."""
        params = set()
        try:
            # 1. URL Query Parameters
            parsed = urllib.parse.urlparse(req.get('url', ''))
            qs = urllib.parse.parse_qs(parsed.query)
            params.update(qs.keys())
            
            # 2. Body Parameters
            content = req.get('content', b'')
            if content:
                # Try JSON
                try:
                    body_str = content.decode('utf-8', errors='ignore')
                    js = json.loads(body_str)
                    if isinstance(js, dict):
                        params.update(js.keys())
                    elif isinstance(js, list) and len(js) > 0 and isinstance(js[0], dict):
                        params.update(js[0].keys())
                except:
                    # Try Form-urlencoded
                    try:
                        fs = urllib.parse.parse_qs(content.decode('utf-8', errors='ignore'))
                        params.update(fs.keys())
                    except:
                        pass
        except:
            pass
        return sorted(list(params))

    def perform_site_map_recon(self):
        """Sends the enriched structure of the Site Map to AI for Business Logic & Access Control analysis."""
        if not self.ai_enabled:
            messagebox.showwarning("AI Disabled", "Please provide an AI API Key in the Configuration tab.")
            return

        if not self.flows:
            messagebox.showinfo("Info", "No traffic captured yet. Discover some URLs first.")
            return

        # Build enriched attack surface data
        recon_list = []
        seen_endpoints = set() # (method, base_url)
        
        for flow_id in self.flows:
            flow = self.flows[flow_id]
            req = flow.get("request", {})
            method = req.get("method", "GET")
            full_url = req.get("url", "")
            base_url = full_url.split("?")[0] # Strip query for clean grouping
            
            endpoint_key = (method, base_url)
            if endpoint_key not in seen_endpoints:
                params = self._extract_param_names(req)
                param_text = f" [Params: {', '.join(params)}]" if params else ""
                recon_list.append(f"{method} {base_url}{param_text}")
                seen_endpoints.add(endpoint_key)

        # Sort and limit to keep prompt size reasonable
        recon_list.sort()
        paths_str = "\n".join(recon_list[:150])

        prompt = (
            "ROLE: Senior Bug Bounty Hunter & Logic Specialist.\n"
            "TASK: Perform deep structural reconnaissance on the enriched attack surface.\n\n"
            "--- DISCOVERED ENDPOINTS (Method + URL + Parameters) ---\n"
            f"{paths_str}\n\n"
            "--- ANALYSIS REQUIREMENTS ---\n"
            "1. **Access Control (IDOR/Bypass)**: Focus on endpoints with IDs or sensitive params. Which ones are likely to fail if swapped?\n"
            "2. **Race Conditions (Concurrency)**: Identify endpoints that handle 'Limits' or 'Balances'. (e.g. AddToBasket, ApplyPromo, Transfer, Vote, Claim). Which ones could be broken by sending 20 requests at once?\n"
            "3. **Business Logic Flaws**: Analyze 'Action' endpoints (POST/PUT/DELETE). What logical bypasses are possible? (e.g., negative amounts, state-machine bypass).\n"
            "4. **Prioritized Attack Plan**: List the top 5 'Most Likely Vulnerable' endpoints. For each, specify if the test is an IDOR, a Race Condition, or a Logic Bypass, and give the 'Hacker Story'.\n\n"
            "Ignore all static assets and tracking pixels."
        )

        self.notebook.select(self.ai_tab)
        self.log_to_ai("Performing Enriched Logic Recon on Site Map...", sender="System")
        
        # Add to history for context - Use ACTUAL prompt so all providers see the data
        self.ai_history.append({"role": "user", "content": prompt})
        
        threading.Thread(target=self._perform_ai_query, args=(prompt,), daemon=True).start()

    def send_site_map_to_repeater(self):
        """Sends the selected flow from the Site Map to the Repeater."""
        selected = self.site_map_tree.selection()
        if not selected:
            return
        node_id = selected[0]
        
        flow_id = getattr(self, "node_to_flow", {}).get(node_id)
        if not flow_id or flow_id not in self.flows:
            # If it's a folder/host node without a direct flow, maybe alert user or do nothing
            return

        flow = self.flows[flow_id]
        req = flow.get("request", {})
        
        # Reuse existing logic to format request string
        headers_str = "\n".join([f"{k}: {v}" for k, v in req.get("headers", [])])
        try:
            body_str = req.get("content", b"").decode('utf-8', errors='replace')
        except:
            body_str = str(req.get("content", b""))

        full_request_str = f"{req.get('method')} {req.get('url')} HTTP/1.1\n{headers_str}\n\n{body_str}"

        # Create tab and switch
        self._create_new_repeater_tab(full_request_str)
        self.notebook.select(self.repeater_tab)

    def copy_site_map_url(self):
        """Copies the URL corresponding to the selected Site Map node."""
        selected = self.site_map_tree.selection()
        if not selected:
            return
        node_id = selected[0]
        
        # Check if it's a host node (parent is empty)
        parent = self.site_map_tree.parent(node_id)
        if not parent:
            # It's a host node
            url = self.site_map_tree.item(node_id, "text")
            self.copy_to_clipboard(url)
            return

        # It's a path segment. We need to reconstruct the full URL.
        # Or more easily, check if it's a leaf node with a flow_id
        flow_id = getattr(self, "node_to_flow", {}).get(node_id)
        if flow_id and flow_id in self.flows:
            url = self.flows[flow_id]["request"]["url"]
            self.copy_to_clipboard(url)
        else:
            # Reconstruct from tree hierarchy
            path_parts = []
            curr = node_id
            while curr:
                path_parts.insert(0, self.site_map_tree.item(curr, "text"))
                curr = self.site_map_tree.parent(curr)
            
            # parts[0] is protocol://host, rest are segments
            host = path_parts[0]
            path = "/".join(path_parts[1:])
            if not path.startswith("/") and path != "":
                path = "/" + path
            
            self.copy_to_clipboard(host + path)

    def on_site_map_select(self, event):
        """Displays request/response details when a node in the site map is selected."""
        selected_items = self.site_map_tree.selection()
        if not selected_items:
            return
        
        node_id = selected_items[0]
        # Find if this node has an associated flow_id
        # We'll store this in a dictionary mapping node_id -> flow_id
        flow_id = getattr(self, "node_to_flow", {}).get(node_id)
        
        self.site_map_req_text.delete("1.0", tk.END)
        self.site_map_resp_text.delete("1.0", tk.END)

        if flow_id and flow_id in self.flows:
            flow = self.flows[flow_id]
            
            # Populate Request
            req = flow.get("request", {})
            req_headers = "\n".join([f"{k}: {v}" for k, v in req.get("headers", [])])
            try:
                req_body = req.get("content", b"").decode('utf-8', errors='replace')
            except:
                req_body = str(req.get("content", b""))
            
            req_full = f"{req.get('method')} {req.get('url')} HTTP/1.1\n{req_headers}\n\n{req_body}"
            self.safe_insert_text(self.site_map_req_text, req_full)

            # Populate Response
            resp = flow.get("response")
            if resp:
                resp_headers = "\n".join([f"{k}: {v}" for k, v in resp.get("headers", [])])
                try:
                    resp_body = resp.get("content", b"").decode('utf-8', errors='replace')
                except:
                    resp_body = str(resp.get("content", b""))
                
                status_line = f"HTTP/1.1 {resp.get('status_code')}" # Simplified
                resp_full = f"{status_line}\n{resp_headers}\n\n{resp_body}"
                self.safe_insert_text(self.site_map_resp_text, resp_full)
            else:
                self.site_map_resp_text.delete("1.0", tk.END)
                self.site_map_resp_text.insert("1.0", "(No response yet)")

    def add_to_site_map(self, flow_id, flow_data, is_interesting=False):
        """Adds a URL from a flow to the hierarchical site map."""
        from urllib.parse import urlparse
        url = flow_data["url"]
        parsed = urlparse(url)
        
        host = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        if not path:
            path = "/"
        
        # 1. Ensure Host node exists
        if host not in self.site_map_nodes:
            node_id = self.site_map_tree.insert("", tk.END, text=host, open=True)
            self.site_map_nodes[host] = node_id
        
        parent_node = self.site_map_nodes[host]
        
        # 2. Build Path hierarchy
        segments = [s for s in path.split("/") if s]
        current_path = host
        tag = "interesting" if is_interesting else ""
        
        if not segments:
            # Root path "/"
            full_path = host + "/"
            if full_path not in self.site_map_nodes:
                node_id = self.site_map_tree.insert(parent_node, tk.END, text="/", tags=(tag,))
                self.site_map_nodes[full_path] = node_id
            
            if not hasattr(self, "node_to_flow"): self.node_to_flow = {}
            self.node_to_flow[self.site_map_nodes[full_path]] = flow_id
            return

        for segment in segments:
            current_path += "/" + segment
            if current_path not in self.site_map_nodes:
                node_id = self.site_map_tree.insert(parent_node, tk.END, text=segment, tags=(tag,))
                self.site_map_nodes[current_path] = node_id
            
            parent_node = self.site_map_nodes[current_path]
        
        # Associate the leaf node with the flow_id
        if not hasattr(self, "node_to_flow"): self.node_to_flow = {}
        self.node_to_flow[parent_node] = flow_id

    def toggle_intercept(self):
        self.is_intercepting = not self.is_intercepting
        state_text = "ON" if self.is_intercepting else "OFF"
        self.intercept_button.config(text=f"Intercept: {state_text}")
        # Send command to proxy thread, which will trigger UI updates via the queue
        self.proxy_manager.toggle_intercept(self.is_intercepting)

    def forward_intercepted_request(self):
        if not self.intercepted_flow:
            return

        # Use end-1c to avoid the trailing newline Tkinter adds
        raw_request = self.intercepted_request_text.get("1.0", "end-1c")
        
        try:
            method, url, headers_list, body_bytes = self._parse_raw_request(raw_request)
            if method is None: 
                return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse request for forwarding: {e}")
            return

        updated_data = {
            "method": method,
            "url": url,
            "headers": headers_list,
            "content": body_bytes,
        }

        item_to_put = {
            "command": "forward",
            "flow_id": self.intercepted_flow["flow_id"],
            "data": updated_data
        }
        
        # Send to proxy queue
        self.proxy_queue.put(item_to_put)

        # Clear and disable
        self.intercepted_request_text.delete("1.0", tk.END)
        self.forward_button.config(state="disabled")
        self.drop_button.config(state="disabled")
        self.intercepted_flow = None

    def drop_intercepted_request(self):
        if not self.intercepted_flow:
            return

        item_to_put = {
            "command": "drop",
            "flow_id": self.intercepted_flow["flow_id"],
            "data": None  # Add data key
        }
        # Send to proxy queue
        self.proxy_queue.put(item_to_put)

        # Clear and disable
        self.intercepted_request_text.delete("1.0", tk.END)
        self.forward_button.config(state="disabled")
        self.drop_button.config(state="disabled")
        self.intercepted_flow = None

    def process_gui_queue(self):
        """Process items from the proxy's queue."""
        # Maximum size for text display to prevent UI lag (approx 500KB)
        MAX_DISPLAY_SIZE = 500000
        # More conservative limit for HTML rendering because tkhtmlview is slower
        MAX_RENDER_SIZE = 200000

        try:
            while True:
                item = self.gui_queue.get_nowait()

                if item["type"] == "flow_summary":
                    self.add_flow_to_history(item)
                elif item["type"] == "intercept_request":
                    self.show_intercepted_request(item)
                elif item["type"] == "clear_intercept":
                    self.intercepted_request_text.delete("1.0", tk.END)
                    self.forward_button.config(state="disabled")
                    self.drop_button.config(state="disabled")
                    self.intercepted_flow = None
                elif item["type"] == "websocket_flow":
                    self.log_websocket_data(item["data"])
                elif item["type"] == "match_replace_log":
                    self.add_flow_to_mr_log(item)
                elif item["type"] == "passive_discovery":
                    # Add discovered links to Site Map silently if in scope
                    for item_link in item["flagged_links"]:
                        link = item_link["url"]
                        is_int = item_link["interesting"]
                        if self.proxy_manager.is_url_in_scope(link):
                            self.add_to_site_map(f"passive_{link}", {"url": link}, is_interesting=is_int)
                elif item["type"] == "passive_security_alert":
                    self.add_vulnerability_alert(item)
                elif item["type"] == "intruder_result":
                    data = item["data"]
                    iid = f"intruder_{data['id']}"
                    
                    # Determine tag based on status code
                    status = str(data["status"])
                    tag = ""
                    if status.startswith("2"): tag = "stat_2xx"
                    elif status.startswith("3"): tag = "stat_3xx"
                    elif status.startswith("4"): tag = "stat_4xx"
                    elif status.startswith("5") or status == "ERR": tag = "stat_5xx"

                    self.intruder_res_table.insert("", tk.END, iid=iid, values=(
                        data["id"], data["payload"], data["status"], data["length"], data["time"]
                    ), tags=(tag,))
                    self.intruder_full_results[iid] = data
                elif item["type"] == "repeater_response":
                    tab_id = item.get("tab_id")
                    if tab_id and tab_id in self.repeater_tabs:
                        widgets = self.repeater_tabs[tab_id]
                        data = item["data"]
                        
                        # Raw response
                        self.safe_insert_text(widgets["resp_text"], data["raw"])
                        widgets["resp_text"].config(state='disabled')

                        # Store decoded body
                        self.repeater_tabs[tab_id]["decoded_body"] = data["decoded"]
                        self.repeater_tabs[tab_id]["current_url"] = data.get("url")

                        # Rendered response
                        html_content = data["decoded"]
                        try:
                            if len(html_content) > MAX_RENDER_SIZE:
                                widgets["render_frame"].set_html(f"<h3>Response too large to render ({len(html_content)} bytes)</h3><p>Please use the <b>Open in Browser</b> button to view the full response.</p>")
                            elif data["is_html"]:
                                # Inject <base> tag to help with relative resources
                                base_url = data.get("url")
                                if base_url:
                                    if "<head>" in html_content.lower():
                                        html_content = re.sub(r"(<head[^>]*>)", r'\1<base href="' + base_url + '">', html_content, flags=re.IGNORECASE)
                                    else:
                                        html_content = f'<base href="{base_url}">' + html_content
                                widgets["render_frame"].set_html(html_content)
                            else:
                                widgets["render_frame"].set_html(f"<pre>{data['decoded']}</pre>")
                        except tk.TclError as te:
                            widgets["render_frame"].set_html(f"<h3>Render Error</h3><p>Failed to render HTML due to invalid styles in response: {te}</p><p>Please use <b>Open in Browser</b> to view the response reliably.</p>")
                        except Exception as e:
                            widgets["render_frame"].set_html(f"<h3>Render Error</h3><p>An unexpected error occurred during rendering: {e}</p>")

                        # Handle Follow Redirect button
                        follow_button = widgets["follow_redirect_button"]
                        if data.get("is_redirect") and data.get("redirect_location"):
                            self.repeater_tabs[tab_id]["redirect_location"] = data["redirect_location"]
                            follow_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5,0))
                        else:
                            self.repeater_tabs[tab_id]["redirect_location"] = None
                            follow_button.pack_forget()

                        widgets["send_button"].config(state='normal')
                        
                        # Update Response Time Label
                        time_ms = data.get("time_ms", 0)
                        widgets["time_label"].config(text=f"Time: {time_ms} ms")

        except queue.Empty:
            pass  # No items in queue
        finally:
            # Schedule the next check
            self.root.after(100, self.process_gui_queue)

    def log_websocket_data(self, data):
        """Formats and logs WebSocket data to the UI."""
        self.ws_log.config(state="normal")
        
        event = data.get("event")
        if event == "start":
            log_message = f"[+] WebSocket Connection Established: {data.get('url')}\n"
        elif event == "end":
            log_message = f"[-] WebSocket Connection Closed.\n{'-'*40}\n"
        elif event == "message":
            direction = ">> Client -> Server" if data.get('from_client') else "<< Server -> Client"
            
            content = data.get('content')
            try:
                # Try to decode as text/json for readability
                if isinstance(content, bytes):
                    content_str = content.decode('utf-8')
                    try:
                        # Pretty-print if it's JSON
                        parsed_json = json.loads(content_str)
                        content_str = json.dumps(parsed_json, indent=2)
                    except (json.JSONDecodeError, TypeError):
                        pass # Not a JSON string
                else:
                    content_str = str(content)
            except UnicodeDecodeError:
                content_str = f"[Binary Data, Length: {len(content)} bytes]"

            log_message = f"{direction}\n{content_str}\n\n"
        else:
            log_message = f"[?] Unknown WebSocket Event: {data}\n"
            
        self.ws_log.insert(tk.END, log_message)
        self.ws_log.see(tk.END) # Auto-scroll
        self.ws_log.config(state="disabled")

    def add_flow_to_history(self, item):
        flow_id = item["flow_id"]
        data = item["data"]
        
        # Store the full flow data for later use (e.g., repeater)
        self.flows[flow_id] = item.get("full_flow", {})

        # Add to hierarchical Site Map ONLY if in scope
        if self.proxy_manager.is_url_in_scope(data["url"]):
            sensitive_patterns = [r"\.env", r"\.git", r"\.sql", r"config", r"backup", r"admin", r"password", r"secret"]
            is_int = any(re.search(pat, data["url"], re.I) for pat in sensitive_patterns)
            self.add_to_site_map(flow_id, data, is_interesting=is_int)

        # Store the summary for filtering
        summary_item = {
            "flow_id": flow_id,
            "method": data["method"],
            "url": data["url"],
            "status_code": data["status_code"]
        }
        self.all_flows_summary.append(summary_item)

        # Only add to Treeview if it matches the current filters
        # Note: 'Filter by Scope' checkbox in the UI handles the visibility in this table
        if self._matches_filter_domain(summary_item["url"], self.current_filter_domain) and \
           self._matches_filter_method(summary_item["method"], self.current_filter_method):
            
            # Check if 'Filter by Scope' is active before inserting into the history table
            matches_scope = True
            if self.filter_history_by_scope_var.get():
                matches_scope = self.proxy_manager.is_url_in_scope(summary_item["url"])
            
            if matches_scope:
                # Determine tag based on Method
                method = data["method"].upper()
                tag = f"meth_{method}"
                if tag not in ["meth_GET", "meth_POST", "meth_PUT", "meth_DELETE"]:
                    tag = "meth_OTHER"

                self.history_table.insert(
                    "", tk.END, iid=flow_id,
                    values=(flow_id, data["method"], data["url"], data["status_code"]),
                    tags=(tag,)
                )
                self.history_table.yview_moveto(1) # Auto-scroll to bottom

    def show_intercepted_request(self, item):
        # Clear any previous search results when a new request comes in
        self.clear_intercept_search()

        self.intercepted_flow = item
        data = item["data"]
        
        headers_str = ""
        for k, v in data["headers"]:
            # Hide pseudo-headers from the UI to avoid confusion and prevent 400s on forward
            if k.startswith(':'):
                continue
            headers_str += f"{k}: {v}\n"

        try:
            # Try to decode as UTF-8, fall back to raw representation
            body_content = data["content"].decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            body_content = str(data["content"])

        # Use the full URL in the request line for consistency
        request_line = f"{data['method']} {data['url']} HTTP/1.1"
        full_request = f"{request_line}\n{headers_str}\n{body_content}"
        
        self.safe_insert_text(self.intercepted_request_text, full_request)
        
        self.forward_button.config(state="normal")
        self.drop_button.config(state="normal")
        

    def send_repeater_request(self):
        """Parses the repeater text from the current tab and sends the request."""
        current_tab_id = self.get_current_repeater_tab_id()
        if not current_tab_id:
            return

        widgets = self.repeater_tabs[current_tab_id]
        req_text_widget = widgets["req_text"]
        resp_text_widget = widgets["resp_text"]
        send_button = widgets["send_button"]

        raw_request = req_text_widget.get("1.0", "end-1c")
        if not raw_request.strip():
            messagebox.showerror("Error", "Request is empty.")
            return

        try:
            method, url, headers, body = self._parse_raw_request(raw_request)
            if method is None:
                return
        except Exception as e:
            messagebox.showerror("Parsing Error", f"Failed to parse request: {e}")
            return
        
        send_button.config(state='disabled')
        resp_text_widget.config(state='normal')
        resp_text_widget.delete("1.0", tk.END)
        resp_text_widget.insert("1.0", "Sending request...")
        resp_text_widget.config(state='disabled')

        thread = threading.Thread(
            target=self._send_request_thread,
            args=(method, url, headers, body, current_tab_id),
            daemon=True
        )
        thread.start()

    def _parse_raw_request(self, raw_request: str):
        """Robustly parses a raw HTTP request, ensuring compatibility and binary preservation."""
        # 1. Separate head and body
        # We use a very strict split to avoid taking trailing newlines into the body 
        # unless they were explicitly part of it.
        if "\r\n\r\n" in raw_request:
            head, body = raw_request.split("\r\n\r\n", 1)
        elif "\n\n" in raw_request:
            head, body = raw_request.split("\n\n", 1)
        else:
            head = raw_request
            body = ""

        # 2. Extract lines from head
        lines = head.replace("\r", "").split("\n")
        lines = [l.strip() for l in lines if l.strip()]
        
        if not lines:
            return None, None, None, None

        request_line = lines[0]
        header_lines = lines[1:]

        # 3. Parse Request Line
        try:
            parts = request_line.split(" ")
            if len(parts) < 2:
                raise ValueError("Invalid request line")
            method = parts[0].upper()
            path = parts[1]
        except Exception:
            messagebox.showerror("Error", "Invalid request line format. Expected: METHOD PATH HTTP/VERSION")
            return None, None, None, None

        # 4. Parse Headers (list of pairs)
        headers_list = []
        for line in header_lines:
            if not line.strip(): continue
            if line.startswith(":"): continue # Skip pseudo-headers
            if ":" in line:
                key, value = line.split(":", 1)
                k_clean = key.strip()
                # 5. CRITICAL: Skip Host and Content-Length here. 
                # The Proxy Engine will re-add them correctly based on the target URL and body length.
                if k_clean.lower() in ["host", "content-length", "transfer-encoding", "te"]:
                    continue
                headers_list.append((k_clean, value.lstrip(" ")))

        # 6. Determine Target Host (Required for mitmproxy routing)
        # We still need to find the host to reconstruct the full URL.
        host = None
        for line in header_lines:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() == "host":
                    host = v.strip()
                    break
        
        if not host:
            from urllib.parse import urlparse
            p_url = urlparse(path)
            if p_url.netloc:
                host = p_url.netloc
            elif "://" in path:
                host = path.split("://")[1].split("/")[0]

        if not host:
            messagebox.showerror("Error", "Host header is missing. Please ensure the 'Host: ...' header is present in the request.")
            return None, None, None, None

        # 7. Get Body Bytes (Surgical Encoding)
        try:
            body_bytes = body.encode("latin-1")
        except UnicodeEncodeError:
            body_bytes = body.encode("utf-8")

        # 8. Reconstruct Target URL
        scheme = "https" # Default
        if host and (":80" in host or ":8080" in host): scheme = "http"

        if "://" in path:
            url = path
        else:
            if not path.startswith("/"): path = "/" + path
            url = f"{scheme}://{host}{path}"
        
        return method, url, headers_list, body_bytes

    def _send_request_thread(self, method, url, headers, body, tab_id):
        """The actual networking code that runs in a thread."""
        import urllib.request
        import ssl
        import gzip
        import zlib
        import time # Added for timing

        # 1. Convert headers list to dict for urllib.request compatibility
        headers_dict = dict(headers)
        
        # 2. Add identification header to prevent self-interception
        headers_dict['X-Proxy-Tool-Internal'] = 'repeater-request'

        full_response = "" 
        decoded_body = ""
        is_html = False
        is_redirect = False
        redirect_location = None
        start_time = time.perf_counter()

        try:
            # 3. Ensure body is bytes if provided
            encoded_body = None
            if body:
                if isinstance(body, str):
                    encoded_body = body.encode('utf-8', errors='replace')
                else:
                    encoded_body = body

            # Create a request object
            req = urllib.request.Request(url, data=encoded_body, headers=headers_dict, method=method.upper())

            unverified_context = ssl._create_unverified_context()
            class CustomHTTPSHandler(urllib.request.HTTPSHandler):
                def __init__(self, context): super().__init__(context=context)
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def http_error_302(self, req, fp, code, msg, headers):
                    raise urllib.error.HTTPError(req.get_full_url(), code, msg, headers, fp)
                def http_error_301(self, req, fp, code, msg, headers):
                    raise urllib.error.HTTPError(req.get_full_url(), code, msg, headers, fp)

            
            proxy_handler = urllib.request.ProxyHandler({
                'http': f'http://{self.config["host"]}:{self.config["port"]}',
                'https': f'http://{self.config["host"]}:{self.config["port"]}'
            })
            
            opener = urllib.request.build_opener(
                proxy_handler, 
                CustomHTTPSHandler(context=unverified_context),
                NoRedirectHandler()
            )
            
            with opener.open(req, timeout=self.config.get("timeout", 30)) as response:
                end_time = time.perf_counter()
                elapsed_ms = int((end_time - start_time) * 1000)
                
                status_code = response.status
                response_body = response.read()
                response_headers = response.info()
                status_line = f"HTTP/{response.version / 10.0} {status_code} {response.reason}"
                
                if status_code in [301, 302, 303, 307]:
                    is_redirect = True
                    redirect_location = response_headers.get('Location')

                # Decompression and decoding logic...
                content_encoding = response_headers.get('Content-Encoding', '').lower()
                if 'gzip' in content_encoding:
                    try: response_body = gzip.decompress(response_body)
                    except Exception: pass
                elif 'deflate' in content_encoding:
                    try: response_body = zlib.decompress(response_body)
                    except Exception: pass
                elif 'zstd' in content_encoding: # Added for ZSTD
                    try: response_body = zstandard.decompress(response_body)
                    except Exception: pass
                elif 'br' in content_encoding: # Added for Brotli
                    try: response_body = brotli.decompress(response_body)
                    except Exception: pass

                content_type_header = response_headers.get('Content-Type', '').lower()
                if 'text/html' in content_type_header: is_html = True
                
                # Robust decoding: if it's common text types OR if it's small/printable, decode it
                is_likely_text = any(t in content_type_header for t in ['text', 'json', 'xml', 'javascript', 'html'])
                
                if is_likely_text or not content_type_header:
                    charset = 'utf-8'
                    if 'charset=' in content_type_header:
                        try: charset = content_type_header.split('charset=')[1].split(';')[0].strip()
                        except IndexError: pass
                    try: decoded_body = response_body.decode(charset, errors='replace')
                    except (UnicodeDecodeError, LookupError):
                        decoded_body = response_body.decode('latin-1', errors='replace') + \
                                    f"\n\n[Content-Type: {content_type_header} - Decoded with latin-1 due to encoding issues]"
                else:
                    decoded_body = f"[Binary Content - Content-Type: {content_type_header}] (Length: {len(response_body)} bytes)"
                
                full_response = f"{status_line}\n{str(response_headers)}\n\n{decoded_body}"

        except urllib.error.HTTPError as e:
            end_time = time.perf_counter()
            elapsed_ms = int((end_time - start_time) * 1000)
            
            status_code = e.code
            response_body = e.read()
            response_headers = e.headers
            status_line = f"HTTP/{e.version / 10.0} {status_code} {e.reason}"

            if status_code in [301, 302, 303, 307]:
                is_redirect = True
                redirect_location = response_headers.get('Location')

            content_encoding = response_headers.get('Content-Encoding', '').lower()
            if 'gzip' in content_encoding:
                try: response_body = gzip.decompress(response_body)
                except Exception: pass
            elif 'deflate' in content_encoding:
                try: response_body = zlib.decompress(response_body)
                except Exception: pass
            elif 'zstd' in content_encoding: # Added for ZSTD
                try: response_body = zstandard.decompress(response_body)
                except Exception: pass
            elif 'br' in content_encoding: # Added for Brotli
                try: response_body = brotli.decompress(response_body)
                except Exception: pass
            
            content_type_header = response_headers.get('Content-Type', '').lower()
            if 'text/html' in content_type_header: is_html = True
            
            try:
                decoded_body = response_body.decode('utf-8', errors='replace')
            except (UnicodeDecodeError, LookupError):
                decoded_body = response_body.decode('latin-1', errors='replace') + \
                            f"\n\n[Content-Type: {content_type_header} - Decoded with latin-1 due to encoding issues]"
            
            full_response = f"{status_line}\n{str(response_headers)}\n\n{decoded_body}"

        except Exception as e:
            end_time = time.perf_counter()
            elapsed_ms = int((end_time - start_time) * 1000)
            full_response = f"Error: {e}"
            decoded_body = f"Error: {e}"
        
        # Send the response back to the main thread for display
        self.gui_queue.put({
            "type": "repeater_response",
            "tab_id": tab_id,
            "data": {
                "url": url,
                "raw": full_response,
                "decoded": decoded_body,
                "is_html": is_html,
                "is_redirect": is_redirect,
                "redirect_location": redirect_location,
                "time_ms": elapsed_ms # Send timing data
            }
        })
    
    def apply_filter(self):
        """Applies the domain and method filters to the history table."""
        domain = self.filter_domain_var.get().strip()
        method = self.filter_method_var.get().strip().upper()

        self.current_filter_domain = domain if domain else None
        self.current_filter_method = method if method != "ALL" else None
        
        self._repopulate_history_table()

    def clear_filter(self):
        """Clears all filters and repopulates the history table."""
        self.filter_domain_var.set("")
        self.filter_method_var.set("ALL")
        self.current_filter_domain = None
        self.current_filter_method = None
        self._repopulate_history_table()

    def clear_history(self):
        """Clears all captured history and resets the table."""
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all history? This cannot be undone."):
            # Clear internal storage
            self.flows.clear()
            self.all_flows_summary.clear()
            
            # Repopulate (which will clear the table)
            self._repopulate_history_table()
            
            # Clear detail views in history (if any are currently shown)
            # We don't have separate persistent detail widgets for history selection here
            # but we can clear whatever is currently in the site map views or similar
            # though it's not strictly necessary.

    def _repopulate_history_table(self):
        """Clears the Treeview and repopulates it based on the current filters."""
        # Clear existing items
        for item in self.history_table.get_children():
            self.history_table.delete(item)
        
        # Repopulate with filtered items
        for summary_item in self.all_flows_summary:
            matches_scope = True
            if self.filter_history_by_scope_var.get():
                matches_scope = self.proxy_manager.is_url_in_scope(summary_item["url"])

            if matches_scope and \
               self._matches_filter_domain(summary_item["url"], self.current_filter_domain) and \
               self._matches_filter_method(summary_item["method"], self.current_filter_method):
                
                # Determine tag based on Method
                method = summary_item["method"].upper()
                tag = f"meth_{method}"
                if tag not in ["meth_GET", "meth_POST", "meth_PUT", "meth_DELETE"]:
                    tag = "meth_OTHER"

                self.history_table.insert(
                    "", tk.END, iid=summary_item["flow_id"],
                    values=(summary_item["flow_id"], summary_item["method"], summary_item["url"], summary_item["status_code"]),
                    tags=(tag,)
                )
        self.history_table.yview_moveto(1) # Auto-scroll to bottom

    def _matches_filter_domain(self, url: str, filter_domain: str | None) -> bool:
        """
        Checks if a URL matches the filter. 
        - If filter is just a domain, match all paths on that domain.
        - If filter includes a path, match only that specific path.
        """
        if not filter_domain:
            return True

        filter_text = filter_domain.lower().strip()
        url_lower = url.lower()

        # Check if the filter includes a path (contains a '/' after the domain part)
        has_path = False
        if "://" in filter_text:
            after_proto = filter_text.split("://", 1)[1]
            if "/" in after_proto and len(after_proto.split("/", 1)[1]) > 0:
                has_path = True
        elif "/" in filter_text and not filter_text.endswith("/"):
            # e.g. "example.com/login"
            has_path = True

        if has_path:
            # Path match: The URL must contain the specific filter string
            return filter_text in url_lower
        else:
            # Domain match: Match only the domain part
            try:
                from urllib.parse import urlparse
                parsed_filter = urlparse(filter_text if "://" in filter_text else f"http://{filter_text}")
                filter_host = (parsed_filter.hostname or filter_text.split('/')[0]).lower().lstrip("www.")
                
                parsed_url = urlparse(url_lower)
                url_host = (parsed_url.hostname or "").lstrip("www.")
                
                return url_host == filter_host or url_host.endswith(f".{filter_host}")
            except:
                return filter_text in url_lower

    def _matches_filter_method(self, method: str, filter_method: str | None) -> bool:
        """Checks if a request's method matches the filter."""
        if not filter_method or filter_method == "ALL":
            return True # No filter applied
        return method.upper() == filter_method.upper()

    def on_closing(self):
        """Handle window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.shutdown()

    def go_back_in_repeater(self, tab_id):
        """Restores the previous request in the repeater."""
        if not tab_id or tab_id not in self.repeater_tabs:
            return

        widgets = self.repeater_tabs[tab_id]
        previous_request = self.repeater_tabs[tab_id].get("previous_request")

        if not previous_request:
            return

        # Restore the previous request
        widgets["req_text"].delete("1.0", tk.END)
        widgets["req_text"].insert("1.0", previous_request)

        # Clear the response area
        widgets["resp_text"].config(state='normal')
        widgets["resp_text"].delete("1.0", tk.END)
        widgets["resp_text"].config(state='disabled')
        widgets["render_frame"].set_html("")

        # Hide the back button and clear the stored previous request
        widgets["back_button"].pack_forget()
        self.repeater_tabs[tab_id]["previous_request"] = None

    def follow_redirect(self, tab_id):
        """Prepares the repeater to follow a redirect."""
        if not tab_id or tab_id not in self.repeater_tabs:
            return

        widgets = self.repeater_tabs[tab_id]
        location = self.repeater_tabs[tab_id].get("redirect_location")

        if not location:
            return

        from urllib.parse import urlparse, urljoin

        # Get the URL of the original request to handle relative redirects
        original_request_raw = widgets["req_text"].get("1.0", tk.END)
        try:
            # We don't need the full parse, just a rough way to get the original URL
            _, original_url, _, _ = self._parse_raw_request(original_request_raw)
            if not original_url:
                raise ValueError("Could not determine original URL")
        except Exception:
            messagebox.showerror("Error", "Could not determine the original request's URL to resolve the redirect.")
            return
            
        # Create the new absolute URL for the redirect
        new_url = urljoin(original_url, location)
        
        parsed_new_url = urlparse(new_url)
        host = parsed_new_url.hostname
        port = parsed_new_url.port
        path = parsed_new_url.path or "/"
        if parsed_new_url.query:
            path += "?" + parsed_new_url.query

        # Build the host header, including port if it's not standard
        host_header = host
        if port and port not in [80, 443]:
            host_header += f":{port}"

        # Create a simple GET request for the new location
        new_request_str = (
            f"GET {path} HTTP/1.1\n"
            f"Host: {host_header}\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\n"
            "Accept: */*\n"
            "Accept-Encoding: gzip, deflate\n"
            "Connection: close\n\n"
        )

        # Save the current request before overwriting it
        original_request = widgets["req_text"].get("1.0", tk.END)
        self.repeater_tabs[tab_id]["previous_request"] = original_request
        widgets["back_button"].pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5,0))

        # Update the request text area with the new request
        widgets["req_text"].delete("1.0", tk.END)
        widgets["req_text"].insert("1.0", new_request_str)

        # Clear the response area
        widgets["resp_text"].config(state='normal')
        widgets["resp_text"].delete("1.0", tk.END)
        widgets["resp_text"].config(state='disabled')
        
        # Clear the rendered view
        widgets["render_frame"].set_html("")

        # Hide the follow redirect button again
        widgets["follow_redirect_button"].pack_forget()
        self.repeater_tabs[tab_id]["redirect_location"] = None

    def close_repeater_tab(self, tab_id):
        """Closes a specific repeater tab and cleans up."""
        if tab_id not in self.repeater_tabs:
            return
        
        widgets = self.repeater_tabs[tab_id]
        tab_frame = widgets["frame"]
        
        # Remove from notebook
        self.repeater_notebook.forget(tab_frame)
        
        # Remove from tracking dictionary
        del self.repeater_tabs[tab_id]
        
        # If no tabs left, create a fresh empty one
        if not self.repeater_tabs:
            self._create_new_repeater_tab()

    def open_response_in_browser(self, tab_id):
        """Saves the current response HTML to a temporary file and opens it in the default browser."""
        if tab_id not in self.repeater_tabs:
            return
        
        html_content = self.repeater_tabs[tab_id].get("decoded_body")
        base_url = self.repeater_tabs[tab_id].get("current_url")
        
        if not html_content:
            messagebox.showinfo("Info", "No response content to open.")
            return

        # Prepare HTML with base tag for the real browser
        if base_url and "<head>" in html_content.lower():
            html_content = re.sub(r"(<head[^>]*>)", r'\1<base href="' + base_url + '">', html_content, flags=re.IGNORECASE)
        elif base_url:
            html_content = f'<base href="{base_url}">' + html_content

        try:
            # Use a temporary file with .html extension
            with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html', encoding='utf-8') as f:
                f.write(html_content)
                temp_path = f.name
            
            # Open the file in the default web browser
            webbrowser.open(f"file://{temp_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open in browser: {e}")

    def _init_ai_tab(self):
        """Initializes the AI Assistant tab with a chat-like interface."""
        main_pane = ttk.PanedWindow(self.ai_tab, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # AI Output Log
        self.ai_log = scrolledtext.ScrolledText(
            main_pane, 
            wrap=tk.WORD, 
            state="normal", # Set to normal to ensure selection is visible
            bg="#f0f0f0", 
            exportselection=True,
            selectbackground="#ff0000", 
            selectforeground="white",
            undo=False
        )
        # Block most key presses to make it read-only but allow selection and copy
        self.ai_log.bind("<Key>", self._on_ai_log_key)
        # Ensure selection is always on top of colored tags
        self.ai_log.tag_raise("sel")
        main_pane.add(self.ai_log, weight=3)

        # Context Menu for AI Log
        self.ai_log_context_menu = tk.Menu(self.root, tearoff=0)
        self.ai_log_context_menu.add_command(label="Copy", command=self.copy_selected_ai_text)
        self.ai_log.bind("<Button-3>", self.show_ai_log_context_menu)

        # Input Area
        input_frame = ttk.Frame(main_pane)
        main_pane.add(input_frame, weight=1)

        self.ai_input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=5)
        self.ai_input_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.ai_input_text.bind("<Return>", self.send_chat_to_ai)

        send_btn = ttk.Button(input_frame, text="Send to AI", command=self.send_chat_to_ai)
        send_btn.pack(side=tk.RIGHT, fill=tk.Y)

        check_btn = ttk.Button(input_frame, text="Check AI Connection", command=self.check_ai_connection)
        check_btn.pack(side=tk.RIGHT, fill=tk.Y, padx=5)

        clear_btn = ttk.Button(input_frame, text="Clear Log", command=self.clear_ai_log)
        clear_btn.pack(side=tk.RIGHT, fill=tk.Y)

    def log_to_ai(self, message, sender="System"):
        """Helper to add text to the AI log with colored backgrounds."""
        # Define tags with colors
        self.ai_log.tag_configure("ai", background="#e1f5fe", foreground="#01579b", spacing1=5, spacing3=5, lmargin1=10, rmargin=10)
        self.ai_log.tag_configure("user", background="#e8f5e9", foreground="#1b5e20", spacing1=5, spacing3=5, lmargin1=10, rmargin=10)
        self.ai_log.tag_configure("system", background="#f5f5f5", foreground="#424242", spacing1=2, spacing3=2, font=("Helvetica", 9, "italic"))
        self.ai_log.tag_configure("bold", font=("Helvetica", 10, "bold"))

        tag = sender.lower()
        
        # Insert Header
        self.ai_log.insert(tk.END, f"[{sender}]\n", (tag, "bold"))
        
        # Insert Body
        self.ai_log.insert(tk.END, f"{message}\n\n", tag)
        
        # Ensure selection is always on top
        self.ai_log.tag_raise("sel")
        self.ai_log.see(tk.END)

    def clear_ai_log(self):
        """Clears all text and memory from the AI Assistant."""
        self.ai_log.delete("1.0", tk.END)
        self.ai_history = [] # Reset memory
        self.log_to_ai("Log and memory cleared. Ready for next analysis.", sender="System")

    def copy_selected_ai_text(self):
        """Copies the selected text from the AI log to the clipboard."""
        try:
            selected_text = self.ai_log.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
        except tk.TclError:
            # No text selected
            pass

    def show_ai_log_context_menu(self, event):
        """Shows the context menu for the AI log."""
        self.ai_log_context_menu.post(event.x_root, event.y_root)

    def _on_ai_log_key(self, event):
        """Makes the AI log read-only while allowing copy and selection."""
        # Allow copy (Ctrl+C)
        if event.state & 4 and event.keysym.lower() == 'c':
            return
        # Allow select all (Ctrl+A)
        if event.state & 4 and event.keysym.lower() in ('a', 'A'):
            # It's easier to just select all and not fight the widget
            self.ai_log.tag_add(tk.SEL, "1.0", tk.END)
            return "break" # Prevent default 'a' insertion
            
        # Allow navigation keys for selection with Shift
        if event.keysym in ('Left', 'Right', 'Up', 'Down', 'End', 'Home', 
                           'Shift_L', 'Shift_R', 'Control_L', 'Control_R'):
            return 
            
        # Block all other key presses
        return "break"

    def send_chat_to_ai(self, event=None):
        """Sends the user's input from the chat box to the AI."""
        if not self.ai_enabled:
            messagebox.showwarning("AI Disabled", "Please provide an AI API Key in the Configuration tab.")
            return

        user_input = self.ai_input_text.get("1.0", tk.END).strip()
        if not user_input:
            return

        self.log_to_ai(user_input, sender="User")
        self.ai_input_text.delete("1.0", tk.END)
        
        # Add to history for context
        self.ai_history.append({"role": "user", "content": user_input})
        if len(self.ai_history) > 20: # Increased memory size slightly
            self.ai_history.pop(0) 

        # Pass the full history to the query thread
        threading.Thread(target=self._perform_ai_query, args=(self.ai_history,), daemon=True).start()
        
        # Prevent the default newline insertion from the <Return> event
        return "break"

    def _perform_ai_query(self, prompt_with_history):
        """Handles the actual API call to the selected AI provider."""
        try:
            provider = self.config.get("ai_provider", "Gemini")
            api_key = self.config.get("gemini_api_key")
            model_name = self.config.get("ai_model_name", "gemini-2.0-flash")

            if provider == "Gemini":
                # For Gemini, the prompt is the history array. Roles MUST be 'user' or 'model'
                gemini_history = []
                for msg in prompt_with_history:
                    role = "model" if msg["role"] == "assistant" else msg["role"]
                    gemini_history.append({"role": role, "content": msg["content"]})
                
                chat = self.ai_model.start_chat(history=gemini_history[:-1]) # Don't include the last user message
                response = chat.send_message(gemini_history[-1]['content'])
                ai_response = response.text
            else:
                # For OpenAI/Groq style APIs. Roles MUST be 'user' or 'assistant'
                base_url = self.config.get("ai_base_url", "https://api.groq.com/openai/v1").rstrip("/")
                headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                
                openai_history = []
                for msg in prompt_with_history:
                    role = "assistant" if msg["role"] == "model" else msg["role"]
                    openai_history.append({"role": role, "content": msg["content"]})

                payload = {"model": model_name, "messages": openai_history}
                resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=30)
                resp.raise_for_status()
                ai_response = resp.json()["choices"][0]["message"]["content"]
            
            # Add AI response to memory
            # Gemini uses 'model', OpenAI/Groq uses 'assistant'
            role_name = "model" if provider == "Gemini" else "assistant"
            self.ai_history.append({"role": role_name, "content": ai_response})

            self.root.after(0, self.log_to_ai, ai_response, "AI")
        except Exception as e:
            error_message = f"AI Error: {e}"
            self.root.after(0, self.log_to_ai, error_message, "System")
            # Also remove the last user message from history if AI fails
            if self.ai_history and self.ai_history[-1]["role"] == "user":
                self.ai_history.pop()

    def check_ai_connection(self):
        """Checks if the AI is configured and reachable."""
        if not self.ai_enabled:
            self.log_to_ai("AI is not configured. Please add your API key in the Configuration tab.", "System")
            return

        self.log_to_ai("Checking AI connection...", "System")
        
        # Use a simple prompt for testing
        test_prompt = "Hello! Are you working correctly? Respond with just 'OK'."
        
        def _check():
            try:
                provider = self.config.get("ai_provider", "Gemini")
                api_key = self.config.get("gemini_api_key")
                model_name = self.config.get("ai_model_name", "gemini-2.0-flash")
                
                if provider == "Gemini":
                    response = self.ai_model.generate_content(test_prompt)
                    result = response.text
                else:
                    base_url = self.config.get("ai_base_url", "https://api.groq.com/openai/v1").rstrip("/")
                    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                    payload = {"model": model_name, "messages": [{"role": "user", "content": test_prompt}]}
                    resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=15)
                    resp.raise_for_status()
                    result = resp.json()["choices"][0]["message"]["content"]

                if "ok" in result.lower():
                    self.root.after(0, self.log_to_ai, f"Connection successful to {provider} ({model_name}). Ready.", "System")
                else:
                    self.root.after(0, self.log_to_ai, f"AI responded unexpectedly: {result}", "System")
            except Exception as e:
                self.root.after(0, self.log_to_ai, f"Connection failed: {e}", "System")

        threading.Thread(target=_check, daemon=True).start()

    def _init_racer_tab(self):
        """Initializes the UI for the Race Condition tab."""
        main_pane = ttk.PanedWindow(self.racer_tab, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Top: Configuration
        config_frame = ttk.LabelFrame(main_pane, text="Race Configuration")
        main_pane.add(config_frame, weight=1)

        input_split = ttk.PanedWindow(config_frame, orient=tk.HORIZONTAL)
        input_split.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left: Raw Request
        req_frame = ttk.Frame(input_split)
        input_split.add(req_frame, weight=3)
        ttk.Label(req_frame, text="Raw Request:").pack(anchor=tk.W)
        self.racer_raw_req_text = scrolledtext.ScrolledText(req_frame, wrap=tk.WORD)
        self.racer_raw_req_text.pack(fill=tk.BOTH, expand=True)

        # Right: Settings
        settings_frame = ttk.Frame(input_split)
        input_split.add(settings_frame, weight=1)
        
        ttk.Label(settings_frame, text="Requests:").pack(anchor=tk.W, pady=(10,0))
        self.racer_count_var = tk.IntVar(value=20)
        ttk.Entry(settings_frame, textvariable=self.racer_count_var).pack(fill=tk.X)

        ttk.Label(settings_frame, text="Strategy:").pack(anchor=tk.W, pady=(10,0))
        self.racer_strategy_var = tk.StringVar(value="Simultaneous")
        ttk.Combobox(settings_frame, textvariable=self.racer_strategy_var, values=["Simultaneous", "Staggered", "HTTP/2 Single Packet"], state="readonly").pack(fill=tk.X)

        self.racer_use_proxy_var = tk.BooleanVar(value=False) # Default to False for maximum speed
        ttk.Checkbutton(settings_frame, text="Use Proxy", variable=self.racer_use_proxy_var).pack(anchor=tk.W, pady=5)

        self.racer_start_btn = ttk.Button(settings_frame, text="START RACE", command=self.start_race_test)
        self.racer_start_btn.pack(fill=tk.X, pady=20)


        # Bottom: Results & Preview
        results_pane = ttk.PanedWindow(main_pane, orient=tk.VERTICAL)
        main_pane.add(results_pane, weight=3)

        # Upper part of results: Table
        table_frame = ttk.LabelFrame(results_pane, text="Race Condition Results")
        results_pane.add(table_frame, weight=1)

        # Race Filter Bar
        r_filter_frame = ttk.Frame(table_frame)
        r_filter_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(r_filter_frame, text="Filter by Status:").pack(side=tk.LEFT)
        self.racer_filter_var = tk.StringVar(value="All")
        self.racer_filter_combo = ttk.Combobox(r_filter_frame, textvariable=self.racer_filter_var, values=["All"], state="readonly", width=10)
        self.racer_filter_combo.pack(side=tk.LEFT, padx=5)
        self.racer_filter_combo.bind("<<ComboboxSelected>>", self.apply_racer_filter)
        
        ttk.Button(r_filter_frame, text="Clear Results", command=self.clear_racer_results).pack(side=tk.RIGHT, padx=5)

        self.racer_results_table = ttk.Treeview(table_frame, columns=("id", "status", "length", "time"), show="headings")
        self.racer_results_table.heading("id", text="Req #")
        self.racer_results_table.heading("status", text="Status")
        self.racer_results_table.heading("length", text="Length")
        self.racer_results_table.heading("time", text="Time (ms)")
        self.racer_results_table.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        self.racer_results_table.bind("<<TreeviewSelect>>", self.on_racer_result_select)

        # Configure Status Tags for Racer
        self.racer_results_table.tag_configure("stat_2xx", foreground="#008000") # Green
        self.racer_results_table.tag_configure("stat_3xx", foreground="#cc7a00") # Orange
        self.racer_results_table.tag_configure("stat_4xx", foreground="#ff0000") # Red
        self.racer_results_table.tag_configure("stat_5xx", foreground="#800080") # Purple

        scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.racer_results_table.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.racer_results_table.configure(yscroll=scroll.set)

        # Context Menu for Racer Results
        self.racer_context_menu = tk.Menu(self.root, tearoff=0)
        self.racer_context_menu.add_command(label="Send to Match & Replace", command=self.send_racer_result_to_mr)
        self.racer_context_menu.add_command(label="Send to Repeater", command=self.send_racer_result_to_repeater)
        self.racer_results_table.bind("<Button-3>", self.show_racer_context_menu)

        # Lower part of results: Request/Response Preview
        preview_frame = ttk.Frame(results_pane)
        results_pane.add(preview_frame, weight=2)

        # --- Racer Search & Filter Controls (Pack FIRST to keep at TOP) ---
        search_controls = ttk.Frame(preview_frame)
        search_controls.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)

        ttk.Label(search_controls, text="Search Response:").pack(side=tk.LEFT, padx=(0, 5))
        self.racer_search_var = tk.StringVar()
        self.racer_search_entry = ttk.Entry(search_controls, textvariable=self.racer_search_var, width=30)
        self.racer_search_entry.pack(side=tk.LEFT, padx=(0, 5))
        self.racer_search_entry.bind("<Return>", lambda e: self.search_racer_response())

        ttk.Button(search_controls, text="<", width=3, command=lambda: self.navigate_racer_search(-1)).pack(side=tk.LEFT)
        ttk.Button(search_controls, text=">", width=3, command=lambda: self.navigate_racer_search(1)).pack(side=tk.LEFT)
        
        self.racer_search_status = ttk.Label(search_controls, text="")
        self.racer_search_status.pack(side=tk.LEFT, padx=5)

        self.racer_view_mode = tk.StringVar(value="Full") # Full or Body
        ttk.Checkbutton(search_controls, text="View Body Only", variable=self.racer_view_mode, 
                        onvalue="Body", offvalue="Full", command=self.refresh_racer_preview).pack(side=tk.RIGHT)

        preview_tabs = ttk.Notebook(preview_frame)
        preview_tabs.pack(fill=tk.BOTH, expand=True)

        self.racer_req_view = scrolledtext.ScrolledText(preview_tabs, wrap=tk.WORD)
        self.racer_resp_view = scrolledtext.ScrolledText(preview_tabs, wrap=tk.WORD)
        preview_tabs.add(self.racer_req_view, text="Request")
        preview_tabs.add(self.racer_resp_view, text="Response")

        # Highlighting tags
        self.racer_resp_view.tag_configure('search_match', background='yellow', foreground='black')
        self.racer_resp_view.tag_configure('search_active', background='orange', foreground='black')

        # Local storage for full race data
        self.racer_full_data = {} 
        self.racer_matches = []
        self.racer_match_index = -1

    def refresh_racer_preview(self):
        """Refreshes the preview based on current selection and view mode."""
        self.on_racer_result_select(None)

    def on_racer_result_select(self, event):
        """Displays request/response when a race result is clicked."""
        selected = self.racer_results_table.selection()
        if not selected: return
        
        req_id = selected[0]
        data = self.racer_full_data.get(req_id)
        
        self.racer_req_view.delete("1.0", tk.END)
        self.racer_resp_view.delete("1.0", tk.END)
        
        if data:
            self.racer_req_view.insert("1.0", data.get("raw_request", ""))
            
            resp_content = data.get("raw_response", "")
            error_msg = data.get("error_message")
            
            if error_msg:
                resp_content = f"ENGINE ERROR: {error_msg}\n\n{resp_content}"
            
            if self.racer_view_mode.get() == "Body" and "\n\n" in resp_content:
                # 1. Extract only the body
                body_parts = resp_content.split("\n\n", 1)
                body = body_parts[1] if len(body_parts) > 1 else ""
                
                # 2. If it's HTML, strip tags and scripts for a 'Magical' clean view
                if "<html" in body.lower() or "<body" in body.lower() or "<div" in body.lower():
                    # Remove scripts and styles
                    body = re.sub(r"<(script|style).*?>.*?</\1>", "", body, flags=re.DOTALL | re.IGNORECASE)
                    # Strip all remaining HTML tags
                    clean_text = re.sub(r"<.*?>", "", body)
                    # Convert HTML entities like &nbsp; or &amp;
                    import html
                    clean_text = html.unescape(clean_text)
                    # Clean up multiple newlines/spaces
                    resp_content = "\n".join([line.strip() for line in clean_text.splitlines() if line.strip()])
                else:
                    resp_content = body # Keep as-is if it's already clean (like JSON)
            
            self.safe_insert_text(self.racer_resp_view, resp_content)
            # Re-run search if there was a keyword
            if self.racer_search_var.get():
                self.search_racer_response()

    def search_racer_response(self):
        """Finds and highlights keywords in the race response view."""
        self.racer_resp_view.tag_remove('search_match', '1.0', tk.END)
        self.racer_resp_view.tag_remove('search_active', '1.0', tk.END)
        self.racer_matches = []
        self.racer_match_index = -1
        
        keyword = self.racer_search_var.get()
        if not keyword:
            self.racer_search_status.config(text="")
            return

        start = "1.0"
        while True:
            start = self.racer_resp_view.search(keyword, start, stopindex=tk.END, nocase=True)
            if not start: break
            end = f"{start}+{len(keyword)}c"
            self.racer_resp_view.tag_add('search_match', start, end)
            self.racer_matches.append(start)
            start = end
        
        if self.racer_matches:
            self.racer_search_status.config(text=f"Found {len(self.racer_matches)}")
            self.navigate_racer_search(1)
        else:
            self.racer_search_status.config(text="No matches")

    def navigate_racer_search(self, direction):
        """Navigates through search matches."""
        if not self.racer_matches: return
        
        # Remove old active tag
        if self.racer_match_index != -1:
            m = self.racer_matches[self.racer_match_index]
            self.racer_resp_view.tag_remove('search_active', m, f"{m}+{len(self.racer_search_var.get())}c")

        self.racer_match_index = (self.racer_match_index + direction) % len(self.racer_matches)
        
        m = self.racer_matches[self.racer_match_index]
        self.racer_resp_view.tag_add('search_active', m, f"{m}+{len(self.racer_search_var.get())}c")
        self.racer_resp_view.see(m)
        self.racer_search_status.config(text=f"{self.racer_match_index+1} / {len(self.racer_matches)}")


    def show_racer_context_menu(self, event):
        """Display the racer results context menu."""
        item = self.racer_results_table.identify_row(event.y)
        if item:
            self.racer_results_table.selection_set(item)
            self.racer_context_menu.post(event.x_root, event.y_root)

    def send_racer_result_to_repeater(self):
        """Sends the raw request from a racer result to the Repeater."""
        selected = self.racer_results_table.selection()
        if not selected: return
        req_id = selected[0]
        data = self.racer_full_data.get(req_id)
        if data and "raw_request" in data:
            self._create_new_repeater_tab(data["raw_request"])
            self.notebook.select(self.repeater_tab)

    def send_racer_result_to_mr(self):
        """Sends selected text (or whole request) from racer to Match & Replace config."""
        selected = self.racer_results_table.selection()
        if not selected: return
        req_id = selected[0]
        data = self.racer_full_data.get(req_id)
        if not data: return

        # If user has selected text in the preview, use that. Otherwise, use whole req.
        try:
            sel_text = self.racer_req_view.get(tk.SEL_FIRST, tk.SEL_LAST).strip()
        except tk.TclError:
            sel_text = ""

        if not sel_text:
            # Fallback to URL path or first interesting bit? 
            # For now, let's just use the selected text or do nothing
            messagebox.showinfo("Info", "Please select a specific ID or string in the Request/Response preview first.")
            return

        # Switch to Config > Match & Replace
        self.notebook.select(self.config_tab)
        # We need to find the match/replace sub-notebook if it exists
        # In this app, it's just a sub-tab of config
        self.mr_match_var.set(sel_text)
        messagebox.showinfo("Success", f"Sent '{sel_text}' to Match & Replace Match field.")

    def start_race_test(self):
        """Initializes and runs the Race Condition test using the racer module."""
        from racer.racer_manager import RaceTestManager
        
        raw_req = self.racer_raw_req_text.get("1.0", tk.END).strip()
        if not raw_req:
            messagebox.showwarning("Warning", "Please provide a raw request.")
            return

        # Clear old results and storage
        for item in self.racer_results_table.get_children():
            self.racer_results_table.delete(item)
        self.racer_full_data = {}

        test_config = {
            "raw_request": raw_req,
            "num_requests": self.racer_count_var.get(),
            "strategy": self.racer_strategy_var.get(),
            "delay_ms": 0,
            "proxy_config": {"host": self.config["host"], "port": self.config["port"], "use_proxy": self.racer_use_proxy_var.get()}
        }

        self.racer_results_queue = queue.Queue()
        self.racer_manager = RaceTestManager(test_config, self.racer_results_queue)
        
        self.racer_start_btn.config(state="disabled", text="RACING...")
        
        threading.Thread(target=self.racer_manager.run_test, daemon=True).start()
        self.root.after(100, self._process_racer_results)

    def _process_racer_results(self):
        """Polls the racer queue and updates the UI table."""
        try:
            while True:
                res = self.racer_results_queue.get_nowait()
                # Create a unique IID for storage, fallback to random if ID missing
                req_id = res.get('request_id')
                if req_id is None:
                    import uuid
                    item_iid = f"err_{uuid.uuid4().hex[:8]}"
                else:
                    item_iid = f"res_{req_id}"
                
                # Determine tag based on status code
                status = str(res.get("status_code"))
                tag = ""
                if status.startswith("2"): tag = "stat_2xx"
                elif status.startswith("3"): tag = "stat_3xx"
                elif status.startswith("4"): tag = "stat_4xx"
                elif status.startswith("5") or status == "ERR": tag = "stat_5xx"

                self.racer_results_table.insert("", tk.END, iid=item_iid, values=(
                    req_id if req_id is not None else "?",
                    str(res.get("status_code", "ERR")) + (f" ({res['error_message']})" if res.get("error_message") else ""),
                    res.get("response_length", 0),
                    res.get("execution_time_ms", 0)
                ), tags=(tag,))
                # Store full data for preview
                self.racer_full_data[item_iid] = res
                
                # Update filter dropdown with new status codes
                current_values = list(self.racer_filter_combo['values'])
                new_status = str(res.get("status_code"))
                if new_status not in current_values:
                    current_values.append(new_status)
                    self.racer_filter_combo['values'] = current_values
        except queue.Empty:
            pass

        # Check if finished
        current_count = len(self.racer_results_table.get_children())
        if current_count >= self.racer_count_var.get():
            self.racer_start_btn.config(state="normal", text="START RACE")
            messagebox.showinfo("Race Complete", f"All {current_count} requests finished.")
        else:
            self.root.after(100, self._process_racer_results)

    def apply_racer_filter(self, event=None):
        """Hides race results that don't match the selected status code."""
        selected_status = self.racer_filter_var.get()
        
        # Clear table
        for item in self.racer_results_table.get_children():
            self.racer_results_table.delete(item)
            
        # Re-insert matching items from storage
        for iid, res in self.racer_full_data.items():
            current_status = str(res.get("status_code"))
            if selected_status == "All" or current_status == selected_status:
                tag = ""
                if current_status.startswith("2"): tag = "stat_2xx"
                elif current_status.startswith("3"): tag = "stat_3xx"
                elif current_status.startswith("4"): tag = "stat_4xx"
                elif current_status.startswith("5") or current_status == "ERR": tag = "stat_5xx"

                self.racer_results_table.insert("", tk.END, iid=iid, values=(
                    res.get('request_id', "?"),
                    str(res.get("status_code", "ERR")) + (f" ({res['error_message']})" if res.get("error_message") else ""),
                    res.get("response_length", 0),
                    res.get("execution_time_ms", 0)
                ), tags=(tag,))

    def clear_racer_results(self):
        """Clears all race results and resets the filter."""
        for item in self.racer_results_table.get_children():
            self.racer_results_table.delete(item)
        self.racer_full_data.clear()
        self.racer_filter_combo['values'] = ["All"]
        self.racer_filter_var.set("All")
        self.racer_req_view.delete("1.0", tk.END)
        self.racer_resp_view.delete("1.0", tk.END)

    def _init_crawler_tab(self):
        """Initializes the UI for the Crawler tab."""
        main_pane = ttk.PanedWindow(self.crawler_tab, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Top: Controls
        controls_frame = ttk.LabelFrame(main_pane, text="Crawler Controls")
        main_pane.add(controls_frame, weight=1)

        input_frame = ttk.Frame(controls_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(input_frame, text="Domain / URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.crawler_url_var = tk.StringVar(value="http://example.com")
        self.crawler_url_entry = ttk.Entry(input_frame, textvariable=self.crawler_url_var, width=50)
        self.crawler_url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(input_frame, text="Max Depth:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.crawler_depth_var = tk.IntVar(value=3)
        ttk.Spinbox(input_frame, from_=1, to=10, textvariable=self.crawler_depth_var, width=5).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(input_frame, text="Delay (ms):").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.crawler_delay_var = tk.IntVar(value=100)
        ttk.Spinbox(input_frame, from_=0, to=5000, increment=100, textvariable=self.crawler_delay_var, width=5).grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)

        # Authentication / Headers Frame
        auth_frame = ttk.LabelFrame(controls_frame, text="Custom Headers (for Auth/Cookies)")
        auth_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(auth_frame, text="Enter headers (one per line, e.g., Cookie: session=123):", font=("Helvetica", 8, "italic")).pack(anchor=tk.W, padx=5)
        self.crawler_headers_text = scrolledtext.ScrolledText(auth_frame, height=3, font=("Courier", 9))
        self.crawler_headers_text.pack(fill=tk.X, padx=5, pady=5)

        self.crawler_btn = ttk.Button(controls_frame, text="START ACTIVE CRAWL", command=self.toggle_crawler)
        self.crawler_btn.pack(fill=tk.X, padx=10, pady=2)

        self.wayback_btn = ttk.Button(controls_frame, text="WAYBACK (GHOST) DISCOVERY", command=self.start_wayback_discovery)
        self.wayback_btn.pack(fill=tk.X, padx=10, pady=2)

        # Bottom: Results and Logs
        results_pane = ttk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
        main_pane.add(results_pane, weight=4)

        # Left: Results Table
        results_frame = ttk.LabelFrame(results_pane, text="Discovered URLs with Parameters")
        results_pane.add(results_frame, weight=3)

        self.crawler_results_table = ttk.Treeview(results_frame, columns=("url", "params"), show="headings")
        self.crawler_results_table.heading("url", text="URL")
        self.crawler_results_table.heading("params", text="Parameters")
        self.crawler_results_table.column("url", width=400)
        self.crawler_results_table.column("params", width=200)
        self.crawler_results_table.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.crawler_results_table.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.crawler_results_table.configure(yscroll=scroll.set)

        # Context Menu for Crawler Results
        self.crawler_context_menu = tk.Menu(self.root, tearoff=0)
        self.crawler_context_menu.add_command(label="Copy URL", command=self.copy_crawler_url)
        self.crawler_context_menu.add_command(label="Send to Repeater", command=self.send_crawler_url_to_repeater)
        self.crawler_context_menu.add_command(label="Send to Race Condition", command=self.send_crawler_url_to_racer)
        self.crawler_results_table.bind("<Button-3>", lambda e: self.crawler_context_menu.post(e.x_root, e.y_root))

        # Right: Logs
        log_frame = ttk.LabelFrame(results_pane, text="Crawler Log")
        results_pane.add(log_frame, weight=2)

        self.crawler_log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled', height=10)
        self.crawler_log_text.pack(fill=tk.BOTH, expand=True)

        self.crawler_manager = None

    def toggle_crawler(self):
        """Starts or stops the crawler."""
        if self.crawler_manager and self.crawler_manager.is_running:
            self.crawler_manager.stop()
            self.crawler_btn.config(text="START CRAWL")
        else:
            start_url = self.crawler_url_var.get().strip()
            if not start_url.startswith("http"):
                messagebox.showwarning("Warning", "Please provide a full URL starting with http:// or https://")
                return
            
            # Clear previous results
            for item in self.crawler_results_table.get_children():
                self.crawler_results_table.delete(item)
            self.crawler_log_text.config(state='normal')
            self.crawler_log_text.delete("1.0", tk.END)
            self.crawler_log_text.config(state='disabled')

            domain = urllib.parse.urlparse(start_url).netloc
            
            # Parse custom headers
            custom_headers = {}
            raw_headers = self.crawler_headers_text.get("1.0", tk.END).strip()
            if raw_headers:
                for line in raw_headers.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        custom_headers[k.strip()] = v.strip()
            
            self.crawler_manager = CrawlerManager(
                base_domain=domain,
                scope_rules=self.config["scope_rules"],
                results_callback=lambda data: self.gui_queue.put({"type": "crawler_result", "data": data}),
                log_callback=lambda msg: self.gui_queue.put({"type": "crawler_log", "message": msg}),
                max_depth=self.crawler_depth_var.get(),
                max_threads=5,
                headers=custom_headers,
                proxy_url=f"http://{self.config['host']}:{self.config['port']}", # Point to itself
                delay_ms=self.crawler_delay_var.get() # Pass delay setting
            )
            self.crawler_manager.start(start_url)
            
            # Log confirmation
            num_h = len(custom_headers)
            has_cookie = "Yes" if "Cookie" in custom_headers else "No"
            self.log_to_crawler(f"[INFO] Initializing Crawler with {num_h} custom headers. (Cookie present: {has_cookie})")
            self.log_to_crawler(f"[INFO] Routing crawler traffic through proxy: {self.config['host']}:{self.config['port']}")
            
            self.crawler_btn.config(text="STOP ACTIVE CRAWL")

    def start_wayback_discovery(self):
        """Starts the zero-noise Wayback Machine discovery."""
        start_url = self.crawler_url_var.get().strip()
        if not start_url:
            messagebox.showwarning("Warning", "Please provide a domain or URL.")
            return
        
        domain = urllib.parse.urlparse(start_url).netloc
        if not domain: domain = start_url # Fallback if they just typed the domain

        self.wayback_btn.config(state="disabled", text="FETCHING WAYBACK...")
        self.log_to_crawler(f"[GHOST] Querying Wayback Machine for {domain}...")

        # Run in thread to not block UI
        threading.Thread(target=self._run_wayback_logic, args=(domain,), daemon=True).start()

    def _run_wayback_logic(self, domain):
        try:
            # Query the Wayback CDX API
            # Matches all subdomains (*.domain/*) and filters for 200 OK responses
            api_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            response = requests.get(api_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    # Skip the first item (it's the header ["original"])
                    urls = [item[0] for item in data[1:]]
                    self.gui_queue.put({"type": "wayback_results", "urls": urls})
                else:
                    self.gui_queue.put({"type": "crawler_log", "message": "[GHOST] No historical data found."})
            else:
                self.gui_queue.put({"type": "crawler_log", "message": f"[ERROR] Wayback API returned status {response.status_code}"})
        except Exception as e:
            self.gui_queue.put({"type": "crawler_log", "message": f"[ERROR] Wayback Discovery failed: {e}"})
        finally:
            self.root.after(0, lambda: self.wayback_btn.config(state="normal", text="WAYBACK (GHOST) DISCOVERY"))

    def on_crawler_result(self, data):
        """Handles a result found by the crawler."""
        url = data["url"]
        all_params = data["get_params"] + data["post_params"]
        params_str = ", ".join(all_params)
        
        self.crawler_results_table.insert("", tk.END, values=(url, params_str))
        
        # Also add to Site Map for consistency
        # We don't have a flow ID yet, so we'll use a dummy one or just the URL
        self.add_to_site_map(f"crawl_{url}", {"url": url})

    def log_to_crawler(self, message):
        """Logs a message to the crawler log window."""
        self.crawler_log_text.config(state='normal')
        self.crawler_log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.crawler_log_text.see(tk.END)
        self.crawler_log_text.config(state='disabled')
        
        # If the message indicates the crawl is done, reset the button
        if "Crawl finished" in message:
            self.crawler_btn.config(text="START CRAWL")

    def send_crawler_url_to_repeater(self):
        """Sends selected URL from crawler to Repeater."""
        selected = self.crawler_results_table.selection()
        if not selected: return
        url = self.crawler_results_table.item(selected[0])['values'][0]
        
        # Build a basic GET request
        raw_req = f"GET {url} HTTP/1.1\nHost: {urllib.parse.urlparse(url).netloc}\nConnection: close\n\n"
        self._create_new_repeater_tab(raw_req)
        self.notebook.select(self.repeater_tab)

    def copy_crawler_url(self):
        """Copies the selected URL from the crawler results to the clipboard."""
        selected = self.crawler_results_table.selection()
        if not selected: return
        url = self.crawler_results_table.item(selected[0])['values'][0]
        self.copy_to_clipboard(url)

    def send_crawler_url_to_racer(self):
        """Sends the selected URL from the crawler to the Race Condition tab."""
        selected = self.crawler_results_table.selection()
        if not selected: return
        url = self.crawler_results_table.item(selected[0])['values'][0]
        
        # Build a basic GET request for the racer
        raw_req = f"GET {url} HTTP/1.1\nHost: {urllib.parse.urlparse(url).netloc}\nConnection: close\n\n"
        
        self.racer_raw_req_text.delete("1.0", tk.END)
        self.racer_raw_req_text.insert("1.0", raw_req)
        self.notebook.select(self.racer_tab)

    def analyze_race_results_with_ai(self):
        """Sends the race result patterns to AI to detect exploitation evidence."""
        if not self.ai_enabled:
            messagebox.showwarning("AI Disabled", "Please provide an AI API Key.")
            return

        results = []
        for item in self.racer_results_table.get_children():
            results.append(str(self.racer_results_table.item(item, "values")))

        if not results: return

        results_summary = "\n".join(results)
        prompt = (
            "ROLE: Expert Exploit Developer & Race Condition Specialist.\n"
            "TASK: Analyze these concurrent request results for signs of a successful Race Condition.\n\n"
            "--- RACE RESULTS (Req#, Status, Length, Time) ---\n"
            f"{results_summary}\n\n"
            "--- ANALYSIS RULES ---\n"
            "1. **LIMIT BYPASS**: If ALL requests succeed (200 OK) on an endpoint that should have a limit (e.g. AddToBasket, ClaimReward, Vote), this is a POTENTIAL CRITICAL BUG.\n"
            "2. **PARTIAL BYPASS**: If some requests succeed and some fail (e.g. 10x 200 OK, 40x 403 Forbidden), check if the number of successes exceeds the intended limit (usually 1).\n"
            "3. **INCONSISTENT LENGTHS**: If 200 OK responses have different lengths, the server state was likely changing during the race.\n"
            "4. **VERDICT**: Be aggressive. If the results look like the server failed to lock the resource, flag it as 'VULNERABLE'.\n"
        )

        self.notebook.select(self.ai_tab)
        self.log_to_ai("Analyzing Race Condition results for anomalies...", "System")
        self.ai_history.append({"role": "user", "content": prompt})
        threading.Thread(target=self._perform_ai_query, args=(prompt,), daemon=True).start()

    def send_to_racer_from_history(self):
        """Sends the selected history request to the Race Condition tab."""
        selected = self.history_table.selection()
        if not selected: return
        flow_id = selected[0]
        if flow_id in self.flows:
            req_str = self._get_full_request_str(self.flows[flow_id]["request"])
            self.racer_raw_req_text.delete("1.0", tk.END)
            self.racer_raw_req_text.insert("1.0", req_str)
            self.notebook.select(self.racer_tab)

    def send_to_racer_from_sitemap(self):
        """Sends the selected sitemap request to the Race Condition tab."""
        selected = self.site_map_tree.selection()
        if not selected: return
        node_id = selected[0]
        flow_id = getattr(self, "node_to_flow", {}).get(node_id)
        if flow_id and flow_id in self.flows:
            req_str = self._get_full_request_str(self.flows[flow_id]["request"])
            self.racer_raw_req_text.delete("1.0", tk.END)
            self.racer_raw_req_text.insert("1.0", req_str)
            self.notebook.select(self.racer_tab)






    def _get_full_request_str(self, request_data):
        """Formats request dictionary into a raw string."""
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('headers', [])
        content = request_data.get('content', b'')

        headers_str = "\n".join([f"{k}: {v}" for k, v in headers])
        try:
            body_str = content.decode('utf-8', errors='replace')
        except:
            body_str = str(content)

        return f"{method} {url} HTTP/1.1\n{headers_str}\n\n{body_str}"

    def analyze_history_with_ai(self):
        """Analyzes selected history items with AI."""
        selected_flow_ids = self.history_table.selection()
        if selected_flow_ids:
            self._analyze_flow_ids(selected_flow_ids)
        else:
            messagebox.showinfo("Info", "Please select one or more requests from the history table to analyze.")

    def analyze_site_map_with_ai(self):
        """Analyzes selected site map item with AI."""
        selected = self.site_map_tree.selection()
        if not selected: return
        node_id = selected[0]
        flow_id = getattr(self, "node_to_flow", {}).get(node_id)
        if flow_id:
            self._analyze_flow_ids([flow_id])
        else:
            messagebox.showinfo("Info", "Please select a specific endpoint (leaf node) to analyze.")

    def _analyze_flow_ids(self, flow_ids):
        if not self.ai_enabled:
            messagebox.showwarning("AI Disabled", "Please provide an AI API Key in the Configuration tab.")
            return

        combined_context = []
        for i, fid in enumerate(flow_ids):
            if fid in self.flows:
                f = self.flows[fid]
                req = f.get("request", {})
                resp = f.get("response", {})
                combined_context.append(
                    f"--- Request #{i+1} ---\n"
                    f"URL: {req.get('url')}\n"
                    f"Method: {req.get('method')}\n"
                    f"Body: {str(req.get('content'))[:300]}\n"
                    f"Status: {resp.get('status_code')}\n"
                    f"Resp Body: {str(resp.get('content'))[:400]}"
                )

        if not combined_context: return

        all_data = "\n\n".join(combined_context)
        
        prompt = (
            "Role: Expert Bug Bounty Hunter & Logic Specialist.\n"
            "Task: Analyze this SEQUENCE of requests for Business Logic Flaws and Broken Access Control.\n\n"
            "Focus Areas:\n"
            "1. State Machine/Step Bypass: Can I skip a middle request to reach the goal?\n"
            "2. Parameter Pollution/IDOR: Are IDs (user_id, order_id) consistent? Can they be swapped?\n"
            "3. Privilege Escalation: Does this flow allow a low-privileged user to perform high-privileged actions?\n"
            "4. Race Conditions: Are there endpoints here that handle balances or counts?\n\n"
            f"Traffic Sequence:\n{all_data}\n\n"
            "Provide a concise 'Logic Attack Plan' for this specific flow."
        )
        
        self.notebook.select(self.ai_tab)
        msg = f"Analyzing Logic Flow ({len(flow_ids)} requests)..."
        self.log_to_ai(msg, sender="System")
        
        # Add the FULL prompt to history for chat memory context
        self.ai_history.append({"role": "user", "content": prompt})
        if len(self.ai_history) > 10: self.ai_history.pop(0)

        threading.Thread(target=self._perform_ai_query, args=(prompt,), daemon=True).start()

    def _init_vulnerability_tab(self):
        """Initializes the UI for the Vulnerabilities tab."""
        pane = ttk.PanedWindow(self.vulnerability_tab, orient=tk.VERTICAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # List of Vulnerabilities
        list_frame = ttk.LabelFrame(pane, text="Detected Vulnerabilities")
        pane.add(list_frame, weight=1)

        # Vulnerability Filter Bar
        vuln_filter_frame = ttk.Frame(list_frame)
        vuln_filter_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(vuln_filter_frame, text="Filter Domain:").pack(side=tk.LEFT, padx=(0, 5))
        self.vuln_filter_domain_var = tk.StringVar()
        self.vuln_filter_entry = ttk.Entry(vuln_filter_frame, textvariable=self.vuln_filter_domain_var, width=30)
        self.vuln_filter_entry.pack(side=tk.LEFT, padx=(0, 5))
        self.vuln_filter_entry.bind("<Return>", lambda e: self.apply_vulnerability_filter())

        vuln_filter_button = ttk.Button(vuln_filter_frame, text="Filter", command=self.apply_vulnerability_filter)
        vuln_filter_button.pack(side=tk.LEFT, padx=(0, 2))

        vuln_clear_filter_button = ttk.Button(vuln_filter_frame, text="Clear Filter", command=self.clear_vulnerability_filter)
        vuln_clear_filter_button.pack(side=tk.LEFT, padx=(0, 2))

        self.vuln_table = ttk.Treeview(list_frame, columns=("id", "severity", "title", "type", "url"), show="headings")
        self.vuln_table.heading("id", text="ID")
        self.vuln_table.heading("severity", text="Severity")
        self.vuln_table.heading("title", text="Issue")
        self.vuln_table.heading("type", text="Type")
        self.vuln_table.heading("url", text="URL")

        self.vuln_table.column("id", width=50, anchor=tk.CENTER)
        self.vuln_table.column("severity", width=80, anchor=tk.CENTER)
        self.vuln_table.column("title", width=250)
        self.vuln_table.column("type", width=120)
        self.vuln_table.column("url", width=400)

        # Scrollbar for table
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.vuln_table.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.vuln_table.configure(yscroll=scroll.set)
        self.vuln_table.pack(fill=tk.BOTH, expand=True)

        # Tags for severity coloring
        self.vuln_table.tag_configure("severity_High", foreground="#FF0000", font=("Helvetica", 10, "bold")) # Red
        self.vuln_table.tag_configure("severity_Medium", foreground="#FF8C00", font=("Helvetica", 10, "bold")) # DarkOrange
        self.vuln_table.tag_configure("severity_Low", foreground="#0000FF") # Blue
        self.vuln_table.tag_configure("severity_Info", foreground="#808080") # Gray

        self.vuln_table.bind("<<TreeviewSelect>>", self.on_vuln_select)

        # Details View
        details_frame = ttk.LabelFrame(pane, text="Issue Details")
        pane.add(details_frame, weight=1)

        self.vuln_details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=10, state='disabled')
        self.vuln_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def apply_vulnerability_filter(self):
        """Applies the domain filter to the vulnerability table."""
        self._repopulate_vulnerability_table()

    def clear_vulnerability_filter(self):
        """Clears the domain filter and refreshes the vulnerability table."""
        self.vuln_filter_domain_var.set("")
        self._repopulate_vulnerability_table()

    def _repopulate_vulnerability_table(self):
        """Refreshes the vulnerability Treeview based on the current domain filter."""
        # Clear table
        for item in self.vuln_table.get_children():
            self.vuln_table.delete(item)
        
        filter_domain = self.vuln_filter_domain_var.get().strip().lower()

        # Sort vulnerabilities by ID
        sorted_vulns = sorted(self.vulnerabilities.items(), key=lambda x: int(x[0]))

        for vuln_id, vuln_data in sorted_vulns:
            url = vuln_data.get("url", "").lower()
            
            # Apply Filter
            if filter_domain and filter_domain not in url:
                continue

            severity = vuln_data.get("severity", "Info")
            title = vuln_data.get("title", "Unknown Issue")
            issue_type = vuln_data.get("type", "General")
            
            tag = f"severity_{severity}"
            self.vuln_table.insert("", tk.END, iid=vuln_id, values=(vuln_id, severity, title, issue_type, vuln_data.get("url")), tags=(tag,))

    def add_vulnerability_alert(self, item):
        """Adds findings from the passive security scan to the UI."""
        url = item.get("url", "Unknown")
        issues = item.get("issues", [])
        filter_domain = self.vuln_filter_domain_var.get().strip().lower()
        
        for issue in issues:
            self.vuln_counter += 1
            vuln_id = str(self.vuln_counter)
            
            # Store issue details
            issue_data = issue.copy()
            issue_data["url"] = url
            self.vulnerabilities[vuln_id] = issue_data
            
            # Insert into table if it matches filter
            if not filter_domain or filter_domain in url.lower():
                severity = issue.get("severity", "Info")
                title = issue.get("title", "Unknown Issue")
                issue_type = issue.get("type", "General")
                
                tag = f"severity_{severity}"
                self.vuln_table.insert("", tk.END, iid=vuln_id, values=(vuln_id, severity, title, issue_type, url), tags=(tag,))

    def on_vuln_select(self, event):
        """Displays details of the selected vulnerability."""
        selected = self.vuln_table.selection()
        if not selected:
            return
            
        vuln_id = selected[0]
        if vuln_id in self.vulnerabilities:
            vuln = self.vulnerabilities[vuln_id]
            
            details = f"Issue: {vuln.get('title')}\n"
            details += f"Severity: {vuln.get('severity')}\n"
            details += f"Type: {vuln.get('type')}\n"
            details += f"URL: {vuln.get('url')}\n\n"
            details += f"Description:\n{vuln.get('description')}\n"
            
            if "matches" in vuln:
                details += f"\nFound Matches:\n"
                for match in vuln["matches"]:
                    details += f"- {match}\n"
                    
            self.vuln_details_text.config(state='normal')
            self.vuln_details_text.delete("1.0", tk.END)
            self.vuln_details_text.insert("1.0", details)
            self.vuln_details_text.config(state='disabled')

    def _init_match_replace_log_tab(self):
        """Initializes the UI for the Match & Replace Log tab."""
        # Main Paned Window for Table and Details
        pane = ttk.PanedWindow(self.match_replace_log_tab, orient=tk.VERTICAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Top: Table (Treeview)
        table_frame = ttk.Frame(pane)
        pane.add(table_frame, weight=1)

        self.mr_log_table = ttk.Treeview(
            table_frame,
            columns=("id", "client", "method", "url", "rule", "pattern"),
            show="headings"
        )
        self.mr_log_table.heading("id", text="ID")
        self.mr_log_table.heading("client", text="Client")
        self.mr_log_table.heading("method", text="Method")
        self.mr_log_table.heading("url", text="URL")
        self.mr_log_table.heading("rule", text="Action")
        self.mr_log_table.heading("pattern", text="Match Pattern")

        self.mr_log_table.column("id", width=50, anchor=tk.W)
        self.mr_log_table.column("client", width=120, anchor=tk.W)
        self.mr_log_table.column("method", width=80, anchor=tk.W)
        self.mr_log_table.column("url", width=300, anchor=tk.W)
        self.mr_log_table.column("rule", width=100, anchor=tk.W)
        self.mr_log_table.column("pattern", width=200, anchor=tk.W)
        
        # Hide the 'id' column from view
        self.mr_log_table['displaycolumns'] = ('client', 'method', 'url', 'rule', 'pattern')

        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.mr_log_table.yview)
        self.mr_log_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.mr_log_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.mr_log_table.bind("<<TreeviewSelect>>", self.on_mr_log_select)
        
        # Context Menu for MR Log
        self.mr_log_context_menu = tk.Menu(self.root, tearoff=0)
        self.mr_log_context_menu.add_command(label="Copy URL", command=self.copy_mr_log_url)
        self.mr_log_context_menu.add_command(label="Send Original to Repeater", command=self.send_mr_log_orig_to_repeater)
        self.mr_log_context_menu.add_command(label="Send Modified to Repeater", command=self.send_mr_log_mod_to_repeater)
        self.mr_log_context_menu.add_command(label="Send to Race Condition", command=self.send_mr_log_to_racer)
        self.mr_log_table.bind("<Button-3>", self.show_mr_log_context_menu)

        # Log Controls
        log_controls_frame = ttk.Frame(self.match_replace_log_tab)
        log_controls_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Button(log_controls_frame, text="Send Request (Active Tab)", command=self.send_mr_log_active_request).pack(side=tk.LEFT, padx=2)
        ttk.Button(log_controls_frame, text="Clear Log", command=self.clear_mr_log).pack(side=tk.RIGHT, padx=2)

        # Bottom: Details (Original, Modified, Response)
        details_frame = ttk.Frame(pane)
        pane.add(details_frame, weight=1)

        self.mr_log_details_notebook = ttk.Notebook(details_frame)
        self.mr_log_details_notebook.pack(fill=tk.BOTH, expand=True)

        self.mr_log_orig_text = scrolledtext.ScrolledText(self.mr_log_details_notebook, wrap=tk.WORD, height=10)
        self.mr_log_mod_text = scrolledtext.ScrolledText(self.mr_log_details_notebook, wrap=tk.WORD, height=10)
        self.mr_log_resp_text = scrolledtext.ScrolledText(self.mr_log_details_notebook, wrap=tk.WORD, height=10)

        self.mr_log_details_notebook.add(self.mr_log_orig_text, text="Original Request")
        self.mr_log_details_notebook.add(self.mr_log_mod_text, text="Modified Request")
        self.mr_log_details_notebook.add(self.mr_log_resp_text, text="Response")
        
        # Tags for highlighting replacements
        self.mr_log_mod_text.tag_configure("replacement", background="#90EE90", foreground="black", font=("Courier", 10, "bold")) # Light green

    def on_mr_log_select(self, event):
        """Displays request/response details when a node in the MR log is selected."""
        selected_items = self.mr_log_table.selection()
        if not selected_items:
            return
        
        flow_id = selected_items[0]
        self.mr_log_orig_text.delete("1.0", tk.END)
        self.mr_log_mod_text.delete("1.0", tk.END)
        self.mr_log_resp_text.delete("1.0", tk.END)

        if flow_id and flow_id in self.match_replace_flows:
            flow_data = self.match_replace_flows[flow_id]
            
            # Populate Original Request
            orig = flow_data.get("original")
            if not orig: return
            
            orig_headers = "\n".join([f"{k}: {v}" for k, v in orig.get("headers", [])])
            orig_full = f"{orig.get('method')} {orig.get('url')} HTTP/1.1\n{orig_headers}\n\n{orig.get('content')}"
            self.safe_insert_text(self.mr_log_orig_text, orig_full)
            
            # Generate Preview for Modified Request (especially important for 'Test Only' mode)
            applied_rules = flow_data.get("applied_rules", [])
            
            mod_method = orig.get('method')
            mod_url = orig.get('url')
            mod_headers = list(orig.get('headers', []))
            mod_content = orig.get('content', "")

            for rule in applied_rules:
                match_pat = rule["match"]
                repl = rule["replace"]
                target = rule["type"]
                
                # Apply same logic as proxy to create a preview
                if target == "URL" or target == "All":
                    mod_url = re.sub(match_pat, repl, mod_url)
                
                if target == "Request Body" or target == "All":
                    mod_content = re.sub(match_pat, repl, mod_content)
                
                if target == "Request Header" or target == "All":
                    new_headers = []
                    for h_name, h_val in mod_headers:
                        if ":" in match_pat:
                            h_n_p, h_v_p = match_pat.split(":", 1)
                            if re.search(h_n_p.strip(), h_name, re.I):
                                h_val = re.sub(h_v_p.strip(), repl, h_val)
                        elif re.search(match_pat, h_val):
                             h_val = re.sub(match_pat, repl, h_val)
                        new_headers.append((h_name, h_val))
                    mod_headers = new_headers

            headers_str = "\n".join([f"{k}: {v}" for k, v in mod_headers])
            mod_full = f"{mod_method} {mod_url} HTTP/1.1\n{headers_str}\n\n{mod_content}"
            self.safe_insert_text(self.mr_log_mod_text, mod_full)
            
            # Highlight replacements
            for rule in applied_rules:
                replace_val = rule["replace"]
                if not replace_val: continue
                
                start_pos = "1.0"
                while True:
                    start_pos = self.mr_log_mod_text.search(replace_val, start_pos, stopindex=tk.END)
                    if not start_pos: break
                    end_pos = f"{start_pos}+{len(replace_val)}c"
                    self.mr_log_mod_text.tag_add("replacement", start_pos, end_pos)
                    start_pos = end_pos

            # Populate Response
            resp = flow_data.get("response")
            if resp:
                resp_headers = "\n".join([f"{k}: {v}" for k, v in resp.get("headers", [])])
                try:
                    resp_body = resp.get("content", b"").decode('utf-8', errors='replace')
                except:
                    resp_body = str(resp.get("content", b""))
                
                status_line = f"HTTP/1.1 {resp.get('status_code')}" # Simplified
                resp_full = f"{status_line}\n{resp_headers}\n\n{resp_body}"
                self.safe_insert_text(self.mr_log_resp_text, resp_full)
            else:
                self.mr_log_resp_text.insert("1.0", "(No response yet)")

    def add_flow_to_mr_log(self, item):
        flow_id = item["flow_id"]
        data = item["data"]
        applied_rules = item.get("applied_rules", [])
        client = item.get("client", "Unknown")
        
        # Store for details
        full_flow = item.get("full_flow", {})
        # Enrich the stored flow with original data for highlighting/comparison
        full_flow["original"] = item.get("original_request")
        full_flow["applied_rules"] = applied_rules
        
        self.match_replace_flows[flow_id] = full_flow

        # Use the first applied rule for the summary columns
        main_rule = applied_rules[0] if applied_rules else {"action": "None", "match": "None"}
        action_str = main_rule.get("action", "Replace")
        match_str = main_rule.get("match", "")

        self.mr_log_table.insert(
            "", tk.END, iid=flow_id,
            values=(flow_id, client, data["method"], data["url"], action_str, match_str)
        )
        self.mr_log_table.yview_moveto(1) # Auto-scroll

    def show_mr_log_context_menu(self, event):
        selection = self.mr_log_table.identify_row(event.y)
        if selection:
            self.mr_log_table.selection_set(selection)
            self.mr_log_context_menu.post(event.x_root, event.y_root)

    def clear_mr_log(self):
        for item in self.mr_log_table.get_children():
            self.mr_log_table.delete(item)
        self.match_replace_flows.clear()
        self.mr_log_orig_text.delete("1.0", tk.END)
        self.mr_log_mod_text.delete("1.0", tk.END)
        self.mr_log_resp_text.delete("1.0", tk.END)

    def copy_mr_log_url(self):
        selected = self.mr_log_table.selection()
        if not selected: return
        flow_id = selected[0]
        if flow_id in self.match_replace_flows:
            url = self.match_replace_flows[flow_id]["request"]["url"]
            self.copy_to_clipboard(url)

    def send_mr_log_active_request(self):
        """Sends the request from the currently visible detail tab in the MR log."""
        active_index = self.mr_log_details_notebook.index("current")
        
        # 0 is Original, 1 is Modified
        if active_index == 0:
            raw_request = self.mr_log_orig_text.get("1.0", tk.END).strip()
        elif active_index == 1:
            raw_request = self.mr_log_mod_text.get("1.0", tk.END).strip()
        else:
            messagebox.showinfo("Info", "Please select either the Original or Modified Request tab to send.")
            return

        if not raw_request:
            return

        # Switch to Response tab to show progress
        self.mr_log_details_notebook.select(2)
        self.mr_log_resp_text.config(state='normal')
        self.mr_log_resp_text.delete("1.0", tk.END)
        self.mr_log_resp_text.insert("1.0", "Sending request...")
        self.mr_log_resp_text.config(state='disabled')

        def _perform_send():
            try:
                method, url, headers, body = self._parse_raw_request(raw_request)
                
                # Add identification header
                headers.append(('X-Proxy-Tool-Internal', 'mr-log-manual-test'))

                start_time = time.perf_counter()
                
                # Use requests to send
                # requests.request handles headers as a dict or list of tuples
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=dict(headers), # Convert to dict for requests library
                    data=body.encode('utf-8') if body else None,
                    verify=False,
                    allow_redirects=False,
                    timeout=30
                )
                
                end_time = time.perf_counter()
                elapsed = int((end_time - start_time) * 1000)

                # Format response
                status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}"
                resp_headers = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
                
                # Try to decode body
                try:
                    resp_body = resp.text
                except:
                    resp_body = str(resp.content)

                resp_full = f"{status_line}\n{resp_headers}\n\n{resp_body}"

                # Update UI
                self.root.after(0, lambda: self.safe_insert_text(self.mr_log_resp_text, resp_full))
                # Optional: Update status or time?
            except Exception as e:
                self.root.after(0, lambda: self.safe_insert_text(self.mr_log_resp_text, f"Error sending request: {e}"))

        threading.Thread(target=_perform_send, daemon=True).start()

    def _parse_raw_request(self, raw_request: str):
        """Robustly parses a raw HTTP request string into parts."""
        # Split head and body
        if "\n\n" in raw_request:
            head, body = raw_request.split("\n\n", 1)
        elif "\r\n\r\n" in raw_request:
            head, body = raw_request.split("\r\n\r\n", 1)
        else:
            head = raw_request
            body = ""
        
        lines = head.split("\n")
        request_line = lines[0].strip()
        
        parts = request_line.split(" ")
        if len(parts) < 2:
            raise ValueError("Malformed request line")
        
        method = parts[0]
        url = parts[1]
        
        headers = []
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers.append((k.strip(), v.strip()))
        
        # If URL is just a path, reconstruct from Host header
        if not url.startswith("http"):
            host = None
            for k, v in headers:
                if k.lower() == "host":
                    host = v
                    break
            if host:
                scheme = "https" if ":443" in host else "http"
                url = f"{scheme}://{host}{url}"
        
        return method, url, headers, body

    def send_mr_log_orig_to_repeater(self):
        # Kept for context menu but we could also replace it there
        pass

    def send_mr_log_mod_to_repeater(self):
        # Kept for context menu
        pass

    def send_mr_log_to_racer(self):
        selected = self.mr_log_table.selection()
        if not selected: return
        flow_id = selected[0]
        if flow_id in self.match_replace_flows:
            flow = self.match_replace_flows[flow_id]
            req = flow["request"]
            headers_str = "\n".join([f"{k}: {v}" for k, v in req["headers"]])
            full_request = f"{req['method']} {req['url']} HTTP/1.1\n{headers_str}\n\n{req['content']}"
            self.racer_raw_req_text.delete("1.0", tk.END)
            self.racer_raw_req_text.insert("1.0", full_request)
            self.notebook.select(self.racer_tab)

    def shutdown(self):
        """Cleanly stop the proxy and destroy the window."""
        self.proxy_manager.stop()
        self.root.destroy()
        os._exit(0)

    def _init_intruder_tab(self):
        """Initializes the UI for the Intruder tab."""
        self.intruder_notebook = ttk.Notebook(self.intruder_tab)
        self.intruder_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.intruder_pos_tab = ttk.Frame(self.intruder_notebook)
        self.intruder_payload_tab = ttk.Frame(self.intruder_notebook)
        self.intruder_results_tab = ttk.Frame(self.intruder_notebook)

        self.intruder_notebook.add(self.intruder_pos_tab, text="Positions")
        self.intruder_notebook.add(self.intruder_payload_tab, text="Payloads")
        self.intruder_notebook.add(self.intruder_results_tab, text="Results")

        # --- Positions Sub-Tab ---
        pos_main_frame = ttk.Frame(self.intruder_pos_tab)
        pos_main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        pos_controls = ttk.Frame(pos_main_frame)
        pos_controls.pack(side=tk.RIGHT, fill=tk.Y, padx=5)

        ttk.Button(pos_controls, text="Add §", command=self.intruder_add_marker).pack(fill=tk.X, pady=2)
        ttk.Button(pos_controls, text="Clear §", command=self.intruder_clear_markers).pack(fill=tk.X, pady=2)
        ttk.Button(pos_controls, text="Auto §", command=self.intruder_auto_markers).pack(fill=tk.X, pady=2)
        
        ttk.Label(pos_controls, text="Attack Type:").pack(pady=(10, 0))
        self.intruder_attack_type = tk.StringVar(value="Sniper")
        ttk.Combobox(pos_controls, textvariable=self.intruder_attack_type, values=["Sniper", "Battering Ram"], state="readonly", width=12).pack(pady=2)

        self.intruder_start_btn = ttk.Button(pos_controls, text="START ATTACK", command=self.start_intruder_attack, style="Accent.TButton")
        self.intruder_start_btn.pack(side=tk.BOTTOM, fill=tk.X, pady=10)

        self.intruder_req_text = scrolledtext.ScrolledText(pos_main_frame, wrap=tk.NONE, font=("Courier", 10))
        self.intruder_req_text.pack(fill=tk.BOTH, expand=True)
        self.intruder_req_text.tag_configure("marker", background="yellow", foreground="black")
        self.intruder_req_text.bind("<KeyRelease>", lambda e: self._on_intruder_key())

        # --- Payloads Sub-Tab ---
        pay_frame = ttk.Frame(self.intruder_payload_tab)
        pay_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Payload Type Selection
        pay_type_frame = ttk.Frame(pay_frame)
        pay_type_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(pay_type_frame, text="Payload Type:").pack(side=tk.LEFT)
        self.intruder_payload_type = tk.StringVar(value="Simple List")
        self.pay_type_combo = ttk.Combobox(pay_type_frame, textvariable=self.intruder_payload_type, values=["Simple List", "Numbers"], state="readonly", width=15)
        self.pay_type_combo.pack(side=tk.LEFT, padx=5)
        self.intruder_payload_type.trace_add("write", self._on_intruder_payload_type_change)

        # Container for dynamic payload settings
        self.pay_settings_container = ttk.Frame(pay_frame)
        self.pay_settings_container.pack(fill=tk.BOTH, expand=True)

        # 1. Simple List UI (default)
        self.simple_list_frame = ttk.Frame(self.pay_settings_container)
        self.simple_list_frame.pack(fill=tk.BOTH, expand=True)
        
        pay_header = ttk.Frame(self.simple_list_frame)
        pay_header.pack(fill=tk.X)
        ttk.Label(pay_header, text="Payload Options [Simple List]").pack(side=tk.LEFT)
        ttk.Button(pay_header, text="Load from File", command=self.intruder_load_payloads_file).pack(side=tk.RIGHT)
        
        self.intruder_payload_list_text = scrolledtext.ScrolledText(self.simple_list_frame, height=15)
        self.intruder_payload_list_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # 2. Numbers UI (hidden by default)
        self.numbers_frame = ttk.Frame(self.pay_settings_container)
        
        num_grid = ttk.Frame(self.numbers_frame)
        num_grid.pack(pady=20)
        
        ttk.Label(num_grid, text="From:").grid(row=0, column=0, padx=5, pady=5)
        self.intruder_num_from = tk.IntVar(value=1)
        ttk.Entry(num_grid, textvariable=self.intruder_num_from, width=15).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(num_grid, text="To:").grid(row=1, column=0, padx=5, pady=5)
        self.intruder_num_to = tk.IntVar(value=1000)
        ttk.Entry(num_grid, textvariable=self.intruder_num_to, width=15).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(num_grid, text="Step:").grid(row=2, column=0, padx=5, pady=5)
        self.intruder_num_step = tk.IntVar(value=1)
        ttk.Entry(num_grid, textvariable=self.intruder_num_step, width=15).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(num_grid, text="Min Digits:").grid(row=3, column=0, padx=5, pady=5)
        self.intruder_num_digits = tk.IntVar(value=1)
        ttk.Entry(num_grid, textvariable=self.intruder_num_digits, width=15).grid(row=3, column=1, padx=5, pady=5)

        # --- Results Sub-Tab ---
        # Main results container
        res_main_container = ttk.Frame(self.intruder_results_tab)
        res_main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Results Filter Bar (PACKED FIRST to be at the TOP)
        filter_frame = ttk.Frame(res_main_container)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(filter_frame, text="Filter Status:").pack(side=tk.LEFT, padx=2)
        self.intruder_filter_status = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.intruder_filter_status, width=8).pack(side=tk.LEFT, padx=2)

        ttk.Label(filter_frame, text="Hide Length:").pack(side=tk.LEFT, padx=5)
        self.intruder_filter_length = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.intruder_filter_length, width=8).pack(side=tk.LEFT, padx=2)

        ttk.Button(filter_frame, text="Filter", command=self.apply_intruder_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_intruder_filter).pack(side=tk.LEFT, padx=2)

        # Stop Attack Button in Results Tab
        self.intruder_res_stop_btn = ttk.Button(filter_frame, text="STOP ATTACK", command=self.stop_intruder_attack, state="disabled")
        self.intruder_res_stop_btn.pack(side=tk.LEFT, padx=10)

        # Add a Clear Results button
        ttk.Button(filter_frame, text="Clear All Results", command=self.clear_intruder_results).pack(side=tk.RIGHT, padx=5)
        res_pane = ttk.PanedWindow(res_main_container, orient=tk.VERTICAL)
        res_pane.pack(fill=tk.BOTH, expand=True)

        # Top half: Table
        res_table_frame = ttk.Frame(res_pane)
        res_pane.add(res_table_frame, weight=1)

        self.intruder_res_table = ttk.Treeview(res_table_frame, columns=("id", "payload", "status", "length", "time"), show="headings")
        self.intruder_res_table.heading("id", text="ID")
        self.intruder_res_table.heading("payload", text="Payload")
        self.intruder_res_table.heading("status", text="Status")
        self.intruder_res_table.heading("length", text="Length")
        self.intruder_res_table.heading("time", text="Time (ms)")

        self.intruder_res_table.column("id", width=50)
        self.intruder_res_table.column("payload", width=150)
        self.intruder_res_table.column("status", width=80)
        self.intruder_res_table.column("length", width=80)
        self.intruder_res_table.column("time", width=80)

        # Add Vertical Scrollbar to Results Table
        res_scrollbar = ttk.Scrollbar(res_table_frame, orient=tk.VERTICAL, command=self.intruder_res_table.yview)
        self.intruder_res_table.configure(yscroll=res_scrollbar.set)
        res_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.intruder_res_table.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        self.intruder_res_table.bind("<<TreeviewSelect>>", self.on_intruder_result_select)

        # Configure Status Tags for Intruder
        self.intruder_res_table.tag_configure("stat_2xx", foreground="#008000") # Green
        self.intruder_res_table.tag_configure("stat_3xx", foreground="#cc7a00") # Orange
        self.intruder_res_table.tag_configure("stat_4xx", foreground="#ff0000") # Red
        self.intruder_res_table.tag_configure("stat_5xx", foreground="#800080") # Purple

        # Bottom half: Preview with Search
        preview_container = ttk.Frame(res_pane)
        res_pane.add(preview_container, weight=1)

        intruder_search_frame = ttk.Frame(preview_container)
        intruder_search_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(intruder_search_frame, text="Search Results:").pack(side=tk.LEFT)
        self.intruder_search_var = tk.StringVar()
        self.intruder_search_entry = ttk.Entry(intruder_search_frame, textvariable=self.intruder_search_var, width=30)
        self.intruder_search_entry.pack(side=tk.LEFT, padx=5)
        self.intruder_search_entry.bind("<Return>", lambda e: self.search_intruder_response())

        res_preview_frame = ttk.Notebook(preview_container)
        res_preview_frame.pack(fill=tk.BOTH, expand=True)

        self.intruder_res_req_view = scrolledtext.ScrolledText(res_preview_frame, wrap=tk.WORD)
        self.intruder_res_resp_view = scrolledtext.ScrolledText(res_preview_frame, wrap=tk.WORD)
        res_preview_frame.add(self.intruder_res_req_view, text="Request")
        res_preview_frame.add(self.intruder_res_resp_view, text="Response")
        
        self.intruder_res_resp_view.tag_configure("search_match", background="yellow", foreground="black")

        self.intruder_attack_running = False
        self.intruder_full_results = {}

    def _on_intruder_payload_type_change(self, *args):
        """Switches between Simple List and Numbers UI in Intruder."""
        ptype = self.intruder_payload_type.get()
        if ptype == "Simple List":
            self.numbers_frame.pack_forget()
            self.simple_list_frame.pack(fill=tk.BOTH, expand=True)
        else:
            self.simple_list_frame.pack_forget()
            self.numbers_frame.pack(fill=tk.BOTH, expand=True)

    def search_intruder_response(self):
        """Highlights matches in the currently viewed intruder response."""
        keyword = self.intruder_search_var.get()
        self.intruder_res_resp_view.tag_remove("search_match", "1.0", tk.END)
        if not keyword: return
        
        start = "1.0"
        while True:
            start = self.intruder_res_resp_view.search(keyword, start, stopindex=tk.END, nocase=True)
            if not start: break
            end = f"{start}+{len(keyword)}c"
            self.intruder_res_resp_view.tag_add("search_match", start, end)
            start = end

    def _on_intruder_key(self):
        """Combines HTTP syntax highlighting with intruder marker coloring."""
        # 1. Clear tags
        tags_to_clear = [
            "http_method", "http_path", "http_version", "http_header_key", "http_header_val", 
            "http_body", "html_tag", "html_attr", "html_str", "html_comm", "marker"
        ]
        for tag in tags_to_clear:
            self.intruder_req_text.tag_remove(tag, "1.0", tk.END)
        
        # 2. Apply HTTP logic
        self._highlight_http_text(self.intruder_req_text)
        
        # 3. Apply Marker logic
        self.intruder_highlight_markers()

    def intruder_highlight_markers(self, event=None):
        """Colors the text between § markers for better visibility."""
        self.intruder_req_text.tag_remove("marker", "1.0", tk.END)
        content = self.intruder_req_text.get("1.0", tk.END)
        
        # Find all occurrences of §something§
        # We look for pairs of §
        start = "1.0"
        while True:
            first_marker = self.intruder_req_text.search("§", start, stopindex=tk.END)
            if not first_marker: break
            
            second_marker = self.intruder_req_text.search("§", f"{first_marker}+1c", stopindex=tk.END)
            if not second_marker: break
            
            end_pos = f"{second_marker}+1c"
            self.intruder_req_text.tag_add("marker", first_marker, end_pos)
            start = end_pos

    def intruder_add_marker(self):
        """Adds § markers around the current selection."""
        try:
            sel_start = self.intruder_req_text.index(tk.SEL_FIRST)
            sel_end = self.intruder_req_text.index(tk.SEL_LAST)
            content = self.intruder_req_text.get(sel_start, sel_end)
            self.intruder_req_text.delete(sel_start, sel_end)
            self.intruder_req_text.insert(sel_start, f"§{content}§")
            self.intruder_highlight_markers()
        except tk.TclError:
            pass

    def intruder_clear_markers(self):
        """Removes all § markers from the request."""
        content = self.intruder_req_text.get("1.0", tk.END)
        content = content.replace("§", "")
        self.intruder_req_text.delete("1.0", tk.END)
        self.intruder_req_text.insert("1.0", content)
        self.intruder_highlight_markers()

    def intruder_auto_markers(self):
        """Automatically places markers around parameter values."""
        content = self.intruder_req_text.get("1.0", tk.END)
        new_content = re.sub(r'(=|: )([^&\s\n\r]+)', r'\1§\2§', content)
        self.intruder_req_text.delete("1.0", tk.END)
        self.intruder_req_text.insert("1.0", new_content)
        self.intruder_highlight_markers()

    def intruder_load_payloads_file(self):
        """Loads payloads from a selected text file."""
        file_path = filedialog.askopenfilename(
            title="Select Payload File",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    self.intruder_payload_list_text.delete("1.0", tk.END)
                    self.intruder_payload_list_text.insert("1.0", content)
                messagebox.showinfo("Success", f"Loaded payloads from {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def stop_intruder_attack(self):
        """Stops the currently running intruder attack."""
        if self.intruder_attack_running:
            self.intruder_attack_running = False
            self.intruder_start_btn.config(text="START ATTACK")
            self.intruder_res_stop_btn.config(state="disabled")

    def start_intruder_attack(self):
        """Executes the Intruder attack."""
        if self.intruder_attack_running:
            self.stop_intruder_attack()
            return

        raw_req = self.intruder_req_text.get("1.0", tk.END).strip()

        # Determine payloads based on type
        if self.intruder_payload_type.get() == "Simple List":
            payloads = self.intruder_payload_list_text.get("1.0", tk.END).strip().splitlines()
        else:
            # Generate Numbers range
            try:
                start_n = self.intruder_num_from.get()
                end_n = self.intruder_num_to.get()
                step_n = self.intruder_num_step.get()
                min_digits = self.intruder_num_digits.get()
                if step_n <= 0: raise ValueError

                # Use f-string formatting to preserve padding (e.g., 000001)
                format_str = f"{{:0{min_digits}d}}"
                payloads = [format_str.format(n) for n in range(start_n, end_n + 1, step_n)]
            except Exception:
                messagebox.showerror("Error", "Invalid Number range settings.")
                return

        if "§" not in raw_req:
            messagebox.showwarning("Warning", "No payload positions defined. Use § to mark positions.")
            return
        if not payloads:
            messagebox.showwarning("Warning", "No payloads defined.")
            return

        # Setup Results
        for item in self.intruder_res_table.get_children():
            self.intruder_res_table.delete(item)
        self.intruder_full_results = {}
        self.intruder_notebook.select(self.intruder_results_tab)

        self.intruder_attack_running = True
        self.intruder_start_btn.config(text="STOP ATTACK")
        self.intruder_res_stop_btn.config(state="normal")

        threading.Thread(target=self._run_intruder_attack, args=(raw_req, payloads), daemon=True).start()

    def _run_intruder_attack(self, template, payloads):
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        # Pre-parse template: split by §
        parts = template.split("§")
        # Every odd index is a payload position: parts[0] PAYLOAD parts[2] ...

        for i, payload in enumerate(payloads):
            if not self.intruder_attack_running: break

            # Reconstruct request with payload
            # Sniper mode: replaces all §...§ with the same payload for now
            # (In a real Sniper, it iterates positions one by one, but let's start with Battering Ram style)
            final_req = ""
            for idx, part in enumerate(parts):
                if idx % 2 == 1:
                    final_req += payload
                else:
                    final_req += part

            try:
                method, url, headers, body = self._parse_raw_request(final_req)

                start_time = time.perf_counter()
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=dict(headers),
                    data=body.encode('utf-8') if body else None,
                    verify=False,
                    timeout=10,
                    allow_redirects=False
                )
                elapsed = int((time.perf_counter() - start_time) * 1000)

                # Format results
                res_data = {
                    "id": i + 1,
                    "payload": payload,
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "time": elapsed,
                    "raw_req": final_req,
                    "raw_resp": f"HTTP/1.1 {resp.status_code}\n" + "\n".join([f"{k}: {v}" for k, v in resp.headers.items()]) + "\n\n" + resp.text
                }

                self.gui_queue.put({"type": "intruder_result", "data": res_data})

            except Exception as e:
                self.gui_queue.put({"type": "intruder_result", "data": {
                    "id": i+1, "payload": payload, "status": "ERR", "length": 0, "time": 0, "raw_req": final_req, "raw_resp": str(e)
                }})

        # Final UI update after loop finishes or is stopped
        self.root.after(0, lambda: self.intruder_start_btn.config(text="START ATTACK"))
        self.root.after(0, lambda: self.intruder_res_stop_btn.config(state="disabled"))
        self.intruder_attack_running = False
    def on_intruder_result_select(self, event):
        selected = self.intruder_res_table.selection()
        if not selected: return
        res_id = selected[0]
        data = self.intruder_full_results.get(res_id)
        if data:
            self.safe_insert_text(self.intruder_res_req_view, data["raw_req"])
            self.safe_insert_text(self.intruder_res_resp_view, data["raw_resp"])

    def apply_intruder_filter(self):
        """Hides results from the table that don't match the filter."""
        status_to_show = self.intruder_filter_status.get().strip()
        length_to_hide = self.intruder_filter_length.get().strip()
        
        # We need to repopulate the table based on self.intruder_full_results
        # because Treeview doesn't have a simple 'hide' per row
        for item in self.intruder_res_table.get_children():
            self.intruder_res_table.delete(item)
            
        for iid, data in self.intruder_full_results.items():
            # Check Status Filter (e.g., "200")
            if status_to_show and str(data["status"]) != status_to_show:
                continue
            
            # Check Length Filter (e.g., hide "540")
            if length_to_hide and str(data["length"]) == length_to_hide:
                continue
            
            # Determine tag based on status code
            status = str(data["status"])
            tag = ""
            if status.startswith("2"): tag = "stat_2xx"
            elif status.startswith("3"): tag = "stat_3xx"
            elif status.startswith("4"): tag = "stat_4xx"
            elif status.startswith("5") or status == "ERR": tag = "stat_5xx"

            self.intruder_res_table.insert("", tk.END, iid=iid, values=(
                data["id"], data["payload"], data["status"], data["length"], data["time"]
            ), tags=(tag,))

    def clear_intruder_filter(self):
        """Resets the filters and shows all results."""
        self.intruder_filter_status.set("")
        self.intruder_filter_length.set("")
        self.apply_intruder_filter()

    def clear_intruder_results(self):
        """Clears all data and entries from the intruder results."""
        for item in self.intruder_res_table.get_children():
            self.intruder_res_table.delete(item)
        self.intruder_full_results.clear()
        self.intruder_res_req_view.delete("1.0", tk.END)
        self.intruder_res_resp_view.delete("1.0", tk.END)

    def _init_decoder_tab(self):
        decoder_notebook = ttk.Notebook(self.decoder_tab)
        decoder_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        jwt_tab = ttk.Frame(decoder_notebook)
        base64_tab = ttk.Frame(decoder_notebook)
        url_tab = ttk.Frame(decoder_notebook) # New URL tab
        ai_dec_tab = ttk.Frame(decoder_notebook) # Magical AI Decoder Tab

        decoder_notebook.add(jwt_tab, text="JWT")
        decoder_notebook.add(base64_tab, text="Base64")
        decoder_notebook.add(url_tab, text="URL") # Add URL tab
        decoder_notebook.add(ai_dec_tab, text="✨ AI Decoder") 

        self._init_jwt_ui(jwt_tab)
        self._init_base64_ui(base64_tab)
        self._init_url_ui(url_tab) # Initialize URL UI
        self._init_ai_decoder_ui(ai_dec_tab)

    def _init_ai_decoder_ui(self, parent_tab):
        """Initializes the Magical AI Decoder UI."""
        main_pane = ttk.PanedWindow(parent_tab, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Input
        input_frame = ttk.Labelframe(main_pane, text="Input (Paste anything mysterious here)")
        main_pane.add(input_frame, weight=1)
        self.ai_dec_input = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=8)
        self.ai_dec_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Controls
        controls = ttk.Frame(main_pane)
        main_pane.add(controls, weight=0)
        
        decode_btn = ttk.Button(controls, text="Magic Decode ✨", command=self.decode_with_ai)
        decode_btn.pack(fill=tk.X, pady=5)

        self.ai_dec_status_var = tk.StringVar(value="Ready")
        ttk.Label(controls, textvariable=self.ai_dec_status_var, font=("Helvetica", 9, "italic")).pack()

        # Output
        output_frame = ttk.Labelframe(main_pane, text="AI Analysis & Decoded Result")
        main_pane.add(output_frame, weight=2)
        self.ai_dec_output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, bg="#f8f9fa")
        self.ai_dec_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def decode_with_ai(self):
        """Uses a Hybrid Python + AI approach for maximum accuracy."""
        if not self.ai_enabled:
            messagebox.showwarning("AI Disabled", "Please provide an AI API Key in Configuration.")
            return

        raw_input = self.ai_dec_input.get("1.0", tk.END).strip()
        if not raw_input:
            return

        self.ai_dec_status_var.set("Magic in progress... Running Forensic Engine...")
        self.ai_dec_output.delete("1.0", tk.END)

        def _recursive_decode(data):
            """Deep-Recursive Forensic Engine with JSON and Dirty-Hex awareness."""
            import string
            steps = []
            current = data
            
            def is_printable(s):
                if not s or len(s) < 3: return False
                printable = set(string.printable)
                return all(c in printable for c in s)

            def peel(target):
                nonlocal steps
                peeled_current = target
                inner_changed = False
                
                # 1. URL Decode
                unquoted = urllib.parse.unquote(peeled_current)
                if unquoted != peeled_current:
                    peeled_current = unquoted
                    steps.append("URL")
                    inner_changed = True
                
                # 2. Hex Decode (Strict & Dirty)
                try:
                    # Dirty Hex: Strip common separators including % used in escaped hex
                    h_clean = peeled_current.replace("%", "").replace(" ", "").replace(":", "").strip()
                    if len(h_clean) >= 4 and len(h_clean) % 2 == 0 and all(c in string.hexdigits for c in h_clean):
                        decoded = bytes.fromhex(h_clean).decode('utf-8')
                        if is_printable(decoded):
                            peeled_current = decoded
                            steps.append("Hex")
                            inner_changed = True
                except: pass

                # 3. Base64 Decode
                try:
                    b64_clean = peeled_current.strip().replace("\n", "").replace("\r", "")
                    # Try normal and reversed
                    for b_cand in [b64_clean, b64_clean[::-1]]:
                        padded = b_cand + "=" * (-len(b_cand) % 4)
                        decoded = base64.b64decode(padded).decode('utf-8')
                        if is_printable(decoded) and len(decoded) > 3:
                            peeled_current = decoded
                            steps.append("Base64" + (" (Rev)" if b_cand != b64_clean else ""))
                            inner_changed = True
                            break
                except: pass

                # 4. JSON Deep-Dive (Peel inside arrays/objects)
                try:
                    js_data = json.loads(peeled_current)
                    if isinstance(js_data, (dict, list)):
                        def walk_and_peel(obj):
                            if isinstance(obj, dict):
                                return {k: walk_and_peel(v) for k, v in obj.items()}
                            elif isinstance(obj, list):
                                return [walk_and_peel(i) for i in obj]
                            elif isinstance(obj, str) and len(obj) > 4:
                                sub_peel, sub_steps = _recursive_decode(obj)
                                if sub_steps: 
                                    steps.extend([f"Inner({s})" for s in sub_steps])
                                return sub_peel
                            return obj
                        
                        peeled_current = json.dumps(walk_and_peel(js_data), indent=2)
                        steps.append("JSON Deep-Peel")
                        inner_changed = True
                except: pass

                return peeled_current, inner_changed

            # Run peeling recursively up to 15 layers
            for _ in range(15):
                current, changed = peel(current)
                if not changed: break
                
            return current, steps




        def _run():
            try:
                # Step 1: Accurate Python Decoding
                decoded_text, layers = _recursive_decode(raw_input)
                
                # Step 2: Use AI to analyze the result
                prompt = (
                    "ROLE: Expert Security Researcher.\n"
                    "TASK: I have accurately decoded an input using a Python engine. Analyze the result.\n\n"
                    f"ORIGINAL INPUT: {raw_input}\n"
                    f"PYTHON DECODED RESULT: {decoded_text}\n"
                    f"LAYERS FOUND BY ENGINE: {' -> '.join(layers) if layers else 'None'}\n\n"
                    "INSTRUCTIONS:\n"
                    "1. If the result is code (JS/Python), de-obfuscate it and explain its purpose.\n"
                    "2. If it is JSON, format it beautifully.\n"
                    "3. If it contains sensitive info (keys, passwords), highlight them.\n"
                    "4. If the result still looks slightly encoded (e.g. ROT13), finish the decoding.\n"
                )

                provider = self.config.get("ai_provider", "Gemini")
                api_key = self.config.get("gemini_api_key")
                model_name = self.config.get("ai_model_name", "gemini-2.0-flash")

                if provider == "Gemini":
                    response = self.ai_model.generate_content(prompt)
                    ai_result = response.text
                else:
                    base_url = self.config.get("ai_base_url", "https://api.groq.com/openai/v1").rstrip("/")
                    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                    payload = {"model": model_name, "messages": [{"role": "user", "content": prompt}]}
                    resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=30)
                    resp.raise_for_status()
                    ai_result = resp.json()["choices"][0]["message"]["content"]

                final_output = f"## Layers Detected: {' -> '.join(layers) if layers else 'No standard encoding found'}\n\n"
                final_output += f"## Final Decoded String:\n{decoded_text}\n\n"
                final_output += f"--- AI ANALYSIS ---\n{ai_result}"

                self.root.after(0, lambda: self.ai_dec_output.insert(tk.END, final_output))
                self.root.after(0, lambda: self.ai_dec_status_var.set("Magic Complete ✨"))
            except Exception as e:
                self.root.after(0, lambda: self.ai_dec_status_var.set(f"Error: {e}"))
                self.root.after(0, lambda: self.ai_dec_output.insert(tk.END, f"\n\n[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()



    def _init_jwt_ui(self, parent_tab):
        # Main layout
        main_pane = ttk.PanedWindow(parent_tab, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Encoded JWT Section ---
        encoded_frame = ttk.Labelframe(main_pane, text="Encoded JWT", height=150)
        main_pane.add(encoded_frame, weight=1)

        self.jwt_encoded_text = scrolledtext.ScrolledText(encoded_frame, wrap=tk.WORD, height=5)
        self.jwt_encoded_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.jwt_encoded_text.bind("<KeyRelease>", self.decode_jwt)
        
        decode_button = ttk.Button(encoded_frame, text="Decode", command=self.decode_jwt)
        decode_button.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0,5))

        # --- Decoded Section ---
        decoded_notebook = ttk.Notebook(main_pane)
        main_pane.add(decoded_notebook, weight=2)

        # Decoded Token Tab
        decoded_tab = ttk.Frame(decoded_notebook)
        decoded_notebook.add(decoded_tab, text="Decoded Token")

        decoded_pane = ttk.PanedWindow(decoded_tab, orient=tk.HORIZONTAL)
        decoded_pane.pack(fill=tk.BOTH, expand=True)

        header_frame = ttk.Labelframe(decoded_pane, text="Header")
        self.jwt_header_text = scrolledtext.ScrolledText(header_frame, wrap=tk.WORD, height=5)
        self.jwt_header_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.jwt_header_text.bind("<KeyRelease>", self.encode_jwt)
        decoded_pane.add(header_frame, weight=1)

        payload_frame = ttk.Labelframe(decoded_pane, text="Payload")
        self.jwt_payload_text = scrolledtext.ScrolledText(payload_frame, wrap=tk.WORD, height=5)
        self.jwt_payload_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.jwt_payload_text.bind("<KeyRelease>", self.encode_jwt)
        decoded_pane.add(payload_frame, weight=1)

        # Add an explicit Encode button
        encode_button = ttk.Button(decoded_tab, text="Encode", command=self.encode_jwt)
        encode_button.pack(pady=5, fill=tk.X, padx=5)

        # Signature Verification Tab
        verify_tab = ttk.Frame(decoded_notebook)
        decoded_notebook.add(verify_tab, text="Verify Signature")

        verify_frame = ttk.Frame(verify_tab)
        verify_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Algorithm
        ttk.Label(verify_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.jwt_algo_var = tk.StringVar(value="HS256")
        self.jwt_algo_combo = ttk.Combobox(
            verify_frame,
            textvariable=self.jwt_algo_var,
            values=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]
        )
        self.jwt_algo_combo.grid(row=0, column=1, sticky=tk.EW, pady=(0, 5))

        # Key
        key_frame = ttk.Labelframe(verify_frame, text="Secret / Key")
        key_frame.grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=(5,5))
        verify_frame.columnconfigure(1, weight=1)

        self.jwt_key_text = scrolledtext.ScrolledText(key_frame, wrap=tk.WORD, height=8)
        self.jwt_key_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        generate_key_button = ttk.Button(key_frame, text="Generate Keys", command=self.generate_keys)
        generate_key_button.pack(pady=(0,5), fill=tk.X, padx=5)

        # Status
        self.jwt_status_var = tk.StringVar()
        self.jwt_status_var.set("Status: Awaiting token and key...")
        self.jwt_status_label = ttk.Label(verify_frame, textvariable=self.jwt_status_var, anchor=tk.W)
        self.jwt_status_label.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=(5,0))

    def encode_base64(self):
        self.base64_status_var.set("Status: Encoding...")
        input_text = self.base64_input_text.get("1.0", tk.END).strip()
        if not input_text:
            self.base64_status_var.set("Status: Input is empty.")
            self.base64_output_text.delete("1.0", tk.END)
            return

        try:
            encoded_bytes = base64.b64encode(input_text.encode('utf-8'))
            self.base64_output_text.delete("1.0", tk.END)
            self.base64_output_text.insert("1.0", encoded_bytes.decode('utf-8'))
            self.base64_status_var.set("Status: Encoded successfully.")
        except Exception as e:
            self.base64_status_var.set(f"Status: Error encoding Base64 - {e}")
            self.base64_output_text.delete("1.0", tk.END)

    def decode_base64(self):
        self.base64_status_var.set("Status: Decoding...")
        input_text = self.base64_input_text.get("1.0", tk.END).strip()
        if not input_text:
            self.base64_status_var.set("Status: Input is empty.")
            self.base64_output_text.delete("1.0", tk.END)
            return

        try:
            decoded_bytes = base64.b64decode(input_text.encode('utf-8'))
            self.base64_output_text.delete("1.0", tk.END)
            self.base64_output_text.insert("1.0", decoded_bytes.decode('utf-8'))
            self.base64_status_var.set("Status: Decoded successfully.")
        except base64.binascii.Error as e:
            self.base64_status_var.set(f"Status: Invalid Base64 string - {e}")
            self.base64_output_text.delete("1.0", tk.END)
        except Exception as e:
            self.base64_status_var.set(f"Status: Error decoding Base64 - {e}")
            self.base64_output_text.delete("1.0", tk.END)

    def encode_base64url(self):
        self.base64_status_var.set("Status: Encoding URL-safe...")
        input_text = self.base64_input_text.get("1.0", tk.END).strip()
        if not input_text:
            self.base64_status_var.set("Status: Input is empty.")
            self.base64_output_text.delete("1.0", tk.END)
            return

        try:
            encoded_bytes = base64.urlsafe_b64encode(input_text.encode('utf-8'))
            self.base64_output_text.delete("1.0", tk.END)
            self.base64_output_text.insert("1.0", encoded_bytes.decode('utf-8').rstrip('=')) # Remove padding
            self.base64_status_var.set("Status: URL-safe Encoded successfully.")
        except Exception as e:
            self.base64_status_var.set(f"Status: Error encoding Base64URL - {e}")
            self.base64_output_text.delete("1.0", tk.END)

    def decode_base64url(self):
        self.base64_status_var.set("Status: Decoding URL-safe...")
        input_text = self.base64_input_text.get("1.0", tk.END).strip()
        if not input_text:
            self.base64_status_var.set("Status: Input is empty.")
            self.base64_output_text.delete("1.0", tk.END)
            return

        try:
            # Add padding back before decoding if missing
            padded_input = input_text + '=' * (-len(input_text) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded_input.encode('utf-8'))
            self.base64_output_text.delete("1.0", tk.END)
            self.base64_output_text.insert("1.0", decoded_bytes.decode('utf-8'))
            self.base64_status_var.set("Status: URL-safe Decoded successfully.")
        except base64.binascii.Error as e:
            self.base64_status_var.set(f"Status: Invalid Base64URL string - {e}")
            self.base64_output_text.delete("1.0", tk.END)
        except Exception as e:
            self.base64_status_var.set(f"Status: Error decoding Base64URL - {e}")
            self.base64_output_text.delete("1.0", tk.END)

    def _init_base64_ui(self, parent_tab):
        """Initializes the UI for Base64 encoding/decoding."""
        # Main layout
        main_pane = ttk.PanedWindow(parent_tab, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Input Section
        input_frame = ttk.Labelframe(main_pane, text="Input")
        main_pane.add(input_frame, weight=1)

        self.base64_input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10)
        self.base64_input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Controls Section
        controls_frame = ttk.Frame(main_pane)
        main_pane.add(controls_frame, weight=0) # Don't expand vertically

        # Use a grid for buttons to keep them organized
        controls_frame.columnconfigure(0, weight=1)
        controls_frame.columnconfigure(1, weight=1)
        controls_frame.columnconfigure(2, weight=1)
        controls_frame.columnconfigure(3, weight=1)

        ttk.Button(controls_frame, text="Encode Base64", command=self.encode_base64).grid(row=0, column=0, padx=2, pady=2, sticky=tk.EW)
        ttk.Button(controls_frame, text="Decode Base64", command=self.decode_base64).grid(row=0, column=1, padx=2, pady=2, sticky=tk.EW)
        ttk.Button(controls_frame, text="Encode Base64URL", command=self.encode_base64url).grid(row=0, column=2, padx=2, pady=2, sticky=tk.EW)
        ttk.Button(controls_frame, text="Decode Base64URL", command=self.decode_base64url).grid(row=0, column=3, padx=2, pady=2, sticky=tk.EW)

        self.base64_status_var = tk.StringVar(value="Status: Ready")
        self.base64_status_label = ttk.Label(controls_frame, textvariable=self.base64_status_var, anchor=tk.W)
        self.base64_status_label.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky=tk.EW)

        # Output Section
        output_frame = ttk.Labelframe(main_pane, text="Output")
        main_pane.add(output_frame, weight=1)

        self.base64_output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=10)
        self.base64_output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _init_url_ui(self, parent_tab):
        """Initializes the UI for URL encoding/decoding."""
        # Main layout
        main_pane = ttk.PanedWindow(parent_tab, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Input Section
        input_frame = ttk.Labelframe(main_pane, text="Input")
        main_pane.add(input_frame, weight=1)

        self.url_input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10)
        self.url_input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Controls Section
        controls_frame = ttk.Frame(main_pane)
        main_pane.add(controls_frame, weight=0) # Don't expand vertically

        # Use a grid for buttons to keep them organized
        controls_frame.columnconfigure(0, weight=1)
        controls_frame.columnconfigure(1, weight=1)

        ttk.Button(controls_frame, text="Encode URL", command=self.encode_url).grid(row=0, column=0, padx=2, pady=2, sticky=tk.EW)
        ttk.Button(controls_frame, text="Decode URL", command=self.decode_url).grid(row=0, column=1, padx=2, pady=2, sticky=tk.EW)

        self.url_status_var = tk.StringVar(value="Status: Ready")
        self.url_status_label = ttk.Label(controls_frame, textvariable=self.url_status_var, anchor=tk.W)
        self.url_status_label.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.EW)

        # Output Section
        output_frame = ttk.Labelframe(main_pane, text="Output")
        main_pane.add(output_frame, weight=1)

        self.url_output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=10)
        self.url_output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def encode_url(self):
        self.url_status_var.set("Status: Encoding...")
        input_text = self.url_input_text.get("1.0", tk.END).strip()
        if not input_text:
            self.url_status_var.set("Status: Input is empty.")
            self.url_output_text.delete("1.0", tk.END)
            return

        try:
            encoded_text = urllib.parse.quote(input_text, safe='') # safe='' to encode all special characters
            self.url_output_text.delete("1.0", tk.END)
            self.url_output_text.insert("1.0", encoded_text)
            self.url_status_var.set("Status: Encoded successfully.")
        except Exception as e:
            self.url_status_var.set(f"Status: Error encoding URL - {e}")
            self.url_output_text.delete("1.0", tk.END)

    def decode_url(self):
        self.url_status_var.set("Status: Decoding...")
        input_text = self.url_input_text.get("1.0", tk.END).strip()
        if not input_text:
            self.url_status_var.set("Status: Input is empty.")
            self.url_output_text.delete("1.0", tk.END)
            return

        try:
            decoded_text = urllib.parse.unquote(input_text)
            self.url_output_text.delete("1.0", tk.END)
            self.url_output_text.insert("1.0", decoded_text)
            self.url_status_var.set("Status: Decoded successfully.")
        except Exception as e:
            self.url_status_var.set(f"Status: Error decoding URL - {e}")
            self.url_output_text.delete("1.0", tk.END)


    def decode_jwt(self, event=None):
        """Decodes the JWT from the encoded text widget, handling each part individually."""
        # Prevent updates while selecting text
        if self.jwt_encoded_text.tag_ranges("sel"):
            return
            
        encoded_token = self.jwt_encoded_text.get("1.0", tk.END).strip()
        
        # Clear previous state
        self.jwt_header_text.delete("1.0", tk.END)
        self.jwt_payload_text.delete("1.0", tk.END)
        self.jwt_status_var.set("Status: Awaiting token...")
        self.jwt_status_label.config(foreground="black")

        if not encoded_token:
            return

        parts = encoded_token.split('.')
        if len(parts) not in [2, 3]:
            self.jwt_status_var.set("Status: Invalid token format (must have 2 or 3 parts)")
            self.jwt_status_label.config(foreground="red")
            return

        # Decode Header
        try:
            # Add padding for base64 decoding
            header_decoded = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_decoded)
            self.jwt_header_text.insert("1.0", json.dumps(header, indent=4))
            self.jwt_algo_var.set(header.get("alg", "HS256"))
        except Exception as e:
            self.jwt_header_text.insert("1.0", f"Error decoding header: {e}")

        # Decode Payload
        try:
            # Add padding for base64 decoding
            payload_decoded = base64.urlsafe_b64decode(parts[1] + '==')
            payload = json.loads(payload_decoded)
            self.jwt_payload_text.insert("1.0", json.dumps(payload, indent=4))
        except Exception as e:
            self.jwt_payload_text.insert("1.0", f"Error decoding payload: {e}")

        self.jwt_status_var.set("Status: Decoded (signature status below)")
        self.jwt_status_label.config(foreground="black")
        self._verify_jwt_signature()

    def encode_jwt(self, event=None):
        """Encodes a new JWT when header, payload, or key is modified."""
        try:
            header_str = self.jwt_header_text.get("1.0", tk.END)
            payload_str = self.jwt_payload_text.get("1.0", tk.END)
            key = self.jwt_key_text.get("1.0", tk.END).strip()
            algo = self.jwt_algo_var.get()

            if not header_str.strip() or not payload_str.strip():
                self.jwt_status_var.set("Status: Header and Payload cannot be empty.")
                self.jwt_status_label.config(foreground="orange")
                return

            if algo.startswith("RS") or algo.startswith("ES") or algo.startswith("PS"):
                if not key:
                    self.jwt_status_var.set(f"Status: {algo} requires a private key in PEM format to encode.")
                    self.jwt_status_label.config(foreground="red")
                    return
            elif algo.startswith("HS"):
                if not key:
                    self.jwt_status_var.set(f"Status: {algo} requires a secret key (can be any string) to encode.")
                    self.jwt_status_label.config(foreground="red")
                    return

            header = json.loads(header_str)
            payload = json.loads(payload_str)
            
            # Update algorithm in header
            header["alg"] = algo

            encoded_token = jwt.encode(payload, key, algorithm=algo, headers=header)

            self.jwt_encoded_text.delete("1.0", tk.END)
            self.jwt_encoded_text.insert("1.0", encoded_token)
            self.jwt_status_var.set("Status: Encoded successfully.")
            self.jwt_status_label.config(foreground="black")

        except (json.JSONDecodeError, jwt.PyJWTError) as e:
            # If encoding fails, show the error in the status bar
            self.jwt_status_var.set(f"Status: Encoding Error - {e}")
            self.jwt_status_label.config(foreground="red")
        except Exception as e:
            self.jwt_status_var.set(f"Status: An unexpected error occurred - {e}")
            self.jwt_status_label.config(foreground="red")
        else:
            # If encoding is successful, verify the signature
            self._verify_jwt_signature()

    def generate_keys(self):
        algo = self.jwt_algo_var.get()
        private_key = None
        public_key = None
        
        try:
            if algo.startswith("HS"):
                # For HMAC, generate a random secret
                secret = secrets.token_urlsafe(32) # 32 bytes = 256 bits
                self.jwt_key_text.delete("1.0", tk.END)
                self.jwt_key_text.insert("1.0", secret)
                self.jwt_status_var.set("Status: HS Secret generated.")
                self.jwt_status_label.config(foreground="black")
                
            elif algo.startswith("RS") or algo.startswith("ES") or algo.startswith("PS"):
                # For RSA/ECDSA, generate a key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                public_key = private_key.public_key()

                pem_private = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')

                pem_public = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                self.jwt_key_text.delete("1.0", tk.END)
                self.jwt_key_text.insert("1.0", pem_private)
                self.jwt_status_var.set("Status: RS/ES/PS Key Pair generated. Private key in editor. Public key copied to clipboard.")
                self.jwt_status_label.config(foreground="black")
                self.copy_to_clipboard(pem_public) # Automatically copy public key
            else:
                self.jwt_status_var.set("Status: Unknown algorithm for key generation.")
                self.jwt_status_label.config(foreground="red")

        except Exception as e:
            self.jwt_status_var.set(f"Status: Error generating keys - {e}")
            self.jwt_status_label.config(foreground="red")

    def _verify_jwt_signature(self):
        """Attempts to verify the current JWT's signature and updates the status label."""
        try:
            token = self.jwt_encoded_text.get("1.0", tk.END).strip()
            key = self.jwt_key_text.get("1.0", tk.END).strip()
            algo = self.jwt_algo_var.get()

            if not token:
                self.jwt_status_var.set("Status: Awaiting token...")
                self.jwt_status_label.config(foreground="black")
                return

            key_for_verification = key
            if algo.startswith("HS"): # Symmetric algorithms
                if not key:
                    self.jwt_status_var.set("Status: Awaiting secret for HS algorithm verification.")
                    self.jwt_status_label.config(foreground="orange")
                    return
                key_for_verification = key.encode('utf-8')
            elif algo.startswith("RS") or algo.startswith("ES") or algo.startswith("PS"): # Asymmetric algorithms
                if not key:
                    self.jwt_status_var.set("Status: Awaiting public/private key for RS/ES/PS algorithm verification.")
                    self.jwt_status_label.config(foreground="orange")
                    return
                try:
                    # Attempt to load as a public key first (most common for verification)
                    key_for_verification = serialization.load_pem_public_key(key.encode('utf-8'))
                except ValueError:
                    try:
                        # If that fails, try loading as a private key (e.g., if user pastes private key for verification)
                        key_for_verification = serialization.load_pem_private_key(key.encode('utf-8'), password=None)
                        # Extract public key from private key for verification if loaded as private
                        key_for_verification = key_for_verification.public_key()
                    except ValueError:
                        self.jwt_status_var.set(f"Status: Invalid PEM key format for {algo}. Must be a valid public or private key in PEM format.")
                        self.jwt_status_label.config(foreground="red")
                        return
            else:
                self.jwt_status_var.set(f"Status: Unsupported algorithm for verification: {algo}")
                self.jwt_status_label.config(foreground="red")
                return

            jwt.decode(token, key_for_verification, algorithms=[algo])
            self.jwt_status_var.set("Status: Signature Verified")
            self.jwt_status_label.config(foreground="green")

        except jwt.InvalidSignatureError:
            self.jwt_status_var.set("Status: Invalid Signature")
            self.jwt_status_label.config(foreground="red")
        except jwt.ExpiredSignatureError:
            self.jwt_status_var.set("Status: Token has expired")
            self.jwt_status_label.config(foreground="red")
        except jwt.InvalidKeyError:
            self.jwt_status_var.set("Status: Invalid Key (e.g., incorrect format for algorithm)")
            self.jwt_status_label.config(foreground="red")
        except jwt.DecodeError as e:
            self.jwt_status_var.set(f"Status: Decode Error - {e}")
            self.jwt_status_label.config(foreground="red")
        except ValueError as e: # Catch errors related to key format for asymmetric algos
            self.jwt_status_var.set(f"Status: Key format error for {algo} - {e}. Ensure key is valid PEM format for asymmetric algorithms.")
            self.jwt_status_label.config(foreground="red")
        except TypeError as e: # Catch errors related to key type
            self.jwt_status_var.set(f"Status: Key type error for {algo} - {e}. Check if key is bytes/string as expected.")
            self.jwt_status_label.config(foreground="red")
        except Exception as e:
            self.jwt_status_var.set(f"Status: An unexpected error occurred - {e}")
            self.jwt_status_label.config(foreground="red")
