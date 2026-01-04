import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import queue
import threading
import config
import os

from proxy.proxy import ProxyManager

import webbrowser
import tempfile

from tkhtmlview import HTMLScrolledText

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
            port=self.config["port"]
        )
        self.proxy_manager.start()

        # Store full flow data
        self.flows = {}
        # Store all flow summaries for filtering
        self.all_flows_summary = []
        self.current_filter_domain = None
        self.repeater_tabs = {}
        self.repeater_tab_counter = 0
        self.intercepted_flow = None

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
        self.repeater_tab = ttk.Frame(self.notebook)
        self.config_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.proxy_tab, text="Proxy")
        self.notebook.add(self.repeater_tab, text="Repeater")
        self.notebook.add(self.config_tab, text="Configuration")

        # --- Proxy Tab ---
        self._init_proxy_tab()
        
        # --- Repeater Tab ---
        self._init_repeater_tab()

        # --- Config Tab ---
        self._init_config_tab()

    def _init_proxy_tab(self):
        proxy_notebook = ttk.Notebook(self.proxy_tab)
        proxy_notebook.pack(fill=tk.BOTH, expand=True)

        interceptor_tab = ttk.Frame(proxy_notebook)
        http_history_tab = ttk.Frame(proxy_notebook)

        proxy_notebook.add(interceptor_tab, text="Interceptor")
        proxy_notebook.add(http_history_tab, text="HTTP History")

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

        self.intercepted_request_text = scrolledtext.ScrolledText(interceptor_tab, wrap=tk.WORD, height=10)
        self.intercepted_request_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Context Menu for Interceptor
        self.interceptor_context_menu = tk.Menu(self.root, tearoff=0)
        self.interceptor_context_menu.add_command(label="Send to Repeater", command=self.send_intercepted_to_repeater)
        self.intercepted_request_text.bind("<Button-3>", self.show_interceptor_context_menu)

        # --- HTTP History Tab ---
        history_controls_frame = ttk.Frame(http_history_tab)
        history_controls_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(history_controls_frame, text="Filter Domain:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_domain_var = tk.StringVar()
        self.filter_domain_entry = ttk.Entry(history_controls_frame, textvariable=self.filter_domain_var, width=30)
        self.filter_domain_entry.pack(side=tk.LEFT, padx=(0, 5))

        filter_button = ttk.Button(history_controls_frame, text="Filter", command=self.apply_filter)
        filter_button.pack(side=tk.LEFT, padx=(0, 2))

        clear_filter_button = ttk.Button(history_controls_frame, text="Clear", command=self.clear_filter)
        clear_filter_button.pack(side=tk.LEFT)

        # History Table (Treeview)
        table_frame = ttk.Frame(http_history_tab)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.history_table = ttk.Treeview(
            table_frame,
            columns=("id", "method", "url", "status"),
            show="headings"
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

        # Context Menu for Repeater
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Send to Repeater", command=self.send_to_repeater)
        self.history_table.bind("<Button-3>", self.show_context_menu)

    def _init_config_tab(self):
        config_frame = ttk.LabelFrame(self.config_tab, text="Proxy Listen Settings")
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
        
        config_frame.columnconfigure(1, weight=1)

        # Save Button
        save_button = ttk.Button(
            self.config_tab,
            text="Save & Restart Proxy",
            command=self.save_and_restart_proxy
        )
        save_button.pack(pady=10, padx=10, fill=tk.X)

        self.status_label = ttk.Label(self.config_tab, text=f"Proxy is running on {self.config['host']}:{self.config['port']}")
        self.status_label.pack(pady=5, padx=10)

    def save_and_restart_proxy(self):
        """Saves the new config and restarts the proxy server."""
        print("save_and_restart_proxy called.")
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
        config.save_config(self.config)

        # 2. Update UI for Restart
        self.status_label.config(text="Restarting proxy, please wait...")
        self.host_entry.config(state='disabled')
        self.port_entry.config(state='disabled')
        self.timeout_entry.config(state='disabled')
        self.notebook.tab(self.notebook.index(self.config_tab), state='disabled') # Disable config tab
        self.root.update_idletasks() # Force GUI update

        # 3. Execute Restart in a New Thread
        restart_thread = threading.Thread(
            target=self._perform_proxy_restart,
            args=(new_host, new_port),
            daemon=True
        )
        restart_thread.start()
        print("Restart thread started.")

    def _perform_proxy_restart(self, new_host, new_port):
        """Helper method to stop and start the proxy in a separate thread."""
        print("_perform_proxy_restart started.")
        try:
            # Stop the old proxy
            self.proxy_manager.stop()
            
            # Create and start a new proxy manager
            self.proxy_manager = ProxyManager(
                self.gui_queue,
                self.proxy_queue,
                host=new_host,
                port=new_port
            )
            self.proxy_manager.start()

            # Schedule GUI update on the main thread
            self.root.after(0, lambda: self._update_ui_after_restart(True, new_host, new_port))

        except Exception as e:
            print(f"Error during proxy restart: {e}")
            self.root.after(0, lambda: self._update_ui_after_restart(False, new_host, new_port, str(e)))
        finally:
            print("_perform_proxy_restart finished.")

    def _update_ui_after_restart(self, success, host, port, error_msg=None):
        """Updates the GUI on the main thread after proxy restart."""
        self.host_entry.config(state='normal')
        self.port_entry.config(state='normal')
        self.timeout_entry.config(state='normal')
        self.notebook.tab(self.notebook.index(self.config_tab), state='normal') # Re-enable config tab

        if success:
            self.status_label.config(text=f"Proxy is running on {host}:{port}")
            messagebox.showinfo("Proxy Restart", f"Proxy successfully restarted on {host}:{port}")
        else:
            self.status_label.config(text=f"Proxy failed to restart. Error: {error_msg}")
            messagebox.showerror("Proxy Restart Error", f"Failed to restart proxy: {error_msg}")

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
    
    def _init_repeater_tab(self):
        # Top frame for controls
        controls_frame = ttk.Frame(self.repeater_tab)
        controls_frame.pack(fill=tk.X, padx=5, pady=2)

        new_tab_button = ttk.Button(controls_frame, text="New Tab", command=self._create_new_repeater_tab)
        new_tab_button.pack(side=tk.LEFT)

        # Notebook to hold individual repeater tabs
        self.repeater_notebook = ttk.Notebook(self.repeater_tab)
        self.repeater_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.repeater_notebook.bind("<<NotebookTabChanged>>", self._on_repeater_tab_change)

        # Create the first initial tab
        self._create_new_repeater_tab()

    def _create_new_repeater_tab(self, request_str=None):
        self.repeater_tab_counter += 1
        tab_id = f"repeater_{self.repeater_tab_counter}"
        tab_title = str(self.repeater_tab_counter)

        tab_frame = ttk.Frame(self.repeater_notebook)
        self.repeater_notebook.add(tab_frame, text=tab_title)

        # Top frame for the close button
        top_frame = ttk.Frame(tab_frame)
        top_frame.pack(fill=tk.X, side=tk.TOP)

        close_button = ttk.Button(top_frame, text="x", command=lambda: self._close_repeater_tab(tab_id), width=2)
        close_button.pack(side=tk.RIGHT, padx=2, pady=2)

        repeater_pane = ttk.PanedWindow(tab_frame, orient=tk.HORIZONTAL)
        repeater_pane.pack(fill=tk.BOTH, expand=True)

        # Request Frame
        req_frame = ttk.Labelframe(repeater_pane, text="Request")
        repeater_pane.add(req_frame, weight=1)

        req_text = scrolledtext.ScrolledText(req_frame, wrap=tk.WORD, height=10)
        req_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        if request_str:
            req_text.insert("1.0", request_str)

        # Button frame for Send and Back
        req_button_frame = ttk.Frame(req_frame)
        req_button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        send_button = ttk.Button(req_button_frame, text="Send", command=self.send_repeater_request)
        send_button.pack(side=tk.LEFT, expand=True, fill=tk.X)

        back_button = ttk.Button(req_button_frame, text="Back", command=lambda: self.go_back_in_repeater(tab_id))
        back_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5,0))
        back_button.pack_forget() # Hide initially
        
        # Response Frame
        resp_frame = ttk.Labelframe(repeater_pane, text="Response")
        repeater_pane.add(resp_frame, weight=1)

        # Response Notebook
        resp_notebook = ttk.Notebook(resp_frame)
        resp_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        raw_tab = ttk.Frame(resp_notebook)
        render_tab = ttk.Frame(resp_notebook)
        resp_notebook.add(raw_tab, text="Raw")
        resp_notebook.add(render_tab, text="Render")

        # Raw Response
        search_frame = ttk.Frame(raw_tab)
        search_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        search_keyword_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_keyword_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(0, 5), expand=True, fill=tk.X)

        search_button = ttk.Button(search_frame, text="Search", command=lambda: self.search_response_body(tab_id))
        search_button.pack(side=tk.LEFT, padx=(0, 2))

        prev_button = ttk.Button(search_frame, text="<", command=lambda: self.go_to_previous_match(tab_id), width=2)
        prev_button.pack(side=tk.LEFT, padx=(0, 2))
        prev_button.config(state='disabled')

        next_button = ttk.Button(search_frame, text=">", command=lambda: self.go_to_next_match(tab_id), width=2)
        next_button.pack(side=tk.LEFT, padx=(0, 2))
        next_button.config(state='disabled')

        clear_search_button = ttk.Button(search_frame, text="Clear", command=lambda: self.clear_response_search(tab_id))
        clear_search_button.pack(side=tk.LEFT)

        search_status_label = ttk.Label(search_frame, text="")
        search_status_label.pack(side=tk.LEFT, padx=(5,0))

        resp_text = scrolledtext.ScrolledText(raw_tab, wrap=tk.WORD, height=10, state='disabled')
        resp_text.pack(fill=tk.BOTH, expand=True)
        resp_text.tag_configure('search', background='yellow', foreground='black')
        resp_text.tag_configure('active_search', background='orange', foreground='black')

        # Rendered Response
        render_frame = HTMLScrolledText(render_tab)
        render_frame.pack(fill=tk.BOTH, expand=True)

        # Open in Browser and Follow Redirect Buttons
        button_frame = ttk.Frame(resp_frame)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        open_browser_button = ttk.Button(button_frame, text="Open in Browser", command=lambda: self.open_in_browser(tab_id))
        open_browser_button.pack(side=tk.LEFT, expand=True, fill=tk.X)

        follow_redirect_button = ttk.Button(button_frame, text="Follow Redirect", command=lambda: self.follow_redirect(tab_id))
        follow_redirect_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5,0))
        follow_redirect_button.pack_forget() # Hide it initially

        # Store widgets for this tab
        self.repeater_tabs[tab_id] = {
            "req_text": req_text,
            "resp_text": resp_text,
            "render_frame": render_frame,
            "send_button": send_button,
            "back_button": back_button,
            "follow_redirect_button": follow_redirect_button,
            "search_keyword_var": search_keyword_var,
            "search_status_label": search_status_label,
            "prev_search_button": prev_button,
            "next_search_button": next_button,
            "search_matches": [],
            "current_search_index": -1,
            "frame": tab_frame,
            "decoded_body": "",
            "redirect_location": None,
            "previous_request": None
        }
        
        self.repeater_notebook.select(tab_frame)
        return tab_id

    def open_in_browser(self, tab_id):
        """Opens the response content in a web browser."""
        if not tab_id or tab_id not in self.repeater_tabs:
            return

        decoded_body = self.repeater_tabs[tab_id].get("decoded_body", "")
        if not decoded_body:
            messagebox.showinfo("Info", "No response content to open.")
            return

        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".html", encoding='utf-8') as f:
                f.write(decoded_body)
                webbrowser.open(f"file://{f.name}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open in browser: {e}")

    def _close_repeater_tab(self, tab_id):
        if tab_id in self.repeater_tabs:
            tab_frame = self.repeater_tabs[tab_id]["frame"]
            self.repeater_notebook.forget(tab_frame)
            del self.repeater_tabs[tab_id]

    def _on_repeater_tab_change(self, event):
        # Can be used later if we need to do something when the tab changes
        pass

    def get_current_repeater_tab_id(self):
        try:
            selected_tab_frame = self.repeater_notebook.nametowidget(self.repeater_notebook.select())
            for tab_id, widgets in self.repeater_tabs.items():
                if widgets["frame"] == selected_tab_frame:
                    return tab_id
        except (tk.TclError, KeyError): # In case no tab is selected or widget not found
            return None
        return None

    def toggle_intercept(self):
        self.is_intercepting = not self.is_intercepting
        state_text = "ON" if self.is_intercepting else "OFF"
        self.intercept_button.config(text=f"Intercept: {state_text}")
        # Send command to proxy thread, which will trigger UI updates via the queue
        self.proxy_manager.toggle_intercept(self.is_intercepting)

    def forward_intercepted_request(self):
        if not self.intercepted_flow:
            return

        raw_request = self.intercepted_request_text.get("1.0", tk.END)
        parts = raw_request.strip().split('\n\n', 1)
        head = parts[0]
        body = parts[1] if len(parts) > 1 else ''

        head_lines = head.split('\n')
        request_line = head_lines[0]
        header_lines = head_lines[1:]

        try:
            if request_line.count(' ') < 2:
                raise ValueError("Invalid request line")
            method, path, _ = request_line.split(' ', 2)
        except ValueError:
            messagebox.showerror("Error", "Invalid request line. Please make sure the request is well-formed.")
            return

        headers = {}
        for line in header_lines:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

        # Find header keys case-insensitively
        host_key = next((k for k in headers if k.lower() == 'host'), None)
        content_length_key = next((k for k in headers if k.lower() == 'content-length'), None)

        # Recalculate Content-Length
        body_bytes = body.encode('utf-8')
        if content_length_key:
            headers[content_length_key] = str(len(body_bytes))
        elif body_bytes and method.upper() in ["POST", "PUT", "PATCH"]:
            headers["Content-Length"] = str(len(body_bytes))

        host = headers.get(host_key)
        if not host:
            from urllib.parse import urlparse
            parsed_url = urlparse(path)
            if parsed_url.netloc:
                host = parsed_url.netloc
                if not host_key: headers["Host"] = host
            else:
                messagebox.showerror("Error", "Host header is missing and could not be determined from the request line.")
                return
        
        scheme = 'https'
        if ':' in host and host.endswith(':80'):
            scheme = 'http'

        if '://' in path:
            url = path
        else:
            url = f"{scheme}://{host}{path}"

        updated_data = {
            "method": method,
            "url": url,
            "headers": list(headers.items()),
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
                elif item["type"] == "repeater_response":
                    tab_id = item.get("tab_id")
                    if tab_id and tab_id in self.repeater_tabs:
                        widgets = self.repeater_tabs[tab_id]
                        data = item["data"]
                        
                        # Raw response
                        widgets["resp_text"].config(state='normal')
                        widgets["resp_text"].delete("1.0", tk.END)
                        widgets["resp_text"].insert("1.0", data["raw"])
                        widgets["resp_text"].config(state='disabled')

                        # Store decoded body
                        self.repeater_tabs[tab_id]["decoded_body"] = data["decoded"]

                        # Rendered response
                        if data["is_html"]:
                            widgets["render_frame"].set_html(data["decoded"])
                        else:
                            widgets["render_frame"].set_html(f"<pre>{data['decoded']}</pre>")

                        # Handle Follow Redirect button
                        follow_button = widgets["follow_redirect_button"]
                        if data.get("is_redirect") and data.get("redirect_location"):
                            self.repeater_tabs[tab_id]["redirect_location"] = data["redirect_location"]
                            follow_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5,0))
                        else:
                            self.repeater_tabs[tab_id]["redirect_location"] = None
                            follow_button.pack_forget()

                        widgets["send_button"].config(state='normal')

        except queue.Empty:
            pass  # No items in queue
        finally:
            # Schedule the next check
            self.root.after(100, self.process_gui_queue)

    def add_flow_to_history(self, item):
        flow_id = item["flow_id"]
        data = item["data"]
        
        # Store the full flow data for later use (e.g., repeater)
        self.flows[flow_id] = item.get("full_flow", {})

        # Store the summary for filtering
        summary_item = {
            "flow_id": flow_id,
            "method": data["method"],
            "url": data["url"],
            "status_code": data["status_code"]
        }
        self.all_flows_summary.append(summary_item)

        # Only add to Treeview if it matches the current filter
        if self._matches_filter_domain(summary_item["url"], self.current_filter_domain):
            self.history_table.insert(
                "", tk.END, iid=flow_id,
                values=(flow_id, data["method"], data["url"], data["status_code"])
            )
            self.history_table.yview_moveto(1) # Auto-scroll to bottom

    def show_intercepted_request(self, item):
        self.intercepted_flow = item
        data = item["data"]
        
        headers_str = ""
        for k, v in data["headers"]:
            headers_str += f"{k}: {v}\n"

        try:
            # Try to decode as UTF-8, fall back to raw representation
            body_content = data["content"].decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            body_content = str(data["content"])

        # Use the full URL in the request line for consistency
        request_line = f"{data['method']} {data['url']} HTTP/1.1"
        full_request = f"{request_line}\n{headers_str}\n{body_content}"
        
        self.intercepted_request_text.delete("1.0", tk.END)
        self.intercepted_request_text.insert("1.0", full_request)
        
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

        raw_request = req_text_widget.get("1.0", tk.END)
        if not raw_request.strip():
            messagebox.showerror("Error", "Request is empty.")
            return

        try:
            method, url, headers, body = self._parse_raw_request(raw_request)
            if method is None: # Parsing failed, message already shown
                return
        except Exception as e:
            messagebox.showerror("Parsing Error", f"Failed to parse request: {e}")
            return
        
        # Disable the send button to prevent multiple clicks
        send_button.config(state='disabled')
        resp_text_widget.config(state='normal')
        resp_text_widget.delete("1.0", tk.END)
        resp_text_widget.insert("1.0", "Sending request...")
        resp_text_widget.config(state='disabled')

        # Run the request in a separate thread
        thread = threading.Thread(
            target=self._send_request_thread,
            args=(method, url, headers, body, current_tab_id), # Pass tab_id
            daemon=True
        )
        thread.start()

    def _parse_raw_request(self, raw_request: str):
        """Parses a raw HTTP request string in a more robust way."""
        parts = raw_request.strip().split('\n\n', 1)
        head = parts[0]
        body = parts[1] if len(parts) > 1 else ''

        head_lines = head.split('\n')
        request_line = head_lines[0]
        header_lines = head_lines[1:]

        # Parse request line
        try:
            if request_line.count(' ') < 2:
                raise ValueError("Invalid request line")
            method, path, _ = request_line.split(' ', 2)
        except ValueError:
            messagebox.showerror("Error", "Invalid request line. Please make sure the request is well-formed.")
            return None, None, None, None

        # Parse headers, making them case-insensitive for lookup
        headers = {}
        for line in header_lines:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

        # Find header keys case-insensitively
        host_key = next((k for k in headers if k.lower() == 'host'), None)
        content_length_key = next((k for k in headers if k.lower() == 'content-length'), None)

        # Recalculate Content-Length
        body_bytes = body.encode('utf-8')
        if content_length_key:
            headers[content_length_key] = str(len(body_bytes))
        # If there's a body but no content-length header, add it (for POST, etc.)
        elif body_bytes and method.upper() in ["POST", "PUT", "PATCH"]:
             headers["Content-Length"] = str(len(body_bytes))


        # Reconstruct URL
        host = headers.get(host_key)
        if not host:
            from urllib.parse import urlparse
            parsed_url = urlparse(path)
            if parsed_url.netloc:
                host = parsed_url.netloc
                if not host_key: # Add Host header if it was missing
                    headers["Host"] = host
            else:
                messagebox.showerror("Error", "Host header is missing and could not be determined from the request line.")
                return None, None, None, None
        
        # Determine scheme
        scheme = 'http' # Default to http
        if host and ':' in host and host.endswith(':443'):
            scheme = 'https'

        # If the path is an absolute URL, its scheme takes precedence
        if '://' in path:
            url = path
            if path.startswith('https://'):
                scheme = 'https' # Correct the scheme if path is an absolute https URL
        else:
            url = f"{scheme}://{host}{path}"
        
        return method, url, headers, body_bytes

    def _send_request_thread(self, method, url, headers, body, tab_id):
        """The actual networking code that runs in a thread."""
        import urllib.request
        import ssl
        import gzip
        import zlib

        # Add a custom header to identify repeater requests and prevent self-interception
        headers['X-Proxy-Tool-Internal'] = 'repeater-request'

        full_response = "" # Initialize full_response here
        decoded_body = ""
        is_html = False
        is_redirect = False
        redirect_location = None

        try:
            # Create a request object
            req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())

            # Build opener (moved from earlier for clarity)
            unverified_context = ssl._create_unverified_context()
            class CustomHTTPSHandler(urllib.request.HTTPSHandler):
                def __init__(self, context): super().__init__(context=context)
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def http_error_302(self, req, fp, code, msg, headers): return fp
                http_error_301 = http_error_303 = http_error_307 = http_error_302
            
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

                content_type_header = response_headers.get('Content-Type', '').lower()
                if 'text/html' in content_type_header: is_html = True
                
                if 'text/' in content_type_header or any(t in content_type_header for t in ['json', 'xml', 'javascript']):
                    charset = 'utf-8'
                    if 'charset=' in content_type_header:
                        try: charset = content_type_header.split('charset=')[1].split(';')[0].strip()
                        except IndexError: pass
                    try: decoded_body = response_body.decode(charset, errors='replace')
                    except (UnicodeDecodeError, LookupError): decoded_body = response_body.decode('latin-1', errors='replace')
                else:
                    decoded_body = f"[Binary Content - Content-Type: {content_type_header}] (Length: {len(response_body)} bytes)"
                
                full_response = f"{status_line}\n{str(response_headers)}\n\n{decoded_body}"

        except urllib.error.HTTPError as e:
            status_code = e.code
            response_body = e.read()
            response_headers = e.headers
            status_line = f"HTTP/{e.version / 10.0} {status_code} {e.reason}"

            if status_code in [301, 302, 303, 307]:
                is_redirect = True
                redirect_location = response_headers.get('Location')

            # Decompression and decoding logic (repeated for error case)...
            content_encoding = response_headers.get('Content-Encoding', '').lower()
            if 'gzip' in content_encoding:
                try: response_body = gzip.decompress(response_body)
                except Exception: pass
            elif 'deflate' in content_encoding:
                try: response_body = zlib.decompress(response_body)
                except Exception: pass
            
            content_type_header = response_headers.get('Content-Type', '').lower()
            if 'text/html' in content_type_header: is_html = True

            if 'text/' in content_type_header or any(t in content_type_header for t in ['json', 'xml', 'javascript']):
                charset = 'utf-8'
                if 'charset=' in content_type_header:
                    try: charset = content_type_header.split('charset=')[1].split(';')[0].strip()
                    except IndexError: pass
                try: decoded_body = response_body.decode(charset, errors='replace')
                except (UnicodeDecodeError, LookupError): decoded_body = response_body.decode('latin-1', errors='replace')
            else:
                decoded_body = f"[Binary Content - Content-Type: {content_type_header}] (Length: {len(response_body)} bytes)"
            
            full_response = f"{status_line}\n{str(response_headers)}\n\n{decoded_body}"

        except Exception as e:
            full_response = f"Error: {e}"
            decoded_body = f"Error: {e}"
        
        # Send the response back to the main thread for display
        self.gui_queue.put({
            "type": "repeater_response",
            "tab_id": tab_id,
            "data": {
                "raw": full_response,
                "decoded": decoded_body,
                "is_html": is_html,
                "is_redirect": is_redirect,
                "redirect_location": redirect_location
            }
        })

    def apply_filter(self):
        """Applies the domain filter to the history table."""
        domain = self.filter_domain_var.get().strip()
        if domain:
            self.current_filter_domain = domain
        else:
            self.current_filter_domain = None
        self._repopulate_history_table()

    def clear_filter(self):
        """Clears the domain filter and repopulates the history table."""
        self.filter_domain_var.set("")
        self.current_filter_domain = None
        self._repopulate_history_table()

    def _repopulate_history_table(self):
        """Clears the Treeview and repopulates it based on the current filter."""
        # Clear existing items
        for item in self.history_table.get_children():
            self.history_table.delete(item)
        
        # Repopulate with filtered items
        for summary_item in self.all_flows_summary:
            if self._matches_filter_domain(summary_item["url"], self.current_filter_domain):
                self.history_table.insert(
                    "", tk.END, iid=summary_item["flow_id"],
                    values=(summary_item["flow_id"], summary_item["method"], summary_item["url"], summary_item["status_code"])
                )
        self.history_table.yview_moveto(1) # Auto-scroll to bottom

    def _matches_filter_domain(self, url: str, filter_domain: str | None) -> bool:
        """Checks if a URL's domain matches the filter domain (including subdomains)."""
        if not filter_domain:
            return True # No filter applied

        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            url_host = parsed_url.hostname
            if not url_host:
                return False

            # Normalize domains for comparison (e.g., remove www.)
            filter_domain_norm = filter_domain.lower().lstrip("www.")
            url_host_norm = url_host.lower().lstrip("www.")

            # Check for exact match or subdomain match
            return url_host_norm == filter_domain_norm or url_host_norm.endswith(f".{filter_domain_norm}")
        except Exception:
            return False # Malformed URL or other error

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

    def shutdown(self):
        """Cleanly stop the proxy and destroy the window."""
        print("Shutting down proxy manager...")
        self.proxy_manager.stop()
        self.root.destroy()
        os._exit(0)
