# Burp2Proxy

**A Lightweight, Feature-Rich HTTP/HTTPS Proxy for Security Testing**

Burp2Proxy is a powerful, Python-based web interception proxy designed for penetration testers and bug bounty hunters. It serves as a lightweight alternative to heavier suites, offering essential testing tools wrapped in a clean, native interface. Optimized for performance, it runs smoothly even on low-resource hardware.

---

## 🚀 Key Features

*   **🛡️ HTTP/HTTPS Proxy**: Intercept, inspect, and modify web traffic in real-time. Supports full HTTPS decryption.
*   **🔁 Repeater**: Manually modify and resend requests to test for vulnerabilities like SQL Injection, XSS, and IDOR.
*   **🤖 AI Assistant**: Integrated with Google Gemini (GenAI) to analyze requests/responses and suggest potential vulnerabilities or payloads.
*   **🏎️ Race Condition Tester**: Advanced testing for race conditions supporting both **HTTP/1.1** (Last-Byte Sync) and **HTTP/2** (Single Packet Attack).
*   **🔍 JS File Reader**: Automatically detects and extracts JavaScript files from traffic for static analysis and secret hunting.
*   **🧩 Decoder**: Built-in utilities to quickly encode/decode data (Base64, URL, Hex, etc.).
*   **rules Match & Replace**: Define regex rules to automatically modify headers, bodies, or parameters on the fly (e.g., for bypassing WAFs or altering privileges).
*   **🕷️ Crawler**: A multi-threaded web crawler to map out target applications.

---

## 🛠️ Installation

### Prerequisites
*   **Python 3.12+**
*   **Windows, Linux, or macOS**

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/Burp2Proxy.git
cd Burp2Proxy
```

### 2. Set Up a Virtual Environment (Recommended)
It's best to keep dependencies isolated.
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🔐 Certificate Setup (Important!)

To intercept HTTPS traffic (which is most of the web), you must install the **mitmproxy** Certificate Authority (CA).

1.  **Generate the Certificate:**
    Run the tool once to generate the keys.
    ```bash
    python main.py
    ```
    *If it asks about certificates, close the application.*

2.  **Locate the Certificate:**
    The certificate is created in your user folder:
    *   **Windows:** `C:\Users\<YourName>\.mitmproxy\mitmproxy-ca-cert.pem`
    *   **Linux/Mac:** `~/.mitmproxy/mitmproxy-ca-cert.pem`

3.  **Install/Trust the Certificate:**
    *   **Windows:** Double-click `mitmproxy-ca-cert.p12` (or `.pem`), choose "Install Certificate" -> "Current User" -> "Place all certificates in the following store" -> **"Trusted Root Certification Authorities"**.
    *   **Firefox:** Settings -> Privacy & Security -> Certificates -> View Certificates -> Import -> Select the `.pem` file -> Check "Trust this CA to identify websites".
    *   **Chrome/Edge:** Uses the Windows system store (step above).

---

## 🎮 Usage

### 1. Start the Tool
```bash
python main.py
```

### 2. Configure Your Browser
Set your browser (or a tool like FoxyProxy) to route traffic through the proxy:
*   **IP:** `127.0.0.1`
*   **Port:** `8080`

### 3. Configure AI Assistant (Optional)
To use the **AI Assistant** feature:
1.  Sign up at [Groq Cloud](https://console.groq.com/) to get a free API key.
2.  Open the tool and go to the **Configure** tab.
3.  Paste your API key into the "Groq API Key" field and click **Save**.
    *   *Note: Without this key, the AI analysis features will not function.*

### 4. Start Hacking!
*   **Proxy Tab:** See live traffic. Click "Intercept" to pause requests.
*   **Repeater:** Right-click any request in the Proxy history and select "Send to Repeater".
*   **Race Condition:** Configure your target request and select the engine (HTTP/1.1 or H2) to test for race windows.
*   **AI Assistant:** Use the AI tab to analyze selected requests for insights.

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for new features or bug fixes:
1.  Fork the repo.
2.  Create a new branch (`git checkout -b feature-name`).
3.  Commit your changes.
4.  Push to the branch and submit a Pull Request.

## ⚠️ Disclaimer

**This tool is for educational purposes and authorized security testing only.**
The developers are not responsible for any misuse or damage caused by this program. Always obtain permission before testing any system you do not own.
