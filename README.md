# Burp2Proxy

A minimal, lightweight HTTP/HTTPS interception proxy for Windows, designed for bug bounty hunters with low-spec laptops. It provides only the essential features to avoid the bloat and performance overhead of tools like Burp Suite.

## Features
- HTTP/HTTPS Proxy Server
- Intercept and modify requests/responses
- Repeater for manual request testing
- In-memory request history

## Setup Instructions

Follow these steps carefully to set up the tool.

### 1. Install Dependencies

First, install the required Python library. It's recommended to use a virtual environment.

```bash
# Create and activate a virtual environment (optional but recommended)
python -m venv venv
venv\\Scripts\\activate

# Install the required package
pip install -r requirements.txt
```

### 2. Generate the CA Certificate

The tool uses the `mitmproxy` library, which requires a custom Certificate Authority (CA) to be installed on your machine to intercept HTTPS traffic.

The easiest way to generate the certificate is to run `mitmproxy` once.

1.  Open your terminal (the one where you installed the requirements).
2.  Run the following command:
    ```bash
    mitmproxy
    ```
3.  Wait for it to load (you'll see a console UI). Once it's running, you can immediately shut it down by pressing `q` and then `y`.

This one-time action creates the necessary CA files in your user directory at `C:\\Users\\<YourUsername>\\.mitmproxy\\`. The tool will use the `mitmproxy-ca.pem` file from this folder.

### 3. Install the CA Certificate in Windows

You must install the generated CA certificate and trust it to avoid constant browser warnings. These steps work for Chrome, Edge, and other system-aware browsers.

1.  Press `Win + R`, type `certmgr.msc`, and press Enter. This opens the Windows Certificate Manager.
2.  In the left pane, right-click on **Trusted Root Certification Authorities** and go to **All Tasks > Import...**.
3.  The Certificate Import Wizard will open. Click **Next**.
4.  Click **Browse...** and navigate to your user folder. You will need to enable viewing hidden files. Go to `C:\\Users\\<YourUsername>\\.mitmproxy\\`.
5.  In the file dialog, change the file type from "X.509..." to **"All Files (*.*)"**.
6.  Select `mitmproxy-ca.pem` and click **Open**, then **Next**.
7.  Ensure the "Certificate Store" is set to **Trusted Root Certification Authorities**. Click **Next**.
8.  Click **Finish**. You may see a security warning; click **Yes** to install the certificate.

#### **For Firefox Users**
Firefox uses its own certificate store. You must perform these additional steps:
1. In Firefox, go to **Settings**.
2. Search for "certificates" and click the **View Certificates...** button.
3. Select the **Authorities** tab and click **Import...**.
4. Navigate to `C:\\Users\\<YourUsername>\\.mitmproxy\\` and select `mitmproxy-ca.pem`.
5. In the dialog that appears, check the box for **"Trust this CA to identify websites."** and click **OK**.
6. Restart Firefox.

### 4. Configure Your Browser Proxy

You need to tell your browser to send its traffic through the proxy tool.

1.  The proxy will run on **`127.0.0.1`** at port **`8080`**.
2.  Configure your browser's proxy settings to use this address for both HTTP and HTTPS.
    *   **In Windows Settings:** Go to **Settings > Network & Internet > Proxy**.
    *   Turn on **"Use a proxy server"**.
    *   Set the Address to `127.0.0.1` and Port to `8080`.
    *   Click **Save**.
    *   **Note:** This will proxy all your system traffic. Use a browser extension like FoxyProxy for more granular control.

## How to Run the Tool

Once you have completed the setup, you can run the application:

```bash
python main.py
```

## Usage Guide (Example)

1.  **Start the Tool:** Run `python main.py`.
2.  **Browse:** Open your configured browser and navigate to a login page (e.g., `http://testphp.vulnweb.com/login.php`).
3.  **View Traffic:** You will see the requests appearing in the "Proxy" tab's history table.
4.  **Intercept:** Click the "Intercept is OFF" button to enable interception. It will turn to "Intercept is ON".
5.  **Trigger Request:** Submit the login form in your browser. The browser will hang, waiting for the request to be forwarded.
6.  **Modify:** The tool will show the intercepted request. You can modify the parameters in the body (e.g., change the `username` or `password`).
7.  **Forward:** Click "Forward" to send the modified request to the server.
8.  **Repeater:** Right-click on any request in the history table and select "Send to Repeater". Go to the "Repeater" tab, modify the request further, and click "Send" to see the response.
