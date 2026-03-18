# Burp2Proxy Project Overview

## 1. Executive Summary
**Burp2Proxy** is a comprehensive, lightweight security testing tool designed as a powerful alternative to Burp Suite for Windows. Optimized for performance on low-resource hardware, it provides a full suite of penetration testing utilities—including an interception proxy, repeater, and AI-powered assistance—wrapped in a native, responsive GUI.

## 2. Key Features

### 1. HTTP/HTTPS Proxy
The core of the application, powered by `mitmproxy`.
-   **Interception:** Capture request and response traffic in real-time.
-   **Traffic Control:** Pause, inspect, and modify traffic before it reaches the destination.
-   **Scope Management:** Define strict scope rules to focus testing on specific target domains.

### 2. Repeater
A dedicated manual testing interface.
-   **Request Replay:** Modify and resend captured requests to test for vulnerabilities like SQL injection or IDOR.
-   **History:** Tracks request/response pairs for easy comparison and iteration.

### 3. Decoder
A built-in utility for data transformation.
-   **Encoding/Decoding:** Quickly encode or decode data formats (e.g., Base64, URL encoding, Hex) to analyze payloads and obfuscated data.

### 4. AI Assistant
Integrated Artificial Intelligence (via `google-genai`) to assist the tester.
-   **Analysis:** Provides intelligent insights on captured traffic.
-   **Suggestions:** Can suggest potential vulnerabilities or payload modifications based on the context of the request.

### 5. Race Condition Tester
A specialized module for detecting complex race condition vulnerabilities.
-   **Advanced Timing:** Uses techniques like "last-byte synchronization" (HTTP/1.1) and single-packet attacks (HTTP/2) to precisely time requests.
-   **Optimization:** Disables Nagle's algorithm for maximum network performance.

### 6. JS File Reader
A static analysis tool for JavaScript assets.
-   **Discovery:** Automatically identifies JavaScript files accessed during the session.
-   **Analysis:** Reads and presents JS content, helping testers find hardcoded secrets, API endpoints, or client-side logic flaws.

### 7. Match & Replace
Automated traffic modification system.
-   **Rules Engine:** Define regex-based rules to automatically replace headers, body content, or parameters in real-time.
-   **Bypass Testing:** Useful for bypassing client-side controls or stripping security headers automatically.

## 3. Technical Architecture
-   **Frontend:** Native Windows GUI built with Python `tkinter`.
-   **Backend:** Python 3.12+ core leveraging `mitmproxy` for network handling.
-   **Concurrency:** Multi-threaded and asyncio-driven architecture ensures the UI remains responsive even during heavy crawling or race condition attacks.
-   **Deployment:** Standalone Windows executable capability.

## 4. Setup & Usage
-   **Certificate Management:** Automated generation and management of CA certificates for seamless HTTPS interception.
-   **Easy Start:** Simple `python main.py` entry point with a user-friendly interface for all modules.
