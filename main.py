import socket
import time
from typing import Callable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests


MenuAction = Tuple[str, Callable[[], None]]


class VulnerabilityScanner:
    DEFAULT_HEADERS = {
        "User-Agent": "VulnerabilityScanner/1.0",
        "Accept": "*/*",
    }

    XSS_CANARY = "xsscanary_9f31"
    XSS_PAYLOADS = (
        "<script>alert('xsscanary_9f31')</script>",
        "\"'><svg/onload=alert('xsscanary_9f31')>",
        "<img src=x onerror=alert('xsscanary_9f31')>",
    )

    SQLI_PAYLOADS = (
        "'",
        "\"",
        "' OR '1'='1' --",
        "' UNION SELECT NULL --",
    )
    SQL_ERROR_INDICATORS = (
        "sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "sqlite error",
        "postgresql",
        "odbc",
    )

    DIRECTORY_TRAVERSAL_PAYLOADS = (
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252f..%252fetc/passwd",
    )
    DIRECTORY_TRAVERSAL_INDICATORS = (
        "root:x:0:0",
        "/bin/bash",
        "[boot loader]",
    )

    COMMAND_INJECTION_CANARY = "cmdcanary_4b22"
    COMMAND_INJECTION_PAYLOADS = (
        "127.0.0.1;echo cmdcanary_4b22",
        "127.0.0.1&&echo cmdcanary_4b22",
        "127.0.0.1|echo cmdcanary_4b22",
    )

    WEAK_PASSWORD_CREDENTIALS = (
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("test", "test123"),
    )

    CSRF_PAYLOADS = (
        {"name": "John", "comment": "csrfcanary_91ac"},
        {"name": "John", "comment": "csrfcanary_91ac", "action": "profile_update"},
    )
    CSRF_SUCCESS_INDICATORS = (
        "transfer successful",
        "updated successfully",
        "saved successfully",
        "request completed",
    )
    CSRF_BLOCK_INDICATORS = (
        "csrf token",
        "forbidden",
        "unauthorized",
        "invalid token",
    )

    RFI_CANARY = "rficanary_5a3d"
    RFI_PAYLOADS = (
        "https://example.com/rficanary_5a3d.txt",
        "//example.com/rficanary_5a3d.txt",
        "http://example.com/rficanary_5a3d.php",
    )
    RFI_INDICATORS = (
        "sensitive information leaked",
        "warning: include(",
        "failed to open stream",
        "rficanary_5a3d",
    )

    def __init__(
        self,
        timeout: float = 5.0,
        request_delay: float = 0.05,
        port_scan_range: Tuple[int, int] = (1, 100),
    ):
        self.target_url = ""
        self.vulnerabilities: List[str] = []
        self.timeout = max(timeout, 0.1)
        self.request_delay = max(request_delay, 0.0)
        start, end = port_scan_range
        self.port_scan_start = max(1, min(start, end))
        self.port_scan_end = max(start, end)
        self.session = requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)

    def scan(self):
        self._menu_loop(
            title="Vulnerability Scanner Menu",
            actions=[
                ("Cross-Site Scripting (XSS)", self.scan_xss),
                ("SQL Injection", self.scan_sql_injection),
                ("Directory Traversal", self.scan_directory_traversal),
                ("Command Injection", self.scan_command_injection),
                ("Server Misconfiguration", self.scan_server_misconfiguration),
                ("Weak Passwords", self.scan_weak_passwords),
                ("Network Vulnerabilities", self.scan_network_vulnerabilities),
                ("Web Application Security", self.scan_web_application_security),
            ],
            exit_label="Exit",
        )

    def set_target_url(self) -> str:
        while True:
            current = f" [{self.target_url}]" if self.target_url else ""
            value = input(f"Enter the URL to scan for vulnerabilities{current}: ").strip()

            if not value and self.target_url:
                return self.target_url

            normalized = self._normalize_base_url(value)
            if normalized:
                self.target_url = normalized
                return self.target_url

            print("Invalid URL. Please enter a valid host or URL.")

    def _menu_loop(self, title: str, actions: Sequence[MenuAction], exit_label: str = "Go back"):
        while True:
            print(f"\n{title}")
            for index, (label, _) in enumerate(actions, start=1):
                print(f"{index}. {label}")
            exit_index = len(actions) + 1
            print(f"{exit_index}. {exit_label}")

            choice = input(f"Enter your choice (1-{exit_index}): ").strip()
            if not choice.isdigit():
                print("Invalid choice. Please try again.")
                continue

            selected = int(choice)
            if selected == exit_index:
                return
            if 1 <= selected <= len(actions):
                actions[selected - 1][1]()
            else:
                print("Invalid choice. Please try again.")

    def _normalize_base_url(self, raw_url: str) -> Optional[str]:
        value = raw_url.strip()
        if not value:
            return None
        if "://" not in value:
            value = f"http://{value}"

        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            return None

        base = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.path and parsed.path != "/":
            base = f"{base}{parsed.path.rstrip('/')}"
        return base

    def _record_vulnerability(self, message: str, payload: Optional[str] = None):
        entry = message if payload is None else f"{message} | payload: {payload}"
        if entry not in self.vulnerabilities:
            self.vulnerabilities.append(entry)

    def _contains_any(self, text: str, indicators: Sequence[str]) -> bool:
        lowered = text.lower()
        return any(indicator.lower() in lowered for indicator in indicators)

    def _join_url(self, base_url: str, suffix: str) -> str:
        return f"{base_url.rstrip('/')}/{suffix.lstrip('/')}"

    def _throttle(self):
        if self.request_delay > 0:
            time.sleep(self.request_delay)

    def _request_get(self, url: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        self._throttle()
        try:
            return self.session.get(url, **kwargs)
        except requests.RequestException as exc:
            print(f"GET request failed for {url}: {exc}")
            return None

    def _request_post(self, url: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        self._throttle()
        try:
            return self.session.post(url, **kwargs)
        except requests.RequestException as exc:
            print(f"POST request failed for {url}: {exc}")
            return None

    def scan_xss(self):
        self._menu_loop(
            title="XSS Submenu",
            actions=[
                ("Stored XSS", self.check_xss_stored),
                ("Reflected XSS", self.check_xss_reflected),
            ],
        )

    def check_xss_stored(self):
        target = self.set_target_url()
        for payload in self.XSS_PAYLOADS:
            response = self._request_post(target, data={"comment": payload})
            if response is not None and self.XSS_CANARY in response.text.lower():
                self._record_vulnerability("Stored XSS vulnerability found", payload)
                return

    def check_xss_reflected(self):
        target = self.set_target_url()
        for payload in self.XSS_PAYLOADS:
            response = self._request_get(target, params={"message": payload})
            if response is not None and self.XSS_CANARY in response.text.lower():
                self._record_vulnerability("Reflected XSS vulnerability found", payload)
                return

    def scan_sql_injection(self):
        self._menu_loop(
            title="SQL Injection Submenu",
            actions=[
                ("SQL Injection in GET parameters", self.check_sql_injection_get),
                ("SQL Injection in POST parameters", self.check_sql_injection_post),
            ],
        )

    def check_sql_injection_get(self):
        target = self.set_target_url()
        for payload in self.SQLI_PAYLOADS:
            response = self._request_get(target, params={"id": payload})
            if response is None:
                continue
            if response.status_code >= 500 or self._contains_any(response.text, self.SQL_ERROR_INDICATORS):
                self._record_vulnerability("SQL injection vulnerability found (GET)", payload)
                return

    def check_sql_injection_post(self):
        target = self.set_target_url()
        for payload in self.SQLI_PAYLOADS:
            response = self._request_post(target, data={"id": payload})
            if response is None:
                continue
            if response.status_code >= 500 or self._contains_any(response.text, self.SQL_ERROR_INDICATORS):
                self._record_vulnerability("SQL injection vulnerability found (POST)", payload)
                return

    def scan_directory_traversal(self):
        target = self.set_target_url()
        for payload in self.DIRECTORY_TRAVERSAL_PAYLOADS:
            responses = (
                self._request_get(self._join_url(target, payload)),
                self._request_get(target, params={"file": payload}),
                self._request_get(target, params={"path": payload}),
            )
            for response in responses:
                if response is not None and self._contains_any(response.text, self.DIRECTORY_TRAVERSAL_INDICATORS):
                    self._record_vulnerability("Directory traversal vulnerability found", payload)
                    return

    def scan_command_injection(self):
        target = self.set_target_url()
        for payload in self.COMMAND_INJECTION_PAYLOADS:
            response = self._request_get(target, params={"ip": payload})
            if response is not None and self.COMMAND_INJECTION_CANARY in response.text.lower():
                self._record_vulnerability("Command injection vulnerability found", payload)
                return

    def scan_server_misconfiguration(self):
        target = self.set_target_url()
        response = self._request_get(self._join_url(target, "admin"))
        if response is not None and response.status_code == 200:
            self._record_vulnerability("Server misconfiguration vulnerability found")

    def scan_weak_passwords(self):
        target = self.set_target_url()
        login_url = self._join_url(target, "login")
        for username, password in self.WEAK_PASSWORD_CREDENTIALS:
            response = self._request_post(login_url, data={"username": username, "password": password})
            if response is not None and "login successful" in response.text.lower():
                self._record_vulnerability("Weak password vulnerability found", f"{username}:{password}")
                return

    def scan_network_vulnerabilities(self):
        self._menu_loop(
            title="Network Vulnerabilities Submenu",
            actions=[
                ("Open Ports", self.check_open_ports),
                ("Insecure Cookies", self.check_insecure_cookies),
            ],
        )

    def check_open_ports(self):
        target = self.set_target_url()
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname

        if not host:
            print("Invalid target URL for port scan.")
            return

        open_ports = []
        for port in range(self.port_scan_start, self.port_scan_end + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.3)
                    if sock.connect_ex((host, port)) == 0:
                        open_ports.append(port)
                self._throttle()
            except OSError:
                continue

        if open_ports:
            self._record_vulnerability(f"Open ports found: {open_ports}")

    def check_insecure_cookies(self):
        target = self.set_target_url()
        response = self._request_get(target)
        if response is None:
            return

        insecure = [cookie.name for cookie in response.cookies if not cookie.secure]
        if insecure:
            self._record_vulnerability(f"Insecure cookie vulnerability found: {insecure}")

    def scan_web_application_security(self):
        self._menu_loop(
            title="Web Application Security Submenu",
            actions=[
                ("Cross-Site Request Forgery (CSRF)", self.check_cross_site_request_forgery),
                ("Remote File Inclusion (RFI)", self.check_remote_file_inclusion),
            ],
        )

    def check_cross_site_request_forgery(self):
        target = self.set_target_url()
        for payload in self.CSRF_PAYLOADS:
            response = self._request_post(target, data=payload)
            if response is None:
                continue

            body = response.text.lower()
            has_success = self._contains_any(body, self.CSRF_SUCCESS_INDICATORS)
            blocked = response.status_code in (401, 403) or self._contains_any(body, self.CSRF_BLOCK_INDICATORS)
            if has_success and not blocked:
                self._record_vulnerability("Cross-Site Request Forgery (CSRF) vulnerability found", str(payload))
                return

    def check_remote_file_inclusion(self):
        target = self.set_target_url()
        for payload in self.RFI_PAYLOADS:
            response = self._request_get(target, params={"file": payload})
            if response is not None and self._contains_any(response.text, self.RFI_INDICATORS):
                self._record_vulnerability("Remote File Inclusion (RFI) vulnerability found", payload)
                return

    def report_vulnerabilities(self):
        if self.vulnerabilities:
            print("\nVulnerabilities found:")
            for vulnerability in self.vulnerabilities:
                print(f"- {vulnerability}")
        else:
            print("\nNo vulnerabilities found")


def main():
    scanner = VulnerabilityScanner()
    scanner.scan()
    scanner.report_vulnerabilities()


if __name__ == "__main__":
    main()
