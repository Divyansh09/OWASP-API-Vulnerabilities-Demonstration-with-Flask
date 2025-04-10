**OWASP API Vulnerabilities Demonstration with Flask**

This project demonstrates common OWASP API vulnerabilities using Flask, a Python web framework. The goal of this project is to showcase various security issues that developers should avoid when building APIs.

The project covers multiple OWASP API security risks, and each vulnerability is implemented as a separate API endpoint. This can help security practitioners, developers, and penetration testers understand how these vulnerabilities manifest in a real-world scenario.

**Vulnerabilities Covered:**

1. API1: Broken Object Level Authorization
2. API2: Broken Authentication
3. API3: Broken Object Property Level Authorization
4. API4: Unrestricted Resource Consumption
5. API5: Broken Function Level Authorization
6. API6: Unrestricted Access to Sensitive Business Flows
7. API7 & API10: Unsafe Consumption of APIs (SSRF)
8. API8: Security Misconfiguration
9. API9: Improper Inventory Management
10. API10: Insufficient Logging & Monitoring

**Features:**

- Simple Flask API implementation.
- Vulnerable APIs demonstrating OWASP's top 10 API security risks.
- Vulnerable to common attacks and misuse, such as broken authentication, unrestricted resource consumption, and insecure direct object references.
  
**How to Run the Project:**

1. Clone the repository:
 git clone https://github.com/Divyansh09/OWASP-API-Vulnerabilities-Demonstration-with-Flask.git
 cd OWASP-API-Vulnerabilities-Demonstration-with-Flask

2. Install dependencies:
pip install -r requirements.txt

3. Run the application:
python app/main.py

4. Open the API in your browser or use a tool like Postman or cURL to interact with the endpoints:
http://127.0.0.1:5000/


**Testing the API:**
Use Postman or cURL to test the API endpoints. Here are some example requests:

   Broken Authentication (API2)

Method: POST

URL: http://127.0.0.1:5000/api/login

Body (JSON):

{
  "username": "user",
  "password": "password123"
}
   Broken Object Level Authorization (API1)

Method: GET

URL: http://127.0.0.1:5000/api/objects/1


**Security Warning:**
This project is intentionally vulnerable and should not be used in production environments. It is intended solely for educational purposes to demonstrate common security flaws in API design. Use responsibly.
