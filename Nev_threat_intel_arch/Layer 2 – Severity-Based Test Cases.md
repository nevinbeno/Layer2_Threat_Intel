# **Layer 2 – Severity-Based Test Cases**

This document describes risk-based test cases for **Layer 2 – Threat Intelligence**  
 using severity levels: **HIGH, MEDIUM, and LOW**.

---

## **🔴 HIGH Severity Test Cases**

### **Test Case ID: L2-H-01 — Critical CVE Exploitation**

**Severity:** High

**Input:**

* CVE ID (e.g., CVE-2023-34362)

* Public IP from Layer 1 scan

* CVE listed in CISA KEV

**Action:**

* Query NVD, Vulners, and CISA KEV

**Expected Result:**

* CVSS score ≥ 8

* Marked as *Exploited in the Wild*

* High-risk classification generated

**Purpose:**  
 Validates identification of critical vulnerabilities requiring immediate attention.

---

### **Test Case ID: L2-H-02 — Malware-Associated Exposure**

**Severity:** High

**Input:**

* Public IP

* Open management port (22 / 3389\)

* VirusTotal reputation marked malicious

**Action:**

* Query Shodan and VirusTotal

**Expected Result:**

* High threat score generated

* Critical alert visible in dashboard

**Purpose:**  
 Confirms correlation of exposure and malware intelligence.

---

## **🟠 MEDIUM Severity Test Cases**

### **Test Case ID: L2-M-01 — Moderate Risk CVE**

**Severity:** Medium

**Input:**

* CVE with CVSS score between 5.0 and 7.5

* Not listed in CISA KEV

* Limited exploit references

**Action:**

* Query NVD and Vulners

**Expected Result:**

* Medium risk classification

* Monitoring recommendation generated

**Purpose:**  
 Validates handling of non-critical but actionable vulnerabilities.

---

### **Test Case ID: L2-M-02 — Moderate Exposure Risk**

**Severity:** Medium

**Input:**

* Public IP

* Common service exposed (HTTP / HTTPS)

* Neutral VirusTotal reputation

**Action:**

* Query Shodan and VirusTotal

**Expected Result:**

* Medium exposure risk identified

* No immediate alert generated

**Purpose:**  
 Confirms exposure-based risk evaluation.

---

## **🟢 LOW Severity Test Cases**

### **Test Case ID: L2-L-01 — Low Impact CVE**

**Severity:** Low

**Input:**

* CVE with CVSS score \< 4.0

* No known exploits

* Not listed in CISA KEV

**Action:**

* Query NVD and Vulners

**Expected Result:**

* Low risk classification generated

**Purpose:**  
 Ensures low-impact vulnerabilities do not raise false alarms.

---

### **Test Case ID: L2-L-02 — Non-Public Asset**

**Severity:** Low

**Input:**

* Private IP address

* No exposed ports

**Action:**

* Shodan and VirusTotal queries skipped

**Expected Result:**

* Marked as *Not Applicable*

* No intelligence enrichment performed

**Purpose:**  
 Validates correct handling of internal or non-external assets.