## 1️⃣ Input Validation Test Cases
### Test Case L2-TC-01 — Valid Layer-1 Input
- Input: Valid Layer-1 JSON containing public IP, service, CVE
- Action: Layer-2 processes the JSON
- Expected Result: Intelligence enrichment succeeds
    > Purpose: Confirms Layer-2 accepts correct input
### Test Case L2-TC-02 — Missing Optional Fields
- Input: JSON without domain/hostname
- Action: Layer-2 processes input
- Expected Result: No crash, enrichment continues
    > Purpose: Confirms fault tolerance
### Test Case L2-TC-03 — Invalid JSON Structure
- Input: Malformed or incomplete JSON
- Action: Layer-2 attempts parsing
- Expected Result: Graceful error handling
    > Purpose: Prevents runtime failures
## 2️⃣ Exposure Intelligence (Shodan)
### Test Case L2-TC-04 — Public IP Exposure Lookup
- Input: Public IP from Layer-1
- Action: Query Shodan
- Expected Result: Exposure data returned (ports, services, geo)
    > Purpose: Validates exposure enrichment
### Test Case L2-TC-05 — Private IP Handling
- Input: Private IP (192.x.x.x)
- Action: Query Shodan
- Expected Result: Skipped or marked “Not Applicable”
    > Purpose: Enforces correct boundary behavior
## 3️⃣ Malware Intelligence (VirusTotal)
### Test Case L2-TC-06 — IP Reputation Lookup
- Input: Public IP
- Action: Query VirusTotal 
- Expected Result: Reputation score returned
    > Purpose: Confirms malware intelligence integration
### Test Case L2-TC-07 — Unsupported Input Type
- Input: No hash / URL / public IP available
- Action: VirusTotal query skipped
- Expected Result: No failure
    > Purpose: Validates conditional execution
## 4️⃣ Vulnerability Intelligence
### Test Case L2-TC-08 — CVE Lookup (NVD)
- Input: Valid CVE ID
- Action: Query NVD
- Expected Result: CVE metadata returned
    > Purpose: Confirms authoritative vulnerability lookup
### Test Case L2-TC-09 — Exploit Intelligence (Vulners)
- Input: CVE ID
- Action: Query Vulners
- Expected Result: Exploit availability info
    > Purpose: Confirms exploit awareness
### Test Case L2-TC-10 — CISA KEV Check
- Input: CVE present in KEV
- Action: Check KEV list
- Expected Result: Marked as “Exploited in the Wild”
    > Purpose: Confirms prioritization logic
## 5️⃣ Data Integrity Test Cases
### Test Case L2-TC-11 — No Data Mutation
- Input: Layer-1 JSON
- Action: Layer-2 enrichment
- Expected Result: Original data unchanged
    > Purpose: Confirms non-destructive behavior
### Test Case L2-TC-12 — Duplicate Handling
- Input: Duplicate CVEs across services
- Action: Enrichment
- Expected Result: Deduplicated intelligence
    > Purpose: Prevents data inflation
## 6️⃣ Visualization Test Cases (Maps)
### Test Case L2-TC-13 — Map Generation
- Input: Shodan geo data
- Action: Generate map
- Expected Result: HTML map generated
    > Purpose: Confirms visualization pipeline
### Test Case L2-TC-14 — Cluster Behavior
- Input: Multiple IPs with same geo
- Action: Render map
- Expected Result: Clustered markers
    > Purpose: Confirms expected UI behavior
## 7️⃣ Performance & Limits
### Test Case L2-TC-15 — Rate Limit Handling
- Input: Multiple rapid queries
- Action: Layer-2 executes
- Expected Result: Throttling / graceful failure
    > Purpose: Prevents API abuse