# $VirusTotal$: Malware/Reputation INTELLIGENCE
### What it means:
This intelligence tells you if a file, domain, IP, or URL is associated with malware, phishing, botnets, C2 servers, etc.
### Role in your system:
- Detects if an IP/domain from Shodan is already linked to malicious activity
- Gives multiple signals:
      - Antivirus detections
      - Reputation score
      - File hashes
      - Helps identify active compromise indicators.
### Why it's important:
- Even if a system is exposed, it may not be infected.
- VirusTotal = “Is this thing behaving maliciously?”
____
### Workflow of *Search by file*
```pgsql
User uploads file
      ↓
You send the file to VirusTotal
      ↓
VT gives upload_id
      ↓
You query upload_id → get sha256
      ↓
Use sha256 → retrieve full file report
      ↓
Store results in DB
```