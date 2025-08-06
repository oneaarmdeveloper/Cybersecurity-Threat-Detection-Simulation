# Cybersecurity-Threat-Detection-Simulation

A Windows-based Python simulation that generates fake firewall, authentication, and PowerShell logs, detects suspicious activity, and produces professional incident reports in both CSV and PDF formats — complete with real-time console alerts and Windows notifications.

## 📌 Project Overview
This tool mimics a small-scale **Security Operations Center (SOC)** by:
- Generating **randomized log entries** for:
  - Firewall connections
  - Authentication attempts
  - PowerShell commands
- Applying **detection rules** for:
  - Malicious IP addresses
  - Suspicious PowerShell commands
  - Brute-force login attempts
- Triggering **real-time alerts** with:
  - Colored console output
  - Windows toast notifications
- Exporting a **summary report** as:
  - CSV (structured data for analysts)
  - PDF (formatted for management review)

## 🚀 Features
- 🔹 Simulates network & host activity in real time.
- 🔹 Detects multiple attack types:
  - **Malicious IP connections** (from a known list)
  - **Suspicious PowerShell commands**
  - **Brute-force login patterns**
- 🔹 Severity levels (**High / Medium**).
- 🔹 Saves incident history for later review.
- 🔹 Produces professional PDF incident reports.

## 🛠 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/oneaarmdeveloper/cybersecurity-threat-simulation.git
cd cybersecurity-threat-simulation
````

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

Required libraries:

* `colorama`
* `win10toast`
* `pandas`
* `reportlab`

### 3️⃣ Run the Simulation

```bash
python main.py
```

You will be prompted for a simulation duration (1–10 minutes).

---

## 📊 Example Output

**Console Alert:**

```
🚨 SECURITY ALERT 🚨
Time: 2025-08-06 15:37:03
Type: MALICIOUS IP DETECTED
Severity: HIGH
Details: Connection from known malicious IP: 192.168.1.100
==================================================
```

**PDF Report (Summary)**

```
Report Generated: 2025-08-06 15:38:31
Total Alerts: 9
High Priority: 3
Medium Priority: 6
```

---

## 📂 Output Files

* `security_alerts_YYYYMMDD_HHMMSS.csv` → Raw alert data.
* `incident_report_YYYYMMDD_HHMMSS.pdf` → Formatted incident report.

---

## ⚙ Configuration

You can easily extend detection logic by:

* Editing the `self.malicious_ips` list for new IPs.
* Adding more suspicious PowerShell keywords to `self.suspicious_commands`.
* Modifying brute-force thresholds in `check_brute_force()`.

---

## 📈 Possible Improvements

* Add a live web dashboard.
* Integrate with an actual SIEM.
* Store alerts in a SQLite database for trend analysis.
* Export reports to JSON for API use.

---

## 📜 License

MIT License – free to use and modify.

---

## 👤 Author

Developed by **Chukwuebuka Anselm Icheku**
https://github.com/oneaarmdeveloper
Do you want me to make that diagram for you?
```
