# 🦅 LogHawk - Log Monitoring Tool

**LogHawk** is a lightweight, open-source log analysis tool built to help security teams detect suspicious activity like brute-force login attempts, unusual traffic spikes, and unauthorized script executions — fast and efficiently.

---

## 🔍 What It Does

- 🧠 Scans log files for suspicious activity using regex-based rules
- 🚨 Detects threats like brute-force logins, critical errors, and malicious cron jobs
- 📄 Supports multiple log types (`auth.log`, `system.log`, `access.log`, etc.)
- ⚙️ Easily configurable via a JSON file
- 📬 Outputs clear, readable alerts to the terminal
- 📅 Supports automation with `cron`

---

## ⚙️ Requirements

- Python 3.6+

Install Python on Debian/Ubuntu:

```bash
sudo apt-get install python
```

**To run LogHawk, you'll need:**

- ✅ A log file you want to scan

- ✅ A `config.json` file with threat definitions

**The tool supports:**

- 🔎 Match-based threats — alerts on single line matches

- 🔁 Threshold-based threats — dynamically tracks repeated events (e.g., failed logins, repeated endpoint hits) based on grouped values like IP, endpoint, or username

*All alerts will be printed directly to your terminal in a structured format.*

---

## 🚀 How to Use

**Command Usage:**
```bash
python3 /path/to/loghawk.py /path/to/logfile.log --config /path/to/config.json
```

**Example:** (Assuming you are already in the pwd of the script and config file)
```bash
python3 loghawk.py /var/log/auth.log --config config.json
```

---

## 📂 Config File Format

The `config.json` file allows you to define custom threat detection rules for different types of log files.

Each key in the JSON represents the name of a log file, and its value is a list of threat detection rules for that specific log.

**Each rule object contains:**

- `"threat"`: A label for the threat you’re detecting (e.g., SSH Brute Force)

- `"pattern"`: A regular expression used to match lines in the log file

- `"threshold"` (optional): A number indicating how many times the pattern must be matched (per IP or other group) before triggering an alert — used for count-based threats

You can define multiple patterns for the same log file if you're trying to detect different types of threats within a single file.

```json
{
  "auth.log": [
    {
      "threat": "SSH Brute Force",
      "pattern": "Failed password for .* from (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)",
      "threshold": 4,
      "group_by": "ip"
    }    
  ],
  "access.log": [
    {
      "threat": "Web Unauthorized Access",
      "pattern": "(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+) .* HTTP/1\\.1\" 401",
      "threshold": 2,
      "group_by": "ip"
    }
  ],
  "system.log": [
    {
      "threat": "Out of Memory Error",
      "pattern": "Out of memory: Killed process"
    },
    {
      "threat": "High CPU Usage",
      "pattern": "SYSTEM ALERT: High CPU usage detected"
    }
  ],
  "app.log": [
    {
      "threat": "Critical System Errors",
      "pattern": "CRITICAL|ERROR"
    }
  ]
}
```

---

## 🔎 Sample Output

```pgsql
============================================================
[ALERT] SSH Brute Force
Log File     : auth.log
Suspect      : 203.0.113.42
Occurrences  : 6 (Threshold: 5)
------------------------------------------------------------
Line 4: Feb 17 10:16:41 server1 sshd[2143]: Failed password for root from 203.0.113.42 port 3389 ssh2
Line 11: Feb 17 10:30:47 server1 sshd[2143]: Failed password for root from 203.0.113.42 port 3390 ssh2
Line 14: Feb 17 10:45:01 server1 sshd[2143]: Failed password for root from 203.0.113.42 port 3391 ssh2
Line 17: Feb 17 11:00:04 server1 sshd[2143]: Failed password for root from 203.0.113.42 port 35000 ssh2
Line 22: Feb 17 11:25:00 server1 sshd[2143]: Failed password for root from 203.0.113.42 port 35001 ssh2
Line 23: Feb 17 11:26:00 server1 sshd[2143]: Failed password for root from 203.0.113.42 port 35001 ssh2
============================================================

============================================================
[ALERT] SSH Brute Force
Log File     : auth.log
Suspect      : 203.205.205.42
Occurrences  : 8 (Threshold: 5)
------------------------------------------------------------
Line 24: Feb 17 11:26:05 server1 sshd[2143]: Failed password for root from 203.205.205.42 port 35001 ssh2        
Line 25: Feb 17 11:26:10 server1 sshd[2143]: Failed password for root from 203.205.205.42 port 35001 ssh2        
Line 26: Feb 17 11:26:15 server1 sshd[2143]: Failed password for root from 203.205.205.42 port 35001 ssh2        
Line 27: Feb 17 11:26:20 server1 sshd[2143]: Failed password for root from 203.205.205.42 port 35001 ssh2        
Line 28: Feb 17 11:26:25 server1 sshd[2143]: Failed password for root from 203.205.205.42 port 35001 ssh2        
Line 29: Feb 17 11:26:30 server1 sshd[2143]: Failed password for root from 203.205.205.42 port 35001 ssh2        
Line 30: Feb 17 11:26:35 server1 sshd[2143]: Failed password for root from 203.205.205.42 port 35001 ssh2        
Line 31: Feb 17 11:26:40 server1 sshd[2143]: Failed password for root from 203.205.205.42 port 35001 ssh2        
============================================================
```

---

## ⏱️ Automate with Cron

**To run LogHawk hourly, use the following cron job:**
```bash
0 * * * * /usr/bin/python3 /path/to/loghawk.py /path/to/logfile.log --config /path/to/config.json > /path/to/output.log
```

**Follow these steps to edit your crontab and add the cron job:**

**1.** Run the command to open your crontab:
```bash
crontab -e
```
**2.** Copy and paste the cron job above into the crontab. 

**3.** Replace the paths with the correct locations for your LogHawk script, log file, and config file.

**4.** Save and exit.


LogHawk will now run automatically every hour, and its output will be redirected to the specified log file.

---

## 📝 License

LogHawk is an open-source project developed by **Mika Gellizeau** as part of my Lighthouse Labs bootcamp.

You are free to use, modify, and distribute this project for personal, educational, or non-commercial purposes. However, please give appropriate credit to the author (*Mika Gellizeau*) when using or contributing to the project.

This project is provided "as-is," without warranties or guarantees of any kind. Use at your own risk.

