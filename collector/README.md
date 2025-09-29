**README: Collecting cPanel Web Logs with Filebeat for SIEM**

**Overview**

This guide explains how to collect **Apache/Nginx access and error logs** from cPanel-hosted websites and send them to your **SIEM collector** without modifying website code. This works for any website hosted on cPanel.

**Flow:**

```
cPanel logs (.log or .gz) → Filebeat → HTTP (ngrok or public IP) → SIEM collector → Database
```

---

## **Step 1: Access cPanel via SSH**

1. Login to cPanel and open **Terminal** or connect via SSH:

```bash
ssh username@yourdomain.com
```

2. Confirm your home folder:

```bash
pwd
# Typically: /home/username
```

---

## **Step 2: Locate Web Logs**

1. Check logs directory:

```bash
ls -l ~/logs/
```

2. Identify the website logs, typically:

* `yourdomain.com-Sep-2025.gz` → HTTP access log
* `yourdomain.com-ssl_log-Sep-2025.gz` → HTTPS access log

> Note: Some hosts store logs monthly as `.gz` files. Filebeat cannot tail `.gz` directly.

---

## **Step 3: Extract Logs (if compressed)**

```bash
gunzip -c ~/logs/yourdomain.com-Sep-2025.gz > ~/logs/yourdomain.com-Sep-2025.log
gunzip -c ~/logs/yourdomain.com-ssl_log-Sep-2025.gz > ~/logs/yourdomain.com-ssl_log-Sep-2025.log
```

* Keep these `.log` files for Filebeat to tail.
* Repeat monthly when new `.gz` logs are generated.

---

## **Step 4: Install Filebeat (without root)**

1. Download the **tar.gz version**:

```bash
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.14.0-linux-x86_64.tar.gz
tar -xzf filebeat-8.14.0-linux-x86_64.tar.gz
cd filebeat-8.14.0-linux-x86_64
```

2. You can run Filebeat **from this folder** as your cPanel user.

---

## **Step 5: Configure Filebeat**

Create `filebeat.yml` in Filebeat folder:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /home/username/logs/yourdomain.com-Sep-2025.log
      - /home/username/logs/yourdomain.com-ssl_log-Sep-2025.log

output.http:
  hosts: ["http://YOUR_SIEM_SERVER:8000/collect"]
  content_type: "application/json"
  batch_size: 1
```

**Replace:**

* `username` → your cPanel username
* `YOUR_SIEM_SERVER` → local collector public IP or ngrok URL

---

## **Step 6: Expose Local SIEM Collector (if running locally)**

1. Use [ngrok](https://ngrok.com/) to expose port 8000:

```bash
ngrok http 8000
```

2. Copy the `http://xxxx.ngrok.io` URL and use it in `filebeat.yml`.

---

## **Step 7: Test Filebeat**

Run Filebeat manually:

```bash
./filebeat -e -c filebeat.yml
```

* Filebeat reads logs and sends them to your SIEM.
* Check your collector logs for insertion messages.

---

## **Step 8: Generate Test Logs**

* Visit your website in a browser or run:

```bash
curl https://yourdomain.com/
```

* Filebeat should detect new entries and send them to the collector.

---

## **Step 9: Run Filebeat in Background**

* Using **screen**:

```bash
screen -S filebeat
./filebeat -e -c filebeat.yml
# Ctrl+A then D to detach
```

* Using **cron** (optional, for auto-start on reboot):

```bash
crontab -e
# Add:
@reboot /home/username/filebeat/filebeat -e -c /home/username/filebeat.yml
```

---

## **Step 10: Automate Monthly Log Extraction (Optional)**

* Create `process_logs.sh` to extract new `.gz` logs automatically:

```bash
#!/bin/bash
LOG_DIR=/home/username/logs
SIEM_URL=http://YOUR_SIEM_SERVER:8000/collect

for file in $LOG_DIR/yourdomain.com*-$(date +%b-%Y).gz; do
    gunzip -c "$file" | while read line; do
        curl -X POST -H "Content-Type: application/json" -d "{\"message\": \"$line\"}" $SIEM_URL
    done
done
```

* Schedule in cron to run daily/hourly.

---

## **✅ Summary**

1. Extract `.gz` logs to `.log`.
2. Install Filebeat (tar.gz version) in cPanel home folder.
3. Configure `filebeat.yml` with log paths and collector URL.
4. Expose local collector using ngrok if needed.
5. Run Filebeat manually for testing.
6. Keep Filebeat running in background for continuous collection.
7. Automate monthly log extraction if cPanel rotates logs.

---

This README works for **any website hosted on cPanel**. Just change `username` and `yourdomain.com` paths.

---
