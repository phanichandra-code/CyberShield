# CyberShield

## Network Security Monitoring & Threat Detection System

CyberShield is a Python-based cybersecurity monitoring system that analyzes simulated security logs, detects suspicious activity, generates security alerts, stores them in MySQL, and displays the results through a Streamlit SOC dashboard.

## Key Features

- Brute-force login detection
- Port-scan detection
- High-volume request detection
- Security alert generation
- Severity classification
- MySQL alert storage
- SOC-style dashboard
- Alert filtering
- Source IP analysis
- Security event visualization
- Automated detection testing

## Technologies Used

- Python
- MySQL
- Streamlit
- Git
- GitHub
- Python-dotenv

## Detection Rules

### 1. Brute Force Detection

Detects repeated failed login attempts from the same IP within a defined time window.

Threshold:

5 failed login attempts within 60 seconds.

### 2. Port Scan Detection

Detects multiple different ports being accessed by the same IP within a short time period.

Threshold:

5 different ports within 60 seconds.

### 3. High-Volume Activity Detection

Detects unusually high request activity from the same IP.

Threshold:

10 requests within 60 seconds.

## Architecture

Security Logs
↓
Log Processing
↓
Threat Detection
↓
Alert Manager
↓
MySQL Database
↓
Streamlit SOC Dashboard

## Project Structure

CyberShield/
├── logs/
├── src/
├── database/
├── dashboard/
├── tests/
├── requirements.txt
├── .gitignore
└── README.md

## How to Run

### Install dependencies

pip install -r requirements.txt

### Run threat detection

python src/main.py

### Run dashboard

python -m streamlit run dashboard/app.py

## Testing

The project includes positive and negative test cases for:

- Brute-force detection
- Port-scan detection
- High-volume activity detection
- Normal login activity
- Normal port activity
- Normal request activity

## Security Note

This project uses simulated security logs for educational and demonstration purposes. It does not perform real attacks or interact with external systems.

## Future Enhancements

- Machine learning based anomaly detection
- Real-time log monitoring
- Email security alerts
- IP reputation analysis
- Authentication log integration
- Advanced SOC analytics