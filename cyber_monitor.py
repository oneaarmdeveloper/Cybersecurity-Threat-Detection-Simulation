import random
import time
import datetime
import csv
import os
from colorama import init, Fore, Style
from win10toast import ToastNotifier
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# Initialize colorama for colored text
init()

# Initialize Windows toast notifier
toaster = ToastNotifier()

class CyberSecurityMonitor:
    def __init__(self):
        self.alerts = []
        self.failed_login_tracker = {}
        self.malicious_ips = self.load_malicious_ips()
        self.suspicious_commands = ['Invoke-WebRequest', 'IEX', 'Base64', 'Download', 'curl', 'wget']
        
    def load_malicious_ips(self):
        """Load known malicious IP addresses"""
        # Sample malicious IPs for demonstration
        return [
            '192.168.1.100', '10.0.0.50', '172.16.0.25', 
            '203.0.113.0', '198.51.100.0', '192.0.2.0'
        ]
    
    def generate_firewall_log(self):
        """Generate a fake firewall log entry"""
        source_ips = [
            '192.168.1.10', '192.168.1.20', '10.0.0.15', 
            '172.16.0.10', '192.168.1.100', '10.0.0.50'  # Some malicious IPs mixed in
        ]
        
        destination_ports = [80, 443, 22, 23, 21, 25, 53, 135, 445, 3389]
        actions = ['ALLOW', 'DENY', 'DROP']
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source_ip = random.choice(source_ips)
        dest_port = random.choice(destination_ports)
        action = random.choice(actions)
        
        log_entry = f"{timestamp} | FIREWALL | SRC:{source_ip} | DST_PORT:{dest_port} | ACTION:{action}"
        return log_entry, source_ip, dest_port, action
    
    def generate_auth_log(self):
        """Generate fake authentication log entry"""
        usernames = ['admin', 'user1', 'john.doe', 'administrator', 'guest', 'service_account']
        source_ips = ['192.168.1.15', '192.168.1.25', '10.0.0.20', '192.168.1.100']
        results = ['SUCCESS', 'FAILED', 'FAILED', 'FAILED']  # More failures for demo
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = random.choice(usernames)
        source_ip = random.choice(source_ips)
        result = random.choice(results)
        
        log_entry = f"{timestamp} | AUTH | USER:{username} | SRC:{source_ip} | RESULT:{result}"
        return log_entry, username, source_ip, result
    
    def generate_powershell_log(self):
        """Generate fake PowerShell command log"""
        commands = [
            'Get-Process',
            'Get-Service', 
            'Invoke-WebRequest -Uri http://malicious-site.com',
            'IEX (New-Object System.Net.WebClient).DownloadString()',
            'Get-ChildItem',
            '[Convert]::FromBase64String("bWFsaWNpb3VzIGNvZGU=")',
            'Start-Service'
        ]
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        command = random.choice(commands)
        
        log_entry = f"{timestamp} | POWERSHELL | COMMAND:{command}"
        return log_entry, command
    
    def check_brute_force(self, source_ip, result):
        """Check for brute force login attempts"""
        if result == 'FAILED':
            current_time = time.time()
            
            if source_ip not in self.failed_login_tracker:
                self.failed_login_tracker[source_ip] = []
            
            # Add current failed attempt
            self.failed_login_tracker[source_ip].append(current_time)
            
            # Remove attempts older than 1 minute (60 seconds)
            self.failed_login_tracker[source_ip] = [
                t for t in self.failed_login_tracker[source_ip] 
                if current_time - t < 60
            ]
            
            # Check if more than 5 failed attempts in 1 minute
            if len(self.failed_login_tracker[source_ip]) >= 5:
                return True
        return False
    
    def check_malicious_ip(self, ip):
        """Check if IP is in malicious IP list"""
        return ip in self.malicious_ips
    
    def check_suspicious_command(self, command):
        """Check for suspicious PowerShell commands"""
        for suspicious in self.suspicious_commands:
            if suspicious in command:
                return True
        return False
    
    def create_alert(self, alert_type, details, severity="MEDIUM"):
        """Create a security alert"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            'timestamp': timestamp,
            'type': alert_type,
            'details': details,
            'severity': severity
        }
        self.alerts.append(alert)
        
        # Print colored alert to console
        color = Fore.RED if severity == "HIGH" else Fore.YELLOW
        print(f"{color}🚨 SECURITY ALERT 🚨")
        print(f"Time: {timestamp}")
        print(f"Type: {alert_type}")
        print(f"Severity: {severity}")
        print(f"Details: {details}")
        print(f"{Style.RESET_ALL}" + "="*50)
        
        # Send Windows notification
        toaster.show_toast(
            "🔒 Security Alert",
            f"{alert_type}: {details[:50]}...",
            duration=5
        )
    
    def save_logs_to_csv(self):
        """Save all alerts to CSV file"""
        if not self.alerts:
            return
            
        filename = f"security_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['timestamp', 'type', 'details', 'severity']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.alerts)
        
        print(f"{Fore.GREEN}📊 Alerts saved to {filename}{Style.RESET_ALL}")
    
    def generate_pdf_report(self):
        """Generate a PDF incident report"""
        if not self.alerts:
            print(f"{Fore.YELLOW}No alerts to report{Style.RESET_ALL}")
            return
            
        filename = f"incident_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph("🔒 Cybersecurity Incident Report", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Summary
        summary = Paragraph(f"<b>Report Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                          f"<b>Total Alerts:</b> {len(self.alerts)}<br/>"
                          f"<b>High Priority:</b> {len([a for a in self.alerts if a['severity'] == 'HIGH'])}<br/>"
                          f"<b>Medium Priority:</b> {len([a for a in self.alerts if a['severity'] == 'MEDIUM'])}", 
                          styles['Normal'])
        story.append(summary)
        story.append(Spacer(1, 20))
        
        # Alert Details
        for alert in self.alerts[-10:]:  # Show last 10 alerts
            alert_text = f"<b>Time:</b> {alert['timestamp']}<br/>" \
                        f"<b>Type:</b> {alert['type']}<br/>" \
                        f"<b>Severity:</b> {alert['severity']}<br/>" \
                        f"<b>Details:</b> {alert['details']}<br/>"
            
            alert_para = Paragraph(alert_text, styles['Normal'])
            story.append(alert_para)
            story.append(Spacer(1, 10))
        
        doc.build(story)
        print(f"{Fore.GREEN}📄 PDF report saved to {filename}{Style.RESET_ALL}")
    
    def run_simulation(self, duration_minutes=5):
        """Run the security monitoring simulation"""
        print(f"{Fore.CYAN}🔒 Starting Cybersecurity Monitoring System{Style.RESET_ALL}")
        print(f"📊 Monitoring will run for {duration_minutes} minutes")
        print(f"🎯 Watching for: Brute force attacks, Malicious IPs, Suspicious commands")
        print("="*60)
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        while time.time() < end_time:
            # Generate random log type
            log_type = random.choice(['firewall', 'auth', 'powershell'])
            
            if log_type == 'firewall':
                log_entry, source_ip, dest_port, action = self.generate_firewall_log()
                print(f"{Fore.BLUE}📡 {log_entry}{Style.RESET_ALL}")
                
                # Check for malicious IP
                if self.check_malicious_ip(source_ip):
                    self.create_alert(
                        "MALICIOUS IP DETECTED",
                        f"Connection from known malicious IP: {source_ip}",
                        "HIGH"
                    )
            
            elif log_type == 'auth':
                log_entry, username, source_ip, result = self.generate_auth_log()
                print(f"{Fore.GREEN}🔐 {log_entry}{Style.RESET_ALL}")
                
                # Check for brute force
                if self.check_brute_force(source_ip, result):
                    self.create_alert(
                        "BRUTE FORCE ATTACK",
                        f"Multiple failed logins from {source_ip} targeting user: {username}",
                        "HIGH"
                    )
            
            elif log_type == 'powershell':
                log_entry, command = self.generate_powershell_log()
                print(f"{Fore.MAGENTA}⚡ {log_entry}{Style.RESET_ALL}")
                
                # Check for suspicious commands
                if self.check_suspicious_command(command):
                    self.create_alert(
                        "SUSPICIOUS POWERSHELL COMMAND",
                        f"Potentially malicious command detected: {command[:100]}",
                        "MEDIUM"
                    )
            
            # Wait between log entries (1-3 seconds)
            time.sleep(random.uniform(1, 3))
        
        print(f"\n{Fore.CYAN}🏁 Monitoring simulation completed!{Style.RESET_ALL}")
        print(f"📈 Total alerts generated: {len(self.alerts)}")
        
        # Generate reports
        self.save_logs_to_csv()
        self.generate_pdf_report()

def main():
    """Main function to run the cybersecurity monitor"""
    print(f"{Fore.CYAN}")
    print("=" * 60)
    print("    🔒 CYBERSECURITY THREAT DETECTION SYSTEM 🔒")
    print("=" * 60)
    print(f"{Style.RESET_ALL}")
    
    # Create monitor instance
    monitor = CyberSecurityMonitor()
    
    # Get simulation duration from user
    try:
        duration = int(input("Enter simulation duration in minutes (1-10): "))
        if duration < 1 or duration > 10:
            duration = 5
            print(f"Using default duration: {duration} minutes")
    except ValueError:
        duration = 5
        print(f"Invalid input. Using default duration: {duration} minutes")
    
    print(f"\n⏱️  Starting {duration}-minute security simulation...")
    print("👀 Watch for red alerts and Windows notifications!")
    print("\nPress Ctrl+C to stop early\n")
    
    try:
        monitor.run_simulation(duration)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⏹️  Simulation stopped by user{Style.RESET_ALL}")
        monitor.save_logs_to_csv()
        monitor.generate_pdf_report()
    
    print(f"\n{Fore.GREEN}✅ Check your folder for CSV and PDF reports!{Style.RESET_ALL}")
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()