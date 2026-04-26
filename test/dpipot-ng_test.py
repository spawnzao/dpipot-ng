#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script automatizado para teste de proxy e serviços de rede
"""

import subprocess
import socket
import ssl
import sys
import time
from datetime import datetime
import argparse
import signal

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class ProxyTester:
    def __init__(self, target_ip, timeout=5):
        self.target_ip = target_ip
        self.timeout = timeout
        self.results = []
        self.test_count = 0
        self.success_count = 0
        self.fail_count = 0
        
        self.ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            88: "HTTP_ALT",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            4433: "HTTPS_ALT",
            5900: "VNC",
            8080: "HTTP_PROXY",
            8443: "HTTPS_PROXY"
        }
        
        self.tls_ports = [465, 993, 995, 443, 4433, 8443]
        
    def print_header(self, text):
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{text.center(80)}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
        sys.stdout.flush()
    
    def print_test(self, service, test_name, status, details=""):
        status_text = f"{Colors.GREEN}✓ PASS{Colors.RESET}" if status else f"{Colors.RED}✗ FAIL{Colors.RESET}"
        self.results.append({
            'service': service,
            'test': test_name,
            'status': status,
            'details': details,
            'timestamp': datetime.now()
        })
        print(f"  {status_text} | {Colors.YELLOW}{service:15}{Colors.RESET} | {test_name:35} | {details[:60]}")
        sys.stdout.flush()
    
    def check_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            service = self.ports.get(port, f"Porta{port}")
            return result == 0, service
        except:
            return False, self.ports.get(port, f"Porta{port}")
    
    def validate_certificate(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            cert = ssl_sock.getpeercert()
            
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            is_valid = not_before <= datetime.now() <= not_after
            
            ssl_sock.close()
            sock.close()
            
            return {
                'valid': is_valid,
                'cn': subject.get('commonName', 'N/A'),
                'issuer': issuer.get('organizationName', 'N/A'),
                'expires': cert['notAfter']
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)[:50]}
    
    def test_all_ports(self):
        self.print_header("VERIFICANDO PORTAS E SERVIÇOS")
        
        for port in sorted(self.ports.keys()):
            is_open, service = self.check_port(port)
            
            if is_open:
                details = "Porta aberta"
                
                if port in self.tls_ports:
                    self.print_test(service, f"Porta {port}", True, "Porta aberta")
                    self.success_count += 1
                    self.test_count += 1
                    
                    cert_info = self.validate_certificate(self.target_ip, port)
                    if cert_info['valid']:
                        self.print_test(service, "Certificado SSL", True, 
                                      f"CN: {cert_info['cn']}, Exp: {cert_info['expires'][:16]}")
                        self.success_count += 1
                    else:
                        self.print_test(service, "Certificado SSL", False, 
                                      cert_info.get('error', 'Inválido'))
                        self.fail_count += 1
                    self.test_count += 1
                else:
                    self.print_test(service, f"Porta {port}", True, details)
                    self.success_count += 1
                    self.test_count += 1
            else:
                self.print_test(service, f"Porta {port}", False, "Porta fechada")
                self.fail_count += 1
                self.test_count += 1
    
    def print_summary(self):
        self.print_header("RESUMO FINAL")
        
        print(f"\n{Colors.BOLD}📊 Estatísticas:{Colors.RESET}")
        print(f"  • Total de testes: {self.test_count}")
        print(f"  • {Colors.GREEN}✓ Sucessos: {self.success_count}{Colors.RESET}")
        print(f"  • {Colors.RED}✗ Falhas: {self.fail_count}{Colors.RESET}")
        print(f"  • {Colors.BOLD}Taxa: {(self.success_count/self.test_count)*100:.1f}%{Colors.RESET}")
        
        open_ports = []
        for port in sorted(self.ports.keys()):
            is_open, service = self.check_port(port)
            if is_open:
                open_ports.append(f"{port}({service})")
        
        print(f"\n{Colors.BOLD}🔌 Portas abertas:{Colors.RESET}")
        if open_ports:
            print(f"  {', '.join(open_ports)}")
        else:
            print(f"  {Colors.RED}Nenhuma porta aberta{Colors.RESET}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"proxy_test_report_{timestamp}.txt"
        with open(filename, 'w') as f:
            f.write(f"Relatório - {datetime.now()}\n")
            f.write(f"Target: {self.target_ip}\n")
            f.write(f"{'='*80}\n\n")
            for result in self.results:
                status = "PASS" if result['status'] else "FAIL"
                f.write(f"[{status}] {result['service']:15} - {result['test']:35} - {result['details']}\n")
        
        print(f"\n{Colors.GREEN}📄 Relatório: {filename}{Colors.RESET}")
    
    def run_all_tests(self):
        print(f"{Colors.BOLD}{Colors.PURPLE}")
        print("╔════════════════════════════════════════════════════════════╗")
        print("║              PROXY TESTER v2.0                         ║")
        print(f"║                    Target: {self.target_ip}               ║")
        print("╚════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")
        
        start_time = time.time()
        
        self.test_all_ports()
        self.print_summary()
        
        elapsed_time = time.time() - start_time
        print(f"\n{Colors.CYAN}⏱️  Tempo: {elapsed_time:.2f}s{Colors.RESET}\n")

def signal_handler(sig, frame):
    print("\n\n" + Colors.YELLOW + "Teste interrompido." + Colors.RESET)
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description='Proxy Tester')
    parser.add_argument('target', nargs='?', default=None, help='IP do alvo (ex: 1.1.1.1)')
    parser.add_argument('-to', '--timeout', type=int, default=5, help='Timeout em segundos')
    
    args = parser.parse_args()
    
    if args.target is None:
        args.target = input("Digite o IP de teste (ex: 1.1.1.1): ").strip()
    
    if not args.target:
        args.target = "1.1.1.1"
    
    tester = ProxyTester(args.target, args.timeout)
    
    try:
        tester.run_all_tests()
    except Exception as e:
        print(f"{Colors.RED}Erro: {e}{Colors.RESET}")
    finally:
        print(f"{Colors.CYAN}Teste finalizado.{Colors.RESET}")

if __name__ == "__main__":
    main()