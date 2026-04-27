#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script COMPLETO e CORRIGIDO para teste de proxy
Funciona com certificados auto-assinados
Solicita IP interativamente se não for passado como argumento
"""

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
    def __init__(self, target_ip, timeout=10):
        self.target_ip = target_ip
        self.timeout = timeout
        self.results = []
        self.test_count = 0
        self.success_count = 0
        self.fail_count = 0
        
        # Portas a serem testadas
        self.ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 88: "HTTP_ALT", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 465: "SMTPS", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 4433: "HTTPS_ALT", 5900: "VNC",
            8080: "HTTP_PROXY", 8443: "HTTPS_PROXY",
            444: "Probe"  # Teste sem dados (gera firstBytes=zero)
        }
        
        # Portas TLS server-first (Implicit SSL/TLS) - servidor envia certificado primeiro
        self.server_first_tls_ports = [465, 993, 995]
        # Portas TLS client-first (STARTTLS) - cliente envia Client Hello primeiro
        self.client_first_tls_ports = [443, 4433, 8443]
    
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
        print(f"  {status_text} | {Colors.YELLOW}{service:15}{Colors.RESET} | {test_name:35} | {details[:70]}")
        sys.stdout.flush()
        if status:
            self.success_count += 1
        else:
            self.fail_count += 1
        self.test_count += 1
    
    def check_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_and_test_port(self, port):
        """Conecta e retorna socket para teste TLS"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                return sock
            sock.close()
            return None
        except:
            return None
    
    def test_tls_handshake(self, sock, port, service):
        """Faz handshake TLS usando socket existente"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target_ip)
            
            cert = ssl_sock.getpeercert()
            
            if cert:
                # Extrai informações do certificado
                subject = {}
                for item in cert.get('subject', []):
                    if isinstance(item, tuple) and len(item) > 0:
                        key = item[0][0] if isinstance(item[0], tuple) else 'unknown'
                        value = item[0][1] if isinstance(item[0], tuple) and len(item[0]) > 1 else str(item)
                        subject[key] = value
                
                cn = subject.get('commonName', subject.get('CN', 'N/A'))
                
                # Verifica validade
                valid = False
                valid_str = "Data desconhecida"
                
                if 'notBefore' in cert and 'notAfter' in cert:
                    try:
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        valid = not_before <= datetime.now() <= not_after
                        valid_str = f"Válido: {not_before.strftime('%Y-%m-%d')} até {not_after.strftime('%Y-%m-%d')}"
                    except:
                        valid = False
                        valid_str = "Formato de data inválido"
                
                # Verifica se é auto-assinado
                issuer = {}
                for item in cert.get('issuer', []):
                    if isinstance(item, tuple) and len(item) > 0:
                        key = item[0][0] if isinstance(item[0], tuple) else 'unknown'
                        value = item[0][1] if isinstance(item[0], tuple) and len(item[0]) > 1 else str(item)
                        issuer[key] = value
                
                is_self_signed = (subject.get('commonName') == issuer.get('commonName'))
                
                ssl_sock.close()
                sock.close()
                
                return {
                    'valid': True,  # Conexão TLS estabelecida com sucesso
                    'has_cert': True,
                    'self_signed': is_self_signed,
                    'cn': cn,
                    'validity': valid_str,
                    'details': f"CN={cn}, {valid_str}" + (" (auto-assinado)" if is_self_signed else "")
                }
            else:
                ssl_sock.close()
                sock.close()
                return {
                    'valid': True,
                    'has_cert': False,
                    'details': "Conexão TLS sem certificado"
                }
                
        except ssl.SSLError as e:
            return {
                'valid': False,
                'error': f"SSL: {str(e)[:50]}"
            }
        except Exception as e:
            return {
                'valid': False,
                'error': f"Erro: {str(e)[:50]}"
            }
    
    def test_tls_server_first(self, sock, port, service):
        """Server-First TLS (Implicit SSL): espera certificado do servidor primeiro"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock)
            ssl_sock.do_handshake()
            cert = ssl_sock.getpeercert()
            
            if cert:
                is_self_signed = True
                for item in cert.get('issuer', []):
                    if isinstance(item, tuple) and len(item) > 0:
                        issuer_key = item[0][0] if isinstance(item[0], tuple) else 'unknown'
                        issuer_val = item[0][1] if isinstance(item[0], tuple) and len(item[0]) > 1 else str(item)
                        if issuer_key == 'commonName' or issuer_key == 'CN':
                            if issuer_val == cn:
                                is_self_signed = False
                
                subject = {}
                for item in cert.get('subject', []):
                    if isinstance(item, tuple) and len(item) > 0:
                        key = item[0][0] if isinstance(item[0], tuple) else 'unknown'
                        value = item[0][1] if isinstance(item[0], tuple) and len(item[0]) > 1 else str(item)
                        subject[key] = value
                
                cn = subject.get('commonName', subject.get('CN', 'N/A'))
                
                valid = False
                valid_str = "Data desconhecida"
                if 'notBefore' in cert and 'notAfter' in cert:
                    try:
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        valid = not_before <= datetime.now() <= not_after
                        valid_str = f"Valido: {not_before.strftime('%Y-%m-%d')} ate {not_after.strftime('%Y-%m-%d')}"
                    except:
                        valid_str = "Formato de data invalido"
                
                ssl_sock.close()
                return {
                    'valid': True,
                    'has_cert': True,
                    'self_signed': is_self_signed,
                    'cn': cn,
                    'validity': valid_str,
                    'details': f"CN={cn}, {valid_str}" + (" (auto-assinado)" if is_self_signed else "")
                }
            else:
                ssl_sock.close()
                return {
                    'valid': True,
                    'has_cert': False,
                    'details': "Conexao TLS sem certificado"
                }
        except ssl.SSLError as e:
            return {
                'valid': False,
                'error': f"SSL: {str(e)[:50]}"
            }
        except Exception as e:
            return {
                'valid': False,
                'error': f"Erro: {str(e)[:50]}"
            }
    
    def test_all_ports(self):
        """Testa todas as portas e certificados"""
        self.print_header("VERIFICANDO PORTAS E CERTIFICADOS")
        
        for port, service in sorted(self.ports.items()):
            sock = None
            
            if port in self.server_first_tls_ports:
                sock = self.check_and_test_port(port)
                if sock:
                    self.print_test(service, f"Porta {port}", True, "✓ Porta aberta")
                    cert_info = self.test_tls_server_first(sock, port, service)
                    if cert_info['valid']:
                        if cert_info.get('has_cert', False):
                            self.print_test(service, "Certificado TLS", True, cert_info['details'])
                        else:
                            self.print_test(service, "Conexão TLS", True, "Conexão TLS estabelecida")
                    else:
                        self.print_test(service, "Certificado TLS", False, cert_info.get('error', 'Falha'))
                    try:
                        sock.close()
                    except:
                        pass
                else:
                    self.print_test(service, f"Porta {port}", False, "✗ Porta fechada")
            elif port in self.client_first_tls_ports:
                sock = self.check_and_test_port(port)
                if sock:
                    self.print_test(service, f"Porta {port}", True, "✓ Porta aberta")
                    cert_info = self.test_tls_handshake(sock, port, service)
                    if cert_info['valid']:
                        if cert_info.get('has_cert', False):
                            self.print_test(service, "Certificado TLS", True, cert_info['details'])
                        else:
                            self.print_test(service, "Conexão TLS", True, "Conexão TLS estabelecida")
                    else:
                        self.print_test(service, "Certificado TLS", False, cert_info.get('error', 'Falha'))
                    try:
                        sock.close()
                    except:
                        pass
                else:
                    self.print_test(service, f"Porta {port}", False, "✗ Porta fechada")
            else:
                is_open = self.check_port(port)
                if is_open:
                    self.print_test(service, f"Porta {port}", True, "✓ Porta aberta")
                else:
                    self.print_test(service, f"Porta {port}", False, "✗ Porta fechada")
    
    def test_ftp(self):
        """Testa FTP"""
        self.print_header("TESTANDO FTP (Porta 21)")
        
        if not self.check_port(21):
            self.print_test("FTP", "Serviço", False, "Porta 21 fechada")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 21))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.print_test("FTP", "Banner", True, banner[:50])
            
            # Testa login anônimo
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "331" in response:
                sock.send(b"PASS test@example.com\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "230" in response:
                    self.print_test("FTP", "Login anônimo", True, "Acesso permitido")
                    sock.send(b"QUIT\r\n")
                else:
                    self.print_test("FTP", "Login anônimo", False, "Falha no login")
            else:
                self.print_test("FTP", "Login anônimo", False, "Usuário não aceito")
            
            sock.close()
        except Exception as e:
            self.print_test("FTP", "Teste", False, f"Erro: {str(e)[:40]}")
    
    def test_ssh(self):
        """Testa SSH"""
        self.print_header("TESTANDO SSH (Porta 22)")
        
        if not self.check_port(22):
            self.print_test("SSH", "Serviço", False, "Porta 22 fechada")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 22))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.print_test("SSH", "Banner", True, banner[:50])
            sock.close()
        except Exception as e:
            self.print_test("SSH", "Banner", False, f"Erro: {str(e)[:40]}")
    
    def test_telnet(self):
        """Testa Telnet"""
        self.print_header("TESTANDO TELNET (Porta 23)")
        
        if not self.check_port(23):
            self.print_test("Telnet", "Serviço", False, "Porta 23 fechada")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 23))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.print_test("Telnet", "Conexão", True, banner[:50] if banner else "Conexão OK")
            sock.close()
        except Exception as e:
            self.print_test("Telnet", "Conexão", False, f"Erro: {str(e)[:40]}")
    
    def test_smtp(self):
        """Testa SMTP"""
        self.print_header("TESTANDO SMTP (Porta 25)")
        
        if not self.check_port(25):
            self.print_test("SMTP", "Serviço", False, "Porta 25 fechada")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 25))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.print_test("SMTP", "Banner", True, banner[:50])
            
            sock.send(b"HELO test.com\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "250" in response:
                self.print_test("SMTP", "HELO", True, "Comando aceito")
            else:
                self.print_test("SMTP", "HELO", False, response[:40])
            
            sock.send(b"QUIT\r\n")
            sock.close()
        except Exception as e:
            self.print_test("SMTP", "Teste", False, f"Erro: {str(e)[:40]}")
    
    def test_pop3(self):
        """Testa POP3"""
        self.print_header("TESTANDO POP3 (Porta 110)")
        
        if not self.check_port(110):
            self.print_test("POP3", "Serviço", False, "Porta 110 fechada")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 110))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.print_test("POP3", "Banner", True, banner[:50])
            
            sock.send(b"USER test\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "+OK" in response:
                sock.send(b"PASS test\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "+OK" in response:
                    self.print_test("POP3", "Login", True, "Autenticação OK")
                    sock.send(b"QUIT\r\n")
                else:
                    self.print_test("POP3", "Login", False, "Senha inválida")
            else:
                self.print_test("POP3", "Login", False, "Usuário inválido")
            
            sock.close()
        except Exception as e:
            self.print_test("POP3", "Teste", False, f"Erro: {str(e)[:40]}")
    
    def test_imap(self):
        """Testa IMAP"""
        self.print_header("TESTANDO IMAP (Porta 143)")
        
        if not self.check_port(143):
            self.print_test("IMAP", "Serviço", False, "Porta 143 fechada")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 143))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.print_test("IMAP", "Banner", True, banner[:50])
            
            sock.send(b"a1 CAPABILITY\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "OK" in response:
                self.print_test("IMAP", "CAPABILITY", True, "Comando aceito")
            else:
                self.print_test("IMAP", "CAPABILITY", False, response[:40])
            
            sock.send(b"a2 LOGOUT\r\n")
            sock.close()
        except Exception as e:
            self.print_test("IMAP", "Teste", False, f"Erro: {str(e)[:40]}")
    
    def test_http_https(self):
        """Testa HTTP/HTTPS"""
        self.print_header("TESTANDO HTTP/HTTPS")
        
        for port in [80, 88, 8080]:
            if self.check_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((self.target_ip, port))
                    sock.send(b"GET / HTTP/1.0\r\nHost: test\r\n\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if "HTTP" in response:
                        self.print_test(f"HTTP-{port}", "Requisição", True, response[:50])
                    else:
                        self.print_test(f"HTTP-{port}", "Requisição", True, "Porta aberta")
                    sock.close()
                except:
                    self.print_test(f"HTTP-{port}", "Requisição", True, "Porta aberta")
            else:
                self.print_test(f"HTTP-{port}", "Serviço", False, "Porta fechada")
    
    def test_mysql(self):
        """Testa MySQL"""
        self.print_header("TESTANDO MySQL (Porta 3306)")
        
        if not self.check_port(3306):
            self.print_test("MySQL", "Serviço", False, "Porta 3306 fechada")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 3306))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.print_test("MySQL", "Banner", True, banner[:50] if banner else "MySQL respondendo")
            sock.close()
        except Exception as e:
            self.print_test("MySQL", "Conexão", True, "Porta 3306 aberta")
    
    def test_vnc(self):
        """Testa VNC"""
        self.print_header("TESTANDO VNC (Porta 5900)")
        
        if not self.check_port(5900):
            self.print_test("VNC", "Serviço", False, "Porta 5900 fechada")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 5900))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if "RFB" in banner:
                self.print_test("VNC", "Conexão", True, f"VNC: {banner[:40]}")
            else:
                self.print_test("VNC", "Conexão", True, "Porta 5900 aberta")
            sock.close()
        except Exception as e:
            self.print_test("VNC", "Conexão", True, "Porta 5900 aberta")
    
    def print_summary(self):
        """Imprime resumo"""
        self.print_header("RESUMO FINAL")
        
        print(f"\n{Colors.BOLD}📊 Estatísticas:{Colors.RESET}")
        print(f"  • Total de testes: {self.test_count}")
        print(f"  • {Colors.GREEN}✓ Sucessos: {self.success_count}{Colors.RESET}")
        print(f"  • {Colors.RED}✗ Falhas: {self.fail_count}{Colors.RESET}")
        print(f"  • {Colors.BOLD}Taxa de sucesso: {(self.success_count/self.test_count)*100:.1f}%{Colors.RESET}")
        
        # Lista portas abertas
        print(f"\n{Colors.BOLD}🔌 Portas abertas encontradas:{Colors.RESET}")
        open_ports = []
        for port, service in sorted(self.ports.items()):
            if self.check_port(port):
                open_ports.append(f"{port}({service})")
        
        if open_ports:
            print(f"  {', '.join(open_ports)}")
        
        # Nota sobre certificados
        print(f"\n{Colors.YELLOW}📌 Informações:{Colors.RESET}")
        print(f"  • Certificados auto-assinados são NORMAIS em ambiente interno")
        print(f"  • Conexões TLS funcionam mesmo com certificados auto-assinados")
        
        # Salva relatório
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"proxy_test_report_{self.target_ip}_{timestamp}.txt"
        with open(filename, 'w') as f:
            f.write(f"Relatório de Testes - {datetime.now()}\n")
            f.write(f"Target: {self.target_ip}\n")
            f.write(f"{'='*80}\n\n")
            f.write(f"Total de testes: {self.test_count}\n")
            f.write(f"Sucessos: {self.success_count}\n")
            f.write(f"Falhas: {self.fail_count}\n")
            f.write(f"Taxa de sucesso: {(self.success_count/self.test_count)*100:.1f}%\n\n")
            f.write("DETALHAMENTO DOS TESTES:\n")
            f.write("-"*80 + "\n")
            for result in self.results:
                status = "PASS" if result['status'] else "FAIL"
                f.write(f"[{status}] {result['service']:15} | {result['test']:35} | {result['details']}\n")
        
        print(f"\n{Colors.GREEN}📄 Relatório salvo em: {filename}{Colors.RESET}")
    
    def run_all_tests(self):
        """Executa todos os testes"""
        print(f"{Colors.BOLD}{Colors.PURPLE}")
        print("╔═══════════════════════════════════════════════════════════════════╗")
        print("║              PROXY TESTER COMPLETO - v3.0                          ║")
        print("║                Inclui suporte a certificados auto-assinados        ║")
        print(f"║                         Target: {self.target_ip}                 ║")
        print("╚═══════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")
        
        start_time = time.time()
        
        self.test_all_ports()
        self.test_ftp()
        self.test_ssh()
        self.test_telnet()
        self.test_smtp()
        self.test_pop3()
        self.test_imap()
        self.test_http_https()
        self.test_mysql()
        self.test_vnc()
        
        self.print_summary()
        
        elapsed_time = time.time() - start_time
        print(f"\n{Colors.CYAN}⏱️  Tempo total: {elapsed_time:.2f} segundos{Colors.RESET}\n")

def validate_ip(ip):
    """Valida se o IP é válido"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_target_ip():
    """Solicita o IP ao usuário interativamente"""
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║                    PROXY TESTER - CONFIGURAÇÃO                     ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    while True:
        print(f"\n{Colors.YELLOW}Digite o IP do servidor/proxy que deseja testar:{Colors.RESET}")
        ip = input(f"{Colors.BOLD}IP: {Colors.RESET}").strip()
        
        if not ip:
            print(f"{Colors.RED}❌ IP não pode estar vazio!{Colors.RESET}")
            continue
        
        if validate_ip(ip):
            print(f"{Colors.GREEN}✓ IP válido: {ip}{Colors.RESET}")
            return ip
        else:
            print(f"{Colors.RED}❌ IP inválido! Digite um IP no formato correto (ex: 192.168.1.1){Colors.RESET}")

def signal_handler(sig, frame):
    print(f"\n\n{Colors.YELLOW}⚠️ Teste interrompido pelo usuário{Colors.RESET}")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description='Proxy Tester Completo - Testa portas, serviços e certificados SSL/TLS',
        epilog='Exemplos:\n'
               '  python3 proxy_tester.py\n'
               '  python3 proxy_tester.py -t 192.168.1.100\n'
               '  python3 proxy_tester.py --target 10.0.0.1 --timeout 15'
    )
    parser.add_argument('-t', '--target', dest='target', help='IP do alvo (se não fornecido, será solicitado)')
    parser.add_argument('-to', '--timeout', type=int, default=10, help='Timeout em segundos (padrão: 10)')
    
    args = parser.parse_args()
    
    # Se o IP foi passado como argumento, usa ele
    if args.target:
        target_ip = args.target
        if not validate_ip(target_ip):
            print(f"{Colors.RED}❌ IP inválido: {target_ip}{Colors.RESET}")
            print(f"{Colors.YELLOW}Por favor, forneça um IP válido.{Colors.RESET}")
            sys.exit(1)
        print(f"{Colors.GREEN}✓ Usando IP informado: {target_ip}{Colors.RESET}")
    else:
        # Se não foi passado, solicita interativamente
        target_ip = get_target_ip()
    
    print(f"{Colors.CYAN}⏱️  Timeout configurado: {args.timeout} segundos{Colors.RESET}")
    print(f"{Colors.YELLOW}Iniciando testes...{Colors.RESET}")
    time.sleep(1)
    
    tester = ProxyTester(target_ip, args.timeout)
    
    try:
        tester.run_all_tests()
    except Exception as e:
        print(f"{Colors.RED}❌ Erro fatal: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()