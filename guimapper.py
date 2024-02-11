import sys
import os
import subprocess
import socket
from subprocess import check_output

usage = 'Modo de uso:\n\n' \
'python [modo] [host] [porta] [opções]\n\n' \
'-Faz varredura utilizando ping request nos ips 192.168.0.22 e no range 192.168.1.1 até 192.168.1.100\n' \
'python guimapper.py -varredura -tipo=ICMP -ip=192.168.0.22,192.168.1.1-100\n\n' \
'-Faz varredura utilizando o protocolo TCP com a flag SYN no host 192.168.0.22 nas portas 80 e no range de 8080 até 9083\n' \
'python guimapper.py -varredura -tipo=SYN -ip=192.168.0.22 -porta=80,8080-9083\n\n'\
'-Faz varredura utilizando o protocolo UDP no host 192.168.0.22 nas portas 80 e no range de 8080 até 9083\n' \
'python guimapper.py -varredura -tipo=UDP -ip=192.168.0.22 -porta=80,8080-9083\n\n' \
'-Faz varredura utilizando o protocolo UDP e traz os banners dos serviços ativos\n' \
'python guimapper.py -banner -tipo=UDP -ip=192.168.0.22 -porta=80,8080-9083\n\n' \
'[Tipos]\nSYN (utiliza a o protocolo TCP com a flag SYN)\nUDP (utiliza o protocolo UDP)\nICMP (utiliza o protocolo ICMP com o tipo request)\nARP (utiliza o protocolo ARP para realizar a consulta no host)\n' \
'\n[Opções]\n-completo (retorna o resultado de todas as portas e hosts passados, desabilitado por padrão)\n-tempo (tempo entre as requisições, -tempo=3 espaça 3 segundos entre cada requisição)\n' \

banner = '''
   ____       _ __  __                             
  / ___|_   _(_)  \/  | __ _ _ __  _ __   ___ _ __ 
 | |  _| | | | | |\/| |/ _` | '_ \| '_ \ / _ \ '__|
 | |_| | |_| | | |  | | (_| | |_) | |_) |  __/ |   
  \____|\__,_|_|_|  |_|\__,_| .__/| .__/ \___|_|   
                            |_|   |_|              
'''

__version__ = 1.2

abertura = "\n%s\nversion:%s\nby:guicapelleto\n" % (banner,__version__)


class Mapper:

    tipos_suportados = ['SYN', 'UDP', 'ICMP', 'ARP']
    opcoes_aceitas = ['tempo', 'completo']
    

    def __init__(self, varredura=False, banner=False, tipo=[], hosts=[], portas=[], opcoes=[], tempo=1, completo=False):
        self.completo = completo
        self.tempo = tempo
        self.varredura = varredura
        self.banner = banner
        self.hosts = hosts
        self.tipo = tipo
        self.portas = portas
        self.opcoes = opcoes
        self.report = {'ICMP':[], 'UDP':[], 'SYN':[], 'ARP':[], 'BANNERTCP': [], 'BANNERUDP': []}
        self.treat_data()
    
    def treat_data(self):
        hosts = []
        portas = []
        if self.portas:
            for porta in self.portas:
                if '-' in porta:
                    init = int(porta.split('-')[0])
                    fin = int(porta.split('-')[1])
                    for n in range(init, fin+1):
                        portas.append(n)
                else:
                    portas.append(int(porta))
        self.portas = portas
        if self.varredura:
            if self.hosts == []:
                sys.exit('\nNenhum IP foi passado para varredura\n')
            if self.tipo == []:
                sys.exit('\nNão foi possível detectar o tipo de varredura, ex: -tipo=SYN\n')
            else:
                for tipo in self.tipo:
                    if tipo not in self.tipos_suportados:
                        sys.exit('\nTipo de varredura: %s não suportado\n' % (tipo))
                    if (tipo == 'UDP' or tipo == 'SYN') and portas == []:
                        print ("\nNenhuma porta foi selecionada para a varredura, utilizando a porta 80\n")
                        self.portas.append(80)
        if self.banner:
            if self.hosts == []:
                sys.exit('\nNenhum IP foi passado para varredura\n')
            if self.portas == []:
                sys.exit('\nNenhuma porta foi passada para varredura\n')
        if self.hosts:
            for host in self.hosts:
                if '-' in host:
                    try:
                        host = host.split('-')
                        primary = host[0].split('.')
                        init = int(primary[3])
                        fin = int(host[1]) + 1
                        for i in range(init,fin):
                            ip = ''
                            for a in primary[:3]:
                                ip = ip + a + '.'
                            ip = ip + str(i)
                            hosts.append(ip)
                    except: sys.exit('\nErro ao interpretar o range de IP\n')
                else:
                    hosts.append(host)
            self.hosts = hosts

    def icmp_creation(self,host,timeout = 1):
        try:
            icmp = subprocess.run('ping -c 1 -w %s %s' % (timeout, host),shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            icmp = icmp.stdout + icmp.stderr
            if 'icmp_seq=1' in icmp:
                self.report['ICMP'].append(host)
        except:
            pass

    def arp_creation(self,host,timeout = 1):
        try:
            arp = subprocess.run('arping -c 1 -w %s %s' % (timeout,host),shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            arp = arp.stdout + arp.stderr
            if 'index=' in arp:
                self.report['ARP'].append(host)
        except:
            pass

    def udp_creation(self,host, porta):
        try:
            udp = subprocess.run('hping3 -c 1 --udp -p %s %s ' % (porta, host),shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            udp = udp.stdout + udp.stderr
            if '100% packet loss' in udp:
                self.report['UDP'].append(host + " : " + str(porta) + ":Aberta/Drop")
            if 'Port Unreachable' in udp:
                self.report['UDP'].append(host + " : " + str(porta) + ":Fechada/Reject")
        except Exception as err:
            self.report['UDP'].append(host + " : " + str(porta) + ": %s" % (err))

    def syn_creation(self, host, porta):
        try:
            synack = subprocess.run('hping3 -c 1 -S -p %s %s ' % (porta, host),shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            synack = synack.stdout + synack.stderr
            if 'flags=SA' in synack:
                self.report['SYN'].append(host + " : " + str(porta) + ":Aberta")
            if 'flags=RA' in synack:
                self.report['SYN'].append(host + " : " + str(porta) + ":Fechada")
            if '100% packet loss' in synack:
                self.report['SYN'].append(host + " : " + str(porta) + ":Filtro Drop")
            if 'Port Unreachable' in synack:
                self.report['SYN'].append(host + " : " + str(porta) + ":Filtro Reject")
        except Exception as err:
            self.report['SYN'].append(host + " : " + str(porta) + ": %s" % (err))

    def banner_grab(self,host,porta,protocolo):
        if protocolo == 'TCP':
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(5)
            try:
                conn.connect((host,porta))
                resposta = conn.recv(1024)
                self.report['BANNERTCP'].append(host + " : " + str(porta) + "\n%s" % (resposta))
            except Exception as err:
                try:
                    query = f'HEAD / HTTP/1.1\r\n\r\n\r\n'
                    conn.send(query.encode())
                    resposta = conn.recv(4096)
                    self.report['BANNERTCP'].append(host + " : " + str(porta) + "\n%s" % (resposta.decode()))
                except Exception as err: 
                    pass
            finally:
                conn.close()
        if protocolo == 'UDP':
            conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            conn.settimeout(5)
            try:
                conn.connect((host,porta))
                payload = f'help'
                conn.send(payload.encode())
                resposta = conn.recv(1024)
                self.report['BANNERUDP'].append(host + " : " + str(porta) + "\n%s" % (resposta.decode()))
            except Exception as err:
                pass
            finally:
                conn.close()

    def print_progress(self,text):
        print(text, end='\r')

    def startscan(self):
        self.servicos = []
        self.on = True
        if self.varredura:
            print ("Realizando varredura em %s endereço(s)" % (len(self.hosts)))
            for tipo in self.tipos_suportados:
                if tipo in self.tipo and tipo == 'SYN':
                    print('Varredura com TCP e flag SYN')
                    self.progresso = 0
                    for host in self.hosts:
                        self.progresso += 1
                        for porta in self.portas:
                            self.syn_creation(host,porta)
                            self.print_progress('(%s / %s) - PORTA: %s' % (self.progresso, len(self.hosts), porta))
                    print()
                if tipo in self.tipo and tipo == 'UDP':
                    print('Varredura com protcolo UDP')
                    self.progresso = 0
                    for host in self.hosts:
                        self.progresso += 1
                        for porta in self.portas:
                            self.udp_creation(host,porta)
                            self.print_progress('(%s / %s) - PORTA: %s' % (self.progresso, len(self.hosts), porta))
                    print()
                if tipo in self.tipo and tipo == 'ICMP':
                    print('Varredura com ICMP Request')         
                    self.progresso = 0       
                    for host in self.hosts:
                        self.icmp_creation(host=host)
                        self.progresso += 1
                        text = '(%s / %s)' % (self.progresso, len(self.hosts))
                        self.print_progress(text)
                if tipo in self.tipo and tipo == 'ARP':
                    print('Varredura com protcolo ARP')
                    self.progresso = 0
                    for host in self.hosts:
                        self.arp_creation(host=host)
                        self.progresso += 1
                        text = '(%s / %s)' % (self.progresso, len(self.hosts))
                        self.print_progress(text)
        if self.banner:
            for tipo in self.tipo:
                if tipo == 'SYN':
                    print('Captura de banner com protocolo TCP')
                    self.progresso = 0
                    for host in self.hosts:
                        self.progresso += 1
                        for porta in self.portas:
                            self.banner_grab(host,porta,'TCP')
                            self.print_progress('(%s / %s) - PORTA: %s' % (self.progresso, len(self.hosts), porta))
                if tipo == 'UDP':
                    print('Captura de banner com protocolo UDP')
                    self.progresso = 0
                    for host in self.hosts:
                        self.progresso += 1
                        for porta in self.portas:
                            self.banner_grab(host,porta,'UDP')
                            self.print_progress('(%s / %s) - PORTA: %s' % (self.progresso, len(self.hosts), porta))         
        print()

    def show_report(self):
        if self.report['ICMP']:
            print('\n\n')
            print (20 * '*')
            print('ICMP Scan:')
            for host in self.report['ICMP']:
                print (host)
        if self.report['SYN']:
            print('\n\n')
            print (20 * '*')
            print('SYN/TCP Scan:')
            if self.completo == True:
                for host in self.report['SYN']:
                    print (host)
            else:
                for host in self.report['SYN']:
                    if 'Aberta' in host:
                        print (host)                
        if self.report['UDP']:
            print('\n\n')
            print (20 * '*')
            print('UDP Scan:')
            for host in self.report['UDP']:
                print (host)
        if self.report['ARP']:
            print('\n\n')
            print (20 * '*')
            print('ARP Scan:')
            for host in self.report['ARP']:
                print (host)
        if self.report['BANNERTCP']:
            print('\n\n')
            print (20 * '*')
            print('Banner TCP:')
            for host in self.report['BANNERTCP']:
                print (host)
        if self.report['BANNERUDP']:
            print('\n\n')
            print (20 * '*')
            print('Banner UDP:')
            for host in self.report['BANNERUDP']:
                print (host)
        print('\n\n')


def get_args():
    varredura = False
    banner = False
    tipo = []
    hosts = []
    portas = []
    completo = False
    tempo = 0.1
    if len(sys.argv) < 2 or '-h' in sys.argv:
        print (usage)
    #modos
    if '-varredura' in sys.argv:
        varredura = True
    if '-banner' in sys.argv:
        banner = True
    if '-completo' in sys.argv:
        completo = True
    #tipos e opcoes
    for arg in sys.argv:
        if '-tipo=' in arg:
            tipo = arg.split('-tipo=')[1].split(',')
        if '-ip=' in arg:
            hosts = arg.split('-ip=')[1].split(',')
        if '-porta=' in arg:
            portas = arg.split('-porta=')[1].split(',')
        if '-tempo=' in arg:
            tempo = float(arg.split('-tempo=')[1])
    return varredura, banner, tipo, hosts, portas, tempo, completo

def check_root():
    if os.geteuid() != 0 : return False
    else: return True

def main():
    print (abertura)
    if not check_root():
        sys.exit('\nRequires root to run this script\n')
    varredura,banner,tipo,hosts,portas,tempo,completo = get_args()
    map = Mapper(varredura=varredura, banner=banner, tipo=tipo, hosts=hosts, portas=portas, tempo=tempo, completo=completo)
    try:
        map.startscan()
    except Exception as err :
        sys.exit('Encerrado tarefas %s ' % (err))
    map.show_report()

main()
