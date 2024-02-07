<img width="831" alt="Captura de Tela 2024-02-07 às 11 25 54" src="https://github.com/guicapelleto/GuiMapper/assets/125845072/c167ee91-20bd-40ed-afa6-3fbe91f65838">

GuiMapper - 1.1

Criei esse script como forma de estudo e por praticidade de saber o que se está executando exatamente.
Futuras atualizações contará com multithread para acelerar o processo de scanning, bem como implementar o módulo scapy para não depender de ferramentas terceiras como hping e arping.

HPING3 e ARPING são necessários para execução do script.

Modo de uso:
python [modo] [host] [porta] [opções]

-Faz varredura utilizando ping request nos ips 192.168.0.22 e no range 192.168.1.1 até 192.168.1.100
python guimapper.py -varredura -tipo=ICMP -ip=192.168.0.22,192.168.1.1-100

-Faz varredura utilizando o protocolo TCP com a flag SYN no host 192.168.0.22 nas portas 80 e no range de 8080 até 9083
python guimapper.py -varredura -tipo=SYN -ip=192.168.0.22 -porta=80,8080-9083

-Faz varredura utilizando o protocolo UDP no host 192.168.0.22 nas portas 80 e no range de 8080 até 9083
python guimapper.py -varredura -tipo=UDP -ip=192.168.0.22 -porta=80,8080-9083

-Faz varredura utilizando o protocolo UDP e traz os banners dos serviços ativos
python guimapper.py -banner -tipo=UDP -ip=192.168.0.22 -porta=80,8080-9083

[Tipos]
SYN (utiliza a o protocolo TCP com a flag SYN)
UDP (utiliza o protocolo UDP)
ICMP (utiliza o protocolo ICMP com o tipo request)
ARP (utiliza o protocolo ARP para realizar a consulta no host)

[Opções]
-completo (retorna o resultado de todas as portas e hosts passados, desabilitado por padrão)
-tempo (tempo entre as requisições, -tempo=3 espaça 3 segundos entre cada requisição)


Necessário a execução com root.

Exemplo de saída no terminal:


<img width="635" alt="Captura de Tela 2024-02-07 às 11 25 00" src="https://github.com/guicapelleto/GuiMapper/assets/125845072/ce93ea4f-f0d9-49fa-85cb-1e886fc71969">
