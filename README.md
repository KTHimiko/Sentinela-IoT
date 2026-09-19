# Guarita

Controle de acesso à rede (NAC) para redes domésticas e de pequenas
empresas, com camadas de monitoramento (NOC) e de detecção de ameaças
(SOC). Descobre os dispositivos da rede local, classifica o risco dos
serviços que eles expõem, detecta ataques de camada 2 e 3, e contém um
aparelho comprometido sem depender de switch gerenciável.

A contenção não usa VLAN. O público-alvo não tem equipamento de rede
gerenciável, então o isolamento é feito por envenenamento controlado da
tabela ARP do dispositivo-alvo combinado com regras de `iptables` e
`ip6tables` — o mesmo mecanismo que um atacante usaria, aplicado em
sentido defensivo e restrito a um endereço previamente classificado como
de risco.

Trabalho para a Feira FatecExpo em Redes de Computadores, Fatec Osasco.

## O que ele faz

**Descoberta e identificação.** Varre a sub-rede, e para cada aparelho
tenta dizer o que ele é: fabricante pelo prefixo OUI do MAC, nome de host
por DNS reverso, anúncios mDNS e SSDP que o próprio dispositivo emite,
sistema operacional provável pelo TTL, e tipo inferido pelas portas
abertas. MACs aleatórios de privacidade são reconhecidos como tais.

**Classificação de risco.** Dezessete portas TCP associadas a serviços
sensíveis, mais verificação do certificado TLS na 443 — um certificado
autoassinado ou vencido deixa de contar como "tem HTTPS, logo é seguro".

**Detecção de ataques.** ARP spoofing contra o gateway, um mesmo MAC
respondendo por vários IPs, servidor DHCP não autorizado, rede Wi-Fi
falsa (evil twin), criptografia fraca no próprio Wi-Fi, portas expostas à
internet por UPnP no roteador, e evasão de isolamento por troca de MAC.

**Contenção com prova.** ARP spoofing, `iptables`/`ip6tables` e anúncio de
roteador IPv6 forjado. A permanência do bloqueio é verificada relendo as
regras no sistema — não o estado em memória — e o contador de pacotes
descartados pelo próprio kernel serve de evidência. O tráfego que o
dispositivo contido tenta emitir é registrado antes do descarte.

**Triagem.** Severidade por evento, e correlação: dois tipos distintos de
ataque contra o mesmo endereço em trinta minutos viram um incidente
escalado.

**Saúde da rede.** Latência e disponibilidade por dispositivo, medidas a
partir do ping que a varredura já faz.

## Requisitos

Linux. A contenção depende do Netfilter (`iptables`/`ip6tables`), da
tabela ARP em `/proc/net/arp` e de sockets em modo bruto — não há
equivalente em outros sistemas.

- Go 1.27 ou superior
- `libpcap` (exigida pela única dependência externa, `gopacket`)
- `iptables` e `ip6tables`
- `iproute2` (`ip`), `iputils` (`ping`)
- `NetworkManager` (`nmcli`), opcional: sem ele as checagens de Wi-Fi ficam desligadas

## Compilar e executar

```sh
git clone https://github.com/KTHimiko/Guarita.git
cd Guarita
go build -o guarita .
```

A execução exige privilégios: injetar quadros ARP precisa de socket em
modo bruto, e inserir regras de filtragem precisa acesso ao Netfilter.

```sh
sudo ./guarita
```

Preferível a rodar tudo como root é conceder só as duas capacidades
necessárias:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip ./guarita
./guarita
```

O painel sobe em <http://localhost:8090>. Não há configuração a editar: a
interface, a faixa de endereços e o gateway são descobertos sozinhos.

## Configuração

Tudo por variável de ambiente, e todas têm padrão utilizável.

| Variável | Padrão | Para que serve |
|---|---|---|
| `PORTA` | `8090` | Porta do painel web |
| `INTERVALO_SEGUNDOS` | `20` | Intervalo entre varreduras |
| `REDES_EXTRAS` | — | Sub-redes vizinhas a observar, separadas por vírgula (`192.168.3.0/24`). Recusa faixas maiores que /22 |
| `POLITICA_NAC` | `off` | `off`, `simular` ou `aplicar` — ver abaixo |
| `POLITICA_APRENDIZADO_MINUTOS` | `10` | Janela inicial em que a política nunca bloqueia |
| `MODO` | — | `agente` ou `central` — ver abaixo |
| `GUARITA_TOKEN` | — | Segredo compartilhado entre central e agentes. Obrigatório nos dois modos |
| `AGENTES` | — | Agentes que a central agrega: `nome=http://ip:8095,...` |
| `NOME_AGENTE` | hostname | Como este agente se identifica |
| `PORTA_API` | `8095` | Porta da API do agente |

Três arquivos são gravados no diretório de trabalho: `historico.jsonl`
(eventos), `conhecidos.json` (inventário de MACs já vistos) e
`confiaveis.json` (dispositivos marcados como confiáveis). **Nenhum deles
deve ir para o controle de versão** — contêm o mapa da sua rede.

## Política de admissão (NAC)

Desligada por padrão. Quando ativa, reprova dispositivos desconhecidos
(MAC nunca visto) e os que expõem serviço de risco alto; dispositivos
marcados como confiáveis passam sempre.

```sh
sudo POLITICA_NAC=simular ./guarita   # registra o que faria
sudo POLITICA_NAC=aplicar ./guarita   # isola de verdade, por 15 min
```

Comece por `simular`. Ela grava no histórico o que *teria* sido bloqueado
sem bloquear nada, o que deixa ver os falsos positivos antes de custarem
a conexão de alguém. Nos dois modos há uma janela de aprendizado inicial:
numa primeira execução todo dispositivo é desconhecido, e aplicar de
imediato colocaria a rede inteira em quarentena.

## Modo distribuído

ARP é um protocolo de enlace e não atravessa roteador, então uma
instância só contém o que está na própria sub-rede. Para cobrir várias,
roda-se um agente dentro de cada uma e uma central que agrega:

```sh
# dentro da sub-rede 192.168.3.0/24
sudo MODO=agente GUARITA_TOKEN=<segredo> NOME_AGENTE=andar1 ./guarita

# na máquina que centraliza
sudo MODO=central GUARITA_TOKEN=<segredo> \
     AGENTES=andar1=http://192.168.3.10:8095 ./guarita
```

A central mostra tudo num painel só e, ao isolar um dispositivo remoto,
repassa a ordem ao agente dono — que executa a contenção localmente, onde
ela funciona.

Em modo agente o painel passa a escutar apenas em `127.0.0.1` e só a API
fica exposta. O painel não tem autenticação própria, então publicá-lo na
rede entregaria seu botão de isolar a qualquer um. A API exige o token; e
sem `GUARITA_TOKEN` o modo distribuído simplesmente não sobe, em vez de
subir inseguro.

## Limitações conhecidas

- **Não alcança outras sub-redes sem um agente lá dentro.** Dá para
  detectar por ICMP e varrer portas, mas não para descobrir o MAC, o
  fabricante, nem para conter.
- **A contenção depende de o alvo aceitar ARP forjado.** Um dispositivo
  com entradas ARP estáticas, ou uma rede com proteção contra ARP
  spoofing no switch, não é contido por esta técnica.
- **IPv6 é mitigado, não bloqueado no mesmo grau do IPv4.** O anúncio de
  roteador forjado convence o alvo a abandonar a rota IPv6; o bloqueio
  por `ip6tables` depende do módulo de correspondência por MAC.
- **O isolamento é manual por padrão.** A resposta só é autônoma com a
  política de admissão ativa.

## Organização do código

Um único pacote, separado por responsabilidade:

| Arquivo | Responsabilidade |
|---|---|
| `main.go` | Entrada, portas verificadas, variáveis de ambiente, rotas |
| `network.go` | Detecção de interface, gateway e tabela ARP |
| `ports.go` | Varredura de portas, certificado TLS, TTL e latência |
| `identification.go` | Tabela OUI, DNS reverso, tipo por porta e MAC aleatório |
| `mdns_ssdp.go` | Escuta mDNS e sondagem SSDP |
| `isolation.go` | Contenção, verificação do bloqueio e captura do tráfego |
| `spoofing.go` | ARP spoofing de terceiros e MAC duplicado |
| `dhcp.go` | Servidor DHCP não autorizado |
| `wifi.go` | Criptografia do Wi-Fi e evil twin |
| `upnp.go` | Exposição à internet pelo roteador |
| `monitoring.go` | Laço contínuo e comparação entre ciclos |
| `nac.go` | Política de admissão |
| `noc.go` | Latência e disponibilidade |
| `soc.go` | Severidade e correlação de incidentes |
| `metrics.go` | Tempos de resposta medidos |
| `agent.go` | Modo distribuído: API e cliente |
| `history.go`, `inventory.go`, `trust.go` | Persistência |
| `page.go`, `dashboard.go`, `networkmap.go` | Interface web |


## Aviso

Varredura e contenção de rede só devem ser executadas em infraestrutura
própria ou com autorização expressa. Este programa envia quadros ARP
forjados e altera regras de firewall; usá-lo em rede de terceiros sem
permissão é, na melhor das hipóteses, indevido.
