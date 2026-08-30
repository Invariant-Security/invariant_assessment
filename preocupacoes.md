# Preocupações de arquitetura — transporte e seleção de payload

Registro de duas preocupações arquiteturais relacionadas, levantadas em
2026-08-30 numa conversa sobre por que cada endpoint leva ~1s pra avaliar.
Nenhuma das duas tem solução implementada ainda — isso aqui é o mapa, não
o código.

## 1. Hoje o Invariant só avalia alvos no mesmo host onde está instalado

### Como o mecanismo funciona de verdade hoje

Vale corrigir um entendimento comum antes de discutir o problema: **não é
"mandamos o código dos testes pra rodar na máquina avaliada, que devolve
um JSON pronto"**. O que `collect_facts()`
(`src/invariant_assessment/facts.py`) faz:

1. Manda um **script de coleta pequeno** — comandos padrão do sistema
   (`cat`, `stat`, `systemctl`, `sysctl` etc.), não a lógica dos 199
   checks — via `docker exec <alvo> sh -c "<script>"`.
2. O alvo devolve **texto bruto** (stdout do script). Não é JSON, não tem
   PASS/FAIL nenhum ali.
3. A avaliação de verdade (`Check.evaluate()`/`evidence()` dos 199 checks)
   acontece **do nosso lado** (`invariant_assessment`), em cima desse
   texto já coletado. O alvo nunca vê nem executa a lógica de teste.

Isso é bom por dois motivos: protege a lógica proprietária (nunca sai da
nossa máquina) e significa que só **um round-trip por alvo** é necessário
— não são 199 idas-e-vindas, é uma coleta composta só, seguida de
avaliação 100% local em Python.

### O problema

`collect_facts()` fala exclusivamente `docker exec`, que só alcança o
socket Docker **local** (mesmo host, mesmo daemon). Isso significa:

- Uma VM VMware, um servidor físico, ou qualquer máquina que não seja um
  container Docker no mesmo host **não é alcançável hoje**, nem lentamente
  — não conecta de jeito nenhum. Não é uma questão de performance, é uma
  questão de "não funciona ainda".
- Se o serviço de avaliação não estiver na mesma máquina do daemon Docker
  do cliente, também não alcança — a menos que a API do Docker seja
  exposta pela rede, o que a maioria dos ambientes não vai querer fazer
  por segurança.

### Avaliação: precisa mudar arquitetura, ou o processo atual aguenta?

A **separação** (coleta burra no alvo + avaliação centralizada aqui) já
está certa e não precisa mudar. O que falta é só a **camada de
transporte**, que hoje está *hardcoded* pra `docker exec`. Rodar em
"vários dispositivos que conseguem se comunicar pela rede" é uma extensão
**aditiva, não uma reescrita**: trocar/generalizar o transporte (SSH é o
candidato óbvio pra Linux/VM/bare-metal remoto; WinRM pra Windows, que já
está no roadmap) mantendo o resto do pipeline (`SystemFacts` →
`Check.evaluate()` → `Finding`) igual.

Um ponto de design que já ajuda nessa direção: como a coleta já é **um
round-trip só** por alvo (não 199), o custo de rede de um transporte
remoto, quando existir, é pago uma vez por alvo, não multiplicado pelo
número de checks.

### Perguntas em aberto pra quando isso for arquitetado de fato

- Autenticação/distribuição de credenciais por alvo remoto — chave SSH por
  cliente? Por dispositivo? Como gerenciar isso com segurança em escala?
- Paralelismo: hoje os alvos são avaliados em sequência (confirmado:
  10 alvos reais = ~9.8s, ~1s cada, um atrás do outro). Com múltiplos
  dispositivos reais de um cliente, isso passa a importar mais — o tempo
  total não pode escalar linear com a quantidade de máquinas.
- Rede do cliente: firewall/VPN. A oferta comercial já assume "roda no
  ambiente do cliente, on-premises" (ver `research/revised_pricing_and_scale.md`
  do material comercial) — esse ponto reforça que o cliente precisa
  liberar conectividade até cada alvo a partir de onde o Invariant rodar.
- O que hoje depende de estar "dentro" do namespace de um container (via
  `docker exec`) precisa ser reconferido pra rodar como comando remoto via
  SSH num host de verdade — provavelmente pouca coisa (o script de coleta
  é comandos Unix padrão), mas não confirmado.

## 2. Falta uma etapa de seleção de payload por sistema operacional

Levantado pelo usuário ao revisar o rascunho deste arquivo: por que não
ter (1) uma etapa de *scan* que identifica todos os endpoints escolhidos
pelo cliente e traz informação inicial (SO, versão...), e só então (2)
decidir/mandar o payload de testes certo pra cada máquina?

**Essa é uma lacuna real, não é sair do escopo do projeto.**
`src/invariant_assessment/api.py`'s `run_assessment()` já faz a etapa 1 —
detecta o SO via `document_slug_for_os()`. A etapa 2 não existe: o código
roda `for check in CHECKS` **incondicionalmente**, os mesmos 199 checks
sempre, sem filtrar pelo SO detectado. `document` só é usado depois pra
escolher o texto/metadado do documento CIS certo (título, remediação) —
nunca pra decidir quais checks de fato avaliar.

Isso "funciona por acidente" hoje porque os 199 checks existentes foram
escritos pra família Debian/Ubuntu, que compartilha estrutura entre
versões (mesmo systemd, mesmo `/etc/shadow`, etc.) — por isso ninguém
notou o buraco ainda. Mas o roadmap já prevê outras fontes/famílias
(Windows, VMware, AWS Security Pillar, OWASP). No dia que uma segunda
família de checks existir, rodar checks de Windows contra um alvo Linux
(ou vice-versa) sem filtro nenhum vai gerar resultado sem sentido — por
exemplo, tudo FAIL, porque `/etc/shadow` simplesmente não existe no alvo.

A proposta de 2 etapas é exatamente a peça que falta pra isso não quebrar
quando a segunda família de checks chegar:

1. **Scan/identificação** — o que já existe (`collect_facts()` +
   `document_slug_for_os()`), possivelmente exposto como um passo próprio
   em vez de embutido dentro de `run_assessment()`.
2. **Seleção de payload** — nova: usar o SO/família detectado pra escolher
   **qual subconjunto de CHECKS** de fato avaliar, em vez de rodar a lista
   inteira sempre. Hoje `CHECKS` é uma lista única; passaria a precisar de
   agrupamento por família (Debian/Ubuntu, Windows, VMware, ...) com
   `run_assessment()` filtrando por esse grupo antes do loop de avaliação.

Isso também conecta com a preocupação nº 1: numa frota real de múltiplos
dispositivos heterogêneos, fazer a identificação barata primeiro e só
depois decidir o que despachar pra cada um é o padrão natural — em vez de
assumir que todo alvo entende o mesmo payload.
