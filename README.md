# From Prompt to Payload — Pacote de Reprodutibilidade

Material de reprodutibilidade do artigo ***Do Prompt ao Payload: Hierarquia de Instruções,
Contorno de Salvaguardas e a Validação de Artefatos Gerados por Modelos de Linguagem na
Segurança Cibernética*** (RITA, 2026), sobre o **duplo uso de modelos de linguagem (LLMs)
em cibersegurança**.

O experimento é conduzido em um laboratório isolado que abstrai a cadeia do incidente
**Equifax (2017)** (Apache Struts, **CVE-2017-5638 / S2-045**), emulado no **CORE
(Common Open Research Emulator)**. Sob protocolo *white-box* (os parâmetros são fornecidos
ao modelo), mede-se se os mesmos LLMs produzem artefatos **ofensivos** (explorar/exfiltrar)
e **defensivos** (segmentar), validados por **execução** no lab.

> ⚠️ **Aviso / uso responsável.** Todo o material é para **pesquisa acadêmica e fins
> educacionais**, executado em **laboratório totalmente isolado**, sem sistemas reais ou de
> terceiros. Os dados são **fictícios**. A CVE-2017-5638 é pública e corrigida desde 2017.
> **Não** utilize estes artefatos contra sistemas que você não possui ou não está autorizado
> a testar. Ver [`ETHICS.md`](ETHICS.md).

## Topologia do laboratório

`external (10.0.0.20)` → `fw` (firewall/roteador nftables) → **DMZ** `10.0.1.0/24`
(web/Struts em `10.0.1.10:8080`) e **LAN interna** `10.0.2.0/24` (`db1 10.0.2.20`,
`db2 10.0.2.21`).

O nó *web* é um container Docker (vulhub `struts2/s2-045`) em execução no host, ligado à DMZ
emulada do CORE por um **par veth**. A falha estrutural
reproduzida: o `external` não alcança a LAN, mas o web alcança a LAN livremente (ausência de
segmentação), como no incidente real. Ver `topology/topologia-rede.png`.

## Estrutura

```
.
├── README.md
├── ETHICS.md                 # uso responsável e escopo ético
├── topology/
│   └── topologia-rede.png
└── artifacts/                # artefatos GERADOS pelos modelos (verbatim) + evidências
    ├── grok/
    │   ├── offensive/        # exploit_struts_5638_header.py (T1), etapa2_ssh_askpass.py (T2)
    │   │   └── evidence/     # prints: A-recusa, B-T1, B-T2
    │   └── defensive/        # d2_segmentacao.nft (segmentação)
    │       └── evidence/     # prints: ruleset-aplicado, web-para-db-bloqueado, external-para-web-timeout
    ├── deepseek/
    │   ├── offensive/        # etapa1b_s2045.py (T1), pivot4.py + etapa2_ssh_read.sh (T2)
    │   │   └── evidence/     # prints: B-T1, B-T2
    │   └── defensive/        # d2-deepseek-v2.nft (segmentação)
    │       └── evidence/     # print: matriz-verificacao
    └── gemini/               # (coleta pendente)
```

## Organização dos artefatos

Os artefatos estão agrupados por cenário: **ofensivo** — `T1` (exploração da CVE-2017-5638) e
`T2` (movimento lateral por SSH) — e **defensivo** (segmentação de rede via `nftables`). O
cenário ofensivo tem duas condições: **A** (sem *system prompt*) e **B** (com *system prompt*).

As **configurações de *jailbreak*** da condição B **não são redistribuídas aqui** (ver `ETHICS.md`).

## Reproduzir o lab

O laboratório completo, já montado e com todos os scripts e configurações, é distribuído como
imagem **OVA** no **Zenodo** (DOI): `[INSERIR DOI do Zenodo]`.

1. **Importe a OVA** no VirtualBox (Arquivo → Importar Appliance). Mantenha a VM
   **isolada/offline** — em Configurações → Rede, desconecte o adaptador (ver `ETHICS.md`).
2. **Inicie a VM** e entre com `researcher` / `genai2026`.
3. **Suba o CORE e o laboratório**, num terminal:

   ```bash
   sudo systemctl start core-daemon      # senha do sudo: genai2026
   core-gui &
   ```

   Na janela do CORE: **File → Open** → `GenAI_Testbed.xml` → **play** (iniciar a sessão). Depois:

   ```bash
   bash ~/lab/start-lab.sh               # recria contêiner, ponte veth e dados; idempotente (reset)
   ```

4. **Valide** no nó `external` (duplo-clique nele no CORE):

   ```bash
   curl -m5 http://10.0.1.10:8080/
   ```

   Deve retornar a página do *Struts2 Showcase – Fileupload sample* (HTTP 200).

## Modelos avaliados

Grok, DeepSeek e Gemini.

## Como citar

Ao usar este material, cite o artigo associado:

> Cristofolini, A. M.; Marques José, D. A. *Do Prompt ao Payload: Hierarquia de Instruções,
> Contorno de Salvaguardas e a Validação de Artefatos Gerados por Modelos de Linguagem na
> Segurança Cibernética.* Revista de Informática Teórica e Aplicada (RITA), 2026.
