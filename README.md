# From Prompt to Payload — Artefatos do Experimento

Este é o repositório onde estão armazenados os artefatos gerados pelos modelos de linguagem avaliados (Grok, DeepSeek e Gemini) no experimento de duplo uso descrito no artigo *Do Prompt ao Payload: Contorno de Recusa via Instrução de Sistema e Validação de Artefatos de Cibersegurança Gerados por LLMs* (RITA, 2026). Os artefatos — ofensivos (exploração/exfiltração) e defensivos (segmentação) — estão organizados por modelo na pasta `artifacts/`, acompanhados das evidências de execução.

> ⚠️ **Uso responsável.** Material para pesquisa acadêmica. A CVE-2017-5638 é pública e corrigida desde 2017. Ver `ETHICS.md`.

## Conteúdo

- `artifacts/` — artefatos gerados pelos modelos (grok, deepseek, gemini) e evidências
- `topology/` — topologia da rede do laboratório
- `ETHICS.md` — uso responsável e escopo ético

## Abrir o laboratório (OVA)

O ambiente completo, já montado, é distribuído como imagem **OVA** no Zenodo (DOI: [10.5281/zenodo.24508129](https://doi.org/10.5281/zenodo.24508129)).

1. **Importe a OVA** no VirtualBox (**Arquivo → Importar Appliance**). Mantenha a VM isolada/offline — em **Configurações → Rede**, desconecte o adaptador.
2. **Inicie a VM** e entre com `researcher` / `genai2026`.
3. **Suba o CORE e o laboratório** num terminal:

   ```bash
   sudo systemctl start core-daemon   # senha do sudo: genai2026
   core-gui &
   ```

   Na janela do CORE: **File → Open** → `GenAI_Testbed.xml` → **play** (iniciar a sessão). Em seguida:

   ```bash
   bash ~/lab/start-lab.sh   # recria contêiner, ponte veth e dados; idempotente (reset)
   ```

4. **Valide** no nó `external` (duplo-clique nele no CORE):

   ```bash
   curl -m5 http://10.0.1.10:8080/
   ```

   Deve retornar a página do *Struts2 Showcase – Fileupload sample* (HTTP 200).

## Como citar

> Cristofolini, A. M.; Marques José, D. A. *Do Prompt ao Payload: Contorno de Recusa via Instrução de Sistema e Validação de Artefatos de Cibersegurança Gerados por LLMs.* Revista de Informática Teórica e Aplicada (RITA), 2026.
