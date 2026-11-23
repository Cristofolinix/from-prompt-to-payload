# Uso responsável e escopo ético

Este repositório é o **pacote de reprodutibilidade** de um estudo acadêmico sobre o
**duplo uso de modelos de linguagem (LLMs) em segurança cibernética**, que acompanha o
artigo *Do Prompt ao Payload: Hierarquia de Instruções, Contorno de Salvaguardas e a
Validação de Artefatos Gerados por Modelos de Linguagem na Segurança Cibernética* (RITA, 2026).

## Finalidade

O material existe para **permitir a verificação independente** dos resultados relatados no
artigo — nada mais. Ele documenta um experimento conduzido inteiramente em um **laboratório
isolado**, construído pelo autor, que abstrai a cadeia do incidente **Equifax (2017)**.

## Garantias do ambiente

- **Laboratório totalmente isolado**, sem conexão com sistemas reais ou de terceiros. A
  máquina virtual de reprodução deve ser executada **offline**.
- **Alvo público e já corrigido:** a vulnerabilidade reproduzida é a **CVE-2017-5638**
  (Apache Struts / S2-045), divulgada e corrigida desde 2017 e distribuída pelo projeto
  público Vulhub. Nenhuma técnica inédita ou *zero-day* é introduzida.
- **Dados fictícios:** todas as credenciais, arquivos de clientes e *flags* são inventados e
  rotulados como tal. Nenhum dado pessoal real está presente.

## Limites de uso

- Os artefatos ofensivos deste repositório **não devem ser executados contra nenhum sistema
  que você não possua ou não esteja explicitamente autorizado a testar.** Usá-los fora de um
  ambiente controlado e autorizado pode ser ilegal.
- Os artefatos foram **gerados pelos modelos avaliados** e são publicados *verbatim* como
  objeto de estudo — não como ferramentas a serem aperfeiçoadas ou operacionalizadas.
- As **configurações de *jailbreak*** usadas no experimento **não são redistribuídas aqui**;
  o artigo apenas referencia o repositório público de origem, e este pacote não as inclui.

## Divulgação

A CVE é pública e corrigida; o estudo não divulga nenhuma vulnerabilidade nova. O objetivo é
defensivo: evidenciar, de forma mensurável e reproduzível, por que a contenção do uso
malicioso de LLMs é estruturalmente difícil, para informar a comunidade de segurança.

Em caso de dúvida sobre o uso apropriado deste material, entre em contato com os autores
(ver `CITATION.cff`).
