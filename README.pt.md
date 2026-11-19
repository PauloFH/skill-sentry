[English](README.md) | **Português** | [Español](README.es.md) | [中文](README.zh.md)

🌐 https://paulofh.github.io/skill-sentry/

# skill-sentry

Um plugin do Claude Code sem dependências que audita os plugins, skills, hooks e servidores MCP instalados na sua máquina em busca de comportamento malicioso, reforça as configurações do Claude Code e vigia chamadas de ferramentas arriscadas em tempo de execução.

Skills e plugins de terceiros são código e instruções que rodam com os seus privilégios. Um malicioso pode roubar credenciais, instalar um minerador de criptomoedas, abrir uma porta dos fundos ou instruir o modelo, de forma discreta, a fazer isso por ele. O skill-sentry oferece uma segunda olhada rápida, local e legível.

- **Auditar** (`/skill-sentry:audit`): um scanner estático lê a configuração de cada plugin, skill, hook e servidor MCP instalado, pontua cada componente e reporta os achados por categoria: miner, rce, secret, exfil, persistence, permissions, destructive, obfuscation, injection, supply, skill, config.
- **Reforçar** (`/skill-sentry:harden`): revisa o seu `settings.json` e aplica somente os ajustes que você aprovar, um por um.
- **Guarda** (hook PreToolUse): inspeciona as chamadas de ferramentas no momento em que acontecem e bloqueia ou pergunta antes das perigosas.

Requer Node 18 ou superior. Sem dependências npm.

## Modelo de ameaça e limites honestos

O skill-sentry é um segundo par de olhos, não um escudo. Leia isto antes de confiar nele.

- Ele **não é um antivírus nem um sandbox**. Não isola nada e não desfaz estragos.
- O scanner faz **somente análise estática**. Lê arquivos com regras de padrões e nunca os executa. Código suficientemente criativo pode escapar de regras de padrões.
- Ele **não enxerga os hooks de outros plugins enquanto executam**. Só lê a configuração e os scripts deles.
- Ele **não consegue inspecionar código obtido em tempo de execução** (por exemplo, um pacote iniciado com tag de versão flutuante, ou um script baixado e depois executado). Só consegue sinalizar que isso acontece.
- A guarda é um filtro de melhor esforço. **Shell suficientemente ofuscado pode contorná-la.** Ela inspeciona comandos, caminhos e URLs; em Write e Edit olha apenas o caminho de destino, nunca o conteúdo.
- Um relatório limpo não prova segurança. Um relatório ruim é motivo para olhar com mais atenção.

Medidas que valem a pena de qualquer forma: fixar as versões dos plugins, evitar atualização automática de marketplaces de terceiros, ler o que você instala e aplicar as configurações de `/skill-sentry:harden`.

## Instalação

```
/plugin marketplace add PauloFH/skill-sentry
/plugin install skill-sentry@skill-sentry
```

Este repositório é ao mesmo tempo o plugin e o seu próprio marketplace.

## Uso

### Auditar os componentes instalados

```
/skill-sentry:audit
```

O Claude executa o scanner e apresenta um resumo (componentes por veredito, o que mudou desde a baseline), cada problema encontrado ao ler as configurações e uma tabela para cada componente que não seja `ok`. O veredito do scanner nunca é rebaixado: se o Claude discordar, ele acrescenta a própria opinião em uma coluna separada "Claude assessment", e você vê sempre as duas. Texto copiado dos arquivos analisados é tratado como dado não confiável e nunca é seguido como instrução.

Os vereditos vêm de uma pontuação: achados críticos valem 40, altos 15, médios 5. Cada regra conta uma vez por componente, na sua maior severidade, e a pontuação é limitada a 100.

| Pontuação | Veredito |
| --- | --- |
| abaixo de 10 | ok |
| 10 a 29 | review |
| 30 a 59 | suspicious |
| 60 ou mais | malicious |

Qualquer achado crítico eleva o veredito para pelo menos `suspicious`. Combinações escalam dentro de um arquivo: exfiltração junto de acesso a segredos vira crítica, e ofuscação junto de achados de rce, exfil ou secret vira alta.

`/skill-sentry:audit` é o ponto de entrada normal. Para executar o script por conta própria, note que, num plugin instalado, os scripts ficam no diretório de instalação do plugin, `~/.claude/plugins/cache/skill-sentry/skill-sentry/<versão>/scripts/`; os caminhos abaixo são relativos a esse diretório (ou a um clone deste repositório).

Opções úteis (você pode pedi-las ao Claude ou executar o script por conta própria):

```
node scripts/scan.mjs --json
node scripts/scan.mjs --path <dir>
node scripts/scan.mjs --component <id>
node scripts/scan.mjs --diff-only
node scripts/scan.mjs --update-baseline
```

- `--path <dir>` examina uma única pasta, para você verificar uma skill ou plugin **antes de instalar**. Não lê nem grava a baseline.
- `--component <id>` analisa um componente instalado.
- `--diff-only` mostra apenas os componentes adicionados ou alterados desde a baseline. O primeiro scan completo cria a baseline automaticamente.
- `--update-baseline` aceita o estado atual como a nova baseline (o Claude pergunta antes).

### Reforçar as suas configurações

```
/skill-sentry:harden
```

O Claude lista cada recomendação, explica por que ela importa e só aplica uma depois do seu "sim" explícito para aquele item. Um backup com data e hora do `settings.json` é feito antes de qualquer alteração, e o auxiliar mescla somente o que você aprovou.

| Id | O que faz |
| --- | --- |
| `ask-curl` | Pergunta antes de executar curl |
| `ask-wget` | Pergunta antes de executar wget |
| `deny-ssh-read` | Nega a leitura de `~/.ssh` |
| `deny-aws-read` | Nega a leitura de `~/.aws` |
| `ask-env-read` | Pergunta antes de ler arquivos `.env` |
| `disable-skill-shell` | Desativa a execução de shell inline dentro de skills (contrapartida: plugins oficiais que coletam contexto assim deixarão de fazê-lo) |

Mais dois itens são exibidos apenas como informação e nunca são aplicados: revisar marketplaces de terceiros (`third-party-autoupdate`) e restringir marketplaces e hooks por meio de configurações gerenciadas (`managed-settings`).

### Guarda em tempo de execução

A guarda é um hook PreToolUse instalado com o plugin. Ela observa chamadas de Bash, PowerShell, Read, Write, Edit, NotebookEdit, Grep, Glob, WebFetch e ferramentas MCP.

| Decisão | Quando |
| --- | --- |
| deny | Uma regra crítica casa (por exemplo, pipes de baixar e executar, shells reversos, execução de mineradores de criptomoedas, apagamento de disco ou do diretório pessoal). Sempre bloqueado, a menos que você tenha colocado aquele comando exato na allowlist. |
| ask | Uma regra de risco alto casa e uma skill ou plugin é a origem provável da chamada. Também sempre para escritas no diretório de dados ou de instalação do próprio skill-sentry, comandos de shell que mencionam esses diretórios e escritas por formas incomuns de caminho do Windows (caminhos de dispositivo, caminhos UNC, nomes curtos 8.3, streams NTFS, ponto ou espaço no final). |
| log | Uma regra de risco alto casa, mas nenhuma skill ou plugin é a origem provável (você mesmo digitou). Registrado em `guard.log`, sem interrupção. |

Se a própria guarda falhar, ela falha aberta: grava uma linha em `guard.log` e deixa a chamada seguir, em vez de quebrar a sua sessão.

A auditoria padrão (`scan.mjs` só com `--json` e/ou `--diff-only`) e o `harden.mjs check` rodam sem pedir confirmação. Auditorias com `--path` ou `--component`, atualizações da baseline (`--update-baseline`), entradas na allowlist (`--allow`) e o `harden.mjs apply` mostram um pedido de confirmação de propósito: aprove-o para a ação com que você já concordou. Na ferramenta Bash, escreva o caminho do script com barras normais (`C:/Users/...`).

### Allowlist

Se um achado for um falso positivo conhecido, libere-o um achado por vez:

```
node scripts/scan.mjs --allow <componentId> <ruleId> <file> --reason "why"
```

Uma entrada fica atrelada ao sha256 daquele arquivo, então **deixa de valer assim que o arquivo muda**. Entradas que deixam passar um comando bloqueado são comparações de string exata. O Claude só executa isso depois que você disser sim.

Se o comando `skillspector` estiver instalado, a auditoria pode oferecer uma segunda opinião com ele. O skill-sentry nunca o instala.

## Dados e privacidade

- **Sem chamadas de rede e sem telemetria.** Tudo roda localmente.
- Ele grava somente em `~/.claude/skill-sentry/`: `baseline.json`, `allowlist.json`, `guard.log` e `reports/`. A única exceção é o `harden`, que edita o seu `settings.json` após aprovação, com backup.
- Variáveis de ambiente (principalmente para testes): `SKILL_SENTRY_DATA_DIR` (diretório de dados), `SKILL_SENTRY_CLAUDE_HOME` (padrão `~/.claude`), `SKILL_SENTRY_HOME_DIR` (de onde `~/.claude.json` é lido).

## Validação

Testado em uma instalação real do Windows 11 com 11 plugins (65 componentes); os plugins oficiais da Anthropic recebem ok ou review. O projeto tem 197 testes automatizados.

## Créditos e inspiração

- CybeDefend, ["Are Claude Code skills safe?"](https://www.cybedefend.com/blog/are-claude-code-skills-safe)
- O estudo "Agent Skills in the Wild" (janeiro de 2026)
- NVIDIA SkillSpector, um scanner complementar (`skillspector scan <dir> --no-llm`). Use-o junto com o skill-sentry para uma segunda opinião.

## Licença

MIT. Veja [LICENSE](LICENSE).
