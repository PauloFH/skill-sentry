[English](README.md) | **Português** | [Español](README.es.md) | [中文](README.zh.md)

🌐 https://paulofh.github.io/skill-sentry/

# skill-sentry

Um plugin do Claude Code sem dependências que audita os plugins, skills, hooks e servidores MCP instalados na sua máquina em busca de comportamento malicioso, reforça as configurações do Claude Code e vigia chamadas de ferramentas arriscadas em tempo de execução.

Skills e plugins de terceiros são código e instruções que rodam com os seus privilégios. Um malicioso pode roubar credenciais, instalar um minerador de criptomoedas, abrir uma porta dos fundos ou instruir o modelo, de forma discreta, a fazer isso por ele. O skill-sentry oferece uma segunda olhada rápida, local e legível.

- **Auditar** (`/skill-sentry:audit`): um scanner estático lê a configuração de cada plugin, skill, hook e servidor MCP instalado, pontua cada componente e reporta os achados por categoria: miner, rce, secret, exfil, persistence, permissions, destructive, obfuscation, injection, supply, skill, config.
- **Reforçar** (`/skill-sentry:harden`): revisa o seu `settings.json` e aplica somente os ajustes que você aprovar, um por um.
- **Guarda** (hook PreToolUse): inspeciona as chamadas de ferramentas no momento em que acontecem e bloqueia ou pergunta antes das perigosas.

Requer Node 18 ou superior. Sem dependências npm.

Desde a 0.1.1 ele também funciona no OpenAI Codex: veja [Suporte ao Codex](#suporte-ao-codex).

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

Este repositório é ao mesmo tempo o plugin e o seu próprio marketplace. O marketplace instala a partir de `main`, e `main` só recebe mudanças que passaram na CI (a suíte de testes no Linux, no Windows e no macOS, mais verificações de instalação com os CLIs reais do Claude Code e do Codex).

Instale a auditoria com `npx skills add PauloFH/skill-sentry` (Claude Code, Codex e outros agentes). A guarda em tempo de execução e o harden precisam do plugin. Existem skills com nomes parecidos, então use exatamente a origem `PauloFH/skill-sentry`. Veja [skills.sh](#skillssh).

## Uso

### Auditar os componentes instalados

```
/skill-sentry:audit
```

O Claude executa o scanner e apresenta um resumo (componentes por veredito, o que mudou desde a baseline), cada problema encontrado ao ler as configurações e uma tabela para cada componente que não seja `ok`. O veredito do scanner nunca é rebaixado: se o Claude discordar, ele acrescenta a própria opinião em uma coluna separada "Agent assessment", e você vê sempre as duas. Texto copiado dos arquivos analisados é tratado como dado não confiável e nunca é seguido como instrução.

Os vereditos vêm de uma pontuação: achados críticos valem 40, altos 15, médios 5. Cada regra conta uma vez por componente, na sua maior severidade, e a pontuação é limitada a 100.

| Pontuação | Veredito |
| --- | --- |
| abaixo de 10 | ok |
| 10 a 29 | review |
| 30 a 59 | suspicious |
| 60 ou mais | malicious |

Qualquer achado crítico eleva o veredito para pelo menos `suspicious`. Combinações escalam dentro de um arquivo: exfiltração junto de acesso a segredos vira crítica, e ofuscação junto de achados de rce, exfil ou secret vira alta.

`/skill-sentry:audit` é o ponto de entrada normal. Para executar o script por conta própria, note que, num plugin instalado, os scripts ficam no diretório de instalação do plugin, `~/.claude/plugins/cache/skill-sentry/skill-sentry/<versão>/`; os caminhos abaixo são relativos a esse diretório (ou a um clone deste repositório).

Opções úteis (você pode pedi-las ao Claude ou executar o script por conta própria):

```
node skills/audit/scripts/scan.mjs --json
node skills/audit/scripts/scan.mjs --path <dir>
node skills/audit/scripts/scan.mjs --component <id>
node skills/audit/scripts/scan.mjs --diff-only
node skills/audit/scripts/scan.mjs --update-baseline
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
| ask | Uma regra de risco alto casa e uma skill ou plugin é a origem provável da chamada. Também sempre para escritas no diretório de dados ou de instalação do próprio skill-sentry (ou em qualquer outra cópia instalada do skill-sentry, como a instalada para o Codex), comandos de shell que mencionam esses diretórios e escritas por formas incomuns de caminho do Windows (caminhos de dispositivo, caminhos UNC, nomes curtos 8.3, streams NTFS, ponto ou espaço no final). |
| log | Uma regra de risco alto casa, mas nenhuma skill ou plugin é apontado como origem provável. Registrado em `guard.log`, sem interrupção. |

Se a própria guarda falhar, ela falha aberta: grava uma linha em `guard.log` e deixa a chamada seguir, em vez de quebrar a sua sessão.

A auditoria padrão (`scan.mjs` só com `--json` e/ou `--diff-only`) e o `harden.mjs check` rodam sem pedir confirmação. Auditorias com `--path` ou `--component`, atualizações da baseline (`--update-baseline`), entradas na allowlist (`--allow`) e o `harden.mjs apply` mostram um pedido de confirmação de propósito: aprove-o para a ação com que você já concordou. Na ferramenta Bash, escreva o caminho do script com barras normais (`C:/Users/...`).

### Allowlist

Se um achado for um falso positivo conhecido, libere-o um achado por vez:

```
node skills/audit/scripts/scan.mjs --allow <componentId> <ruleId> <file> --reason "why"
```

Uma entrada fica atrelada ao sha256 daquele arquivo, então **deixa de valer assim que o arquivo muda**. Entradas que deixam passar um comando bloqueado são comparações de string exata. O Claude só executa isso depois que você disser sim.

Se o comando `skillspector` estiver instalado, a auditoria pode oferecer uma segunda opinião com ele. O skill-sentry nunca o instala.

## Suporte ao Codex

A versão 0.1.1 do skill-sentry leva a mesma auditoria e a mesma guarda para o OpenAI Codex, além de um harden que só recomenda.

### O que a auditoria cobre no Codex

- `config.toml`: configurações de aprovação e sandbox, servidores MCP, segredos literais, projetos confiáveis, a política de ambiente do shell
- arquivos de política de execução `rules/*.rules`
- plugins e os hooks que eles trazem, junto com o estado de confiança de cada hook
- servidores MCP
- skills, incluindo `~/.agents/skills`
- arquivos de instruções `AGENTS.md`
- o programa `notify`

Os diretórios do Codex no Windows e no WSL são detectados automaticamente. Escolha o que auditar com `--agent claude|codex|all` (padrão `all`), adicione um diretório com `--codex-home <dir>` (repetível) e pule o WSL com `--no-wsl`:

```
node skills/audit/scripts/scan.mjs --agent codex
node skills/audit/scripts/scan.mjs --agent all --codex-home <dir> --no-wsl
```

### Instalação no Codex

```
codex plugin marketplace add PauloFH/skill-sentry
codex plugin add skill-sentry@skill-sentry
```

Esta instalação a partir do repositório público do GitHub foi verificada no Codex do Windows e do WSL.

Depois, **inicie o Codex uma vez e só então confie no hook da guarda**. O Codex não executa um hook enquanto você não confiar nele, e ativar um plugin não faz o Codex confiar nos hooks dele. Na primeira vez que inicia depois da instalação, o Codex grava um arquivo de instalação na pasta do plugin, o que muda a impressão digital do hook. Por isso, confie no hook depois desse primeiro início: abra `/hooks` no Codex (ou "Review hooks" no app desktop), revise o hook do skill-sentry e confie nele. Até você fazer isso, a guarda não roda.

Em seguida, peça ao Codex que execute a auditoria do skill-sentry para ver o seu primeiro relatório. Isso foi verificado só no Codex do WSL. No Codex do Windows, pode ser preciso você aprovar os comandos de shell que ele executa.

### Guarda no Codex

Aqui a guarda também é um hook PreToolUse. O Codex não tem "ask", então ela só pode permitir ou negar. Os níveis são:

| Nível | Quando | Comportamento no Codex |
| --- | --- | --- |
| 1 | Uma regra crítica casa | deny |
| 2 | Uma regra alta de rce, exfil, miner ou destructive; um segredo e saída de rede no mesmo comando; uma chamada capaz de usar a rede depois que, antes na mesma sessão, uma chamada atribuída a uma skill ou plugin leu um segredo e foi liberada na nova tentativa | deny. Se era isso mesmo que você queria, execute você mesmo num terminal. |
| 3 | Qualquer outra regra alta com origem atribuída (uma skill ou plugin) | negado na primeira vez, com o motivo. Uma nova tentativa idêntica na mesma sessão, em até 10 minutos, é permitida uma vez. |
| 4 | Uma regra alta sem nenhuma skill ou plugin apontado como origem | só registrado |
| 5 | Escritas nos arquivos do próprio skill-sentry (qualquer cópia instalada) ou formas incomuns de caminho | deny |

Os patches do `apply_patch` também são inspecionados. A maioria dos patches que a guarda não consegue ler é negada: os que vêm de um arquivo ou de um pipe, ou que usam expansão de shell. Um comando de patch escondido atrás de shell dinâmico ou ofuscado (veja os limites abaixo) não é detectado.

### Limites no Codex

- O Codex não tem "ask": a guarda só pode permitir ou negar.
- Ela falha aberta: se o hook der erro ou passar do tempo limite do Codex (cerca de 5 segundos), a chamada roda.
- Hooks precisam de confiança (`/hooks`). A flag `dangerously-bypass-hook-trust` do Codex desliga essa proteção.
- Depois de uma atualização do plugin, o Codex marca o hook como `modified` e para de executá-lo até você confiar nele de novo em `/hooks`.
- A nova tentativa do nível 3 é confirmada pelo modelo, não por você.
- Entrada interativa enviada a um shell em execução (`write_stdin`) não passa pelo hook.
- Comandos que montam nomes ou caminhos em tempo de execução não são analisados: `eval`, variáveis, globs, comandos de uma linha de interpretador como `python -c`, ou um script escrito numa chamada e executado numa chamada seguinte.
- A atribuição de origem se perde quando mais de cerca de 1 MiB de saída vem depois da leitura da skill na sessão; a chamada passa a contar como nível 4.
- No WSL, se a sessão começar em `/mnt/c` e a sua toolchain de node (por exemplo, o mise) se recusar a iniciar ali, a guarda falha aberta. Comece a sessão em `/home/...`.
- O Codex do WSL e o do Windows mantêm dados separados do skill-sentry (taint, baseline, allowlist).
- Com o sandbox `workspace-write`, a auditoria precisa da sua aprovação para gravar o relatório em `~/.claude/skill-sentry`.
- Ler o `SKILL.md` do próprio skill-sentry por um comando de shell encadeado (`cd ... && cat ...`) pode ser negado. A leitura simples funciona.
- Mencionar um caminho `skill-sentry` solto num comando de shell ainda pode gerar um pedido de confirmação no Claude Code (autoproteção).

### Harden no Codex

```
node skills/audit/scripts/harden.mjs check --agent codex
```

O `check` sem flag continua só para o Claude. O harden do Codex **só recomenda**: o skill-sentry nunca edita arquivos do Codex. Cada recomendação traz um trecho para você aplicar por conta própria:

| Id | O que recomenda |
| --- | --- |
| `approval-sandbox` | Manter `approval_policy` e `sandbox_mode` nos padrões com sandbox e pedido de aprovação |
| `broad-allow-rules` | Trocar regras de allow da política de execução que terminam num shell ou interpretador por regras de prompt |
| `secrets-in-config` | Tirar segredos literais do `config.toml` e referenciar uma variável de ambiente |
| `env-excludes` | Manter as exclusões de ambiente padrão, para que variáveis com cara de segredo não sejam passadas aos comandos |
| `mcp-auto-approve` | Não aprovar servidores ou ferramentas MCP automaticamente |
| `approvals-reviewer` | Manter `approvals_reviewer` em `user` |
| `trusted-tmp-projects` | Não confiar em projetos que ficam em diretórios temporários |
| `hooks-enabled` | Manter os hooks do Codex ativos, para a guarda poder rodar |
| `trust-guard-hook` | Confiar no hook do skill-sentry em `/hooks` |

### Duas instalações, uma versão

Se o Claude Code e o Codex rodarem versões diferentes do skill-sentry, um scanner mais novo reconhece versões anteriores e mostra um aviso de "atualize as duas instalações". Um scanner mais antigo pode apontar a cópia mais nova como suspicious ou malicious (um falso positivo) até as duas instalações serem atualizadas. **Atualize as duas instalações** a cada versão nova.

### skills.sh

`npx skills add PauloFH/skill-sentry` instala só a auditoria, como a skill `skill-sentry-audit` (no Claude Code, `/skill-sentry-audit`). Ele não consegue instalar a guarda em tempo de execução (um hook) nem o harden: para esses, instale o plugin. Com `-g`, o CLI do skills copia a skill para `~/.agents/skills/skill-sentry-audit`, onde o Codex a lê, e liga `~/.claude/skills/skill-sentry-audit` a ela para o Claude Code. A CI verifica essa instalação com o CLI real do skills no Linux e no Windows. Sem uma ref, ele instala o branch padrão (`main`); fixe uma versão com `npx skills add PauloFH/skill-sentry#v<versão>` (por exemplo `#v0.2.0`). Instalações em `$CLAUDE_CONFIG_DIR/skills` (quando essa variável está definida) não são cobertas: o scanner e a guarda olham só `~/.claude/skills`.

Existem skills com nomes parecidos no skills.sh (por exemplo `skillsentry`). São outros projetos: use exatamente a origem `PauloFH/skill-sentry`.

Ao lado do plugin da mesma versão, todo scanner (do plugin ou avulso) reconhece as outras cópias como skill-sentry. A guarda deixa a auditoria avulsa rodar o seu scan e deixa o Codex ler o `SKILL.md` dela só quando essa pasta é uma cópia verificada da auditoria do próprio plugin. Qualquer outro comando nessa pasta pede confirmação (Claude Code) ou é negado (Codex), e o mesmo vale para esses dois numa cópia que a guarda não consegue verificar (uma versão mais nova que a do plugin, um build de desenvolvimento ou de PR, uma instalação com `--rename`) até as duas instalações coincidirem. Atualize as duas instalações a cada versão. Uma cópia instalada com outro nome via `--rename` tem o `SKILL.md` alterado, então os scanners deixam de reconhecê-la.

## Dados e privacidade

- **Sem chamadas de rede e sem telemetria.** Tudo roda localmente.
- Ele grava somente em `~/.claude/skill-sentry/`: `baseline.json`, `allowlist.json`, `guard.log` e `reports/`. A única exceção é o `harden`, que edita o seu `settings.json` após aprovação, com backup.
- Variáveis de ambiente (principalmente para testes): `SKILL_SENTRY_DATA_DIR` (diretório de dados), `SKILL_SENTRY_CLAUDE_HOME` (padrão `~/.claude`), `SKILL_SENTRY_HOME_DIR` (de onde `~/.claude.json` é lido), `SKILL_SENTRY_CODEX_HOME` (substitui o diretório padrão do Codex) e `SKILL_SENTRY_NO_WSL=1` (não procura diretórios do Codex dentro do WSL).

## Validação

Testado em uma instalação real do Windows 11 (68 componentes): 2 sinalizados. Um recebeu malicious: um plugin de orquestração de terceiros que inicia agentes com os pedidos de permissão desativados e aprova comandos automaticamente, poderoso por design, não malware. Outro recebeu review: scripts de teste que usam a flag de pular permissões. Todo o resto saiu ok. O projeto tem mais de 240 testes automatizados.

## Créditos e inspiração

- CybeDefend, ["Are Claude Code skills safe?"](https://www.cybedefend.com/blog/are-claude-code-skills-safe)
- O estudo "Agent Skills in the Wild" (janeiro de 2026)
- NVIDIA SkillSpector, um scanner complementar (`skillspector scan <dir> --no-llm`). Use-o junto com o skill-sentry para uma segunda opinião.

## Licença

MIT. Veja [LICENSE](LICENSE).
