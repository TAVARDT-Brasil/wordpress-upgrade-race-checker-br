<p align="center">
  <a href="https://ag.tavardt.com/br/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Central de Hardening & Auditoria WordPress Upgrade Race Condition

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-brasil.github.io/wordpress-upgrade-race-checker-br/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Vulnerability](https://img.shields.io/badge/Vulnerability-Race%20Condition-red.svg)](https://tavardt-brasil.github.io/wordpress-upgrade-race-checker-br/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Especificação técnica de engenharia defensiva, modelos de configuração para produção e utilitário determinístico de auditoria CLI para neutralização da vulnerabilidade de Condição de Corrida e Execução Remota de Código (RCE) no processo de atualização do WordPress.

***

## Resumo Técnico: A Falha de Condição de Corrida no Upgrade

O WordPress gerencia mais de 40 por cento da web global. Durante atualizações do núcleo, temas ou plugins, o sistema descompacta arquivos ZIP temporários em um diretório intermediário antes de mover os arquivos para seus caminhos finais.

Por padrão, essa descompactação ocorre na pasta `wp-content/upgrade/`, localizada diretamente na raiz acessível da web (DocumentRoot).

Quando servidores web permitem a execução de scripts PHP em pastas de conteúdo, um invasor pode disparar arquivos recém-descompactados durante a janela de extração:
* O invasor monitora ou provoca uma rotina de atualização no alvo.
* Arquivos PHP temporários tornam-se executáveis antes da validação final de permissões.
* Requisições HTTP diretas a esses arquivos disparam Execução Remota de Código (RCE) com os privilégios do usuário do servidor web (`www-data` ou `nginx`).

Este repositório fornece configurações homologadas para servidores de produção, modelos de isolamento perimetral e um utilitário determinístico em Python (`audit_wp_race.py`) para validação técnica da infraestrutura.

***

## Superfícies Críticas de Ataque em Diretórios do WordPress

### 1. O Caminho Público de Extração `wp-content/upgrade/`
A vulnerabilidade principal decorre do uso de pastas de descompressão acessíveis publicamente via HTTP:
* **Janela de Exposição:** Em servidores compartilhados ou com alta carga, a extração de pacotes grandes leva vários segundos.
* **Vetor de Exploração:** O atacante emite rajadas concorrentes de requisições HTTP para os arquivos em processo de extração.
* **Diretriz Defensiva:** Bloquear todo o acesso HTTP direto à pasta `wp-content/upgrade/` e mover a pasta temporária para fora do DocumentRoot.

### 2. Execução Irrestrita de PHP em Pastas de Conteúdo
Muitos servidores web repassam qualquer requisição terminada em `.php` para o FastCGI sem validar a pasta de origem:
* **Janela de Exposição:** Pastas como `uploads` e `upgrade` precisam de permissão de escrita para gerenciar arquivos de mídia e atualizações.
* **Vetor de Exploração:** A combinação de permissão de escrita no sistema de arquivos com execução de scripts cria um risco imediato de execução arbitrária.
* **Diretriz Defensiva:** Bloquear explicitamente a execução de scripts PHP nas pastas `uploads`, `upgrade`, `languages` e `mu-plugins` diretamente no servidor web.

### 3. Listagem de Diretórios Ativa (Directory Listing / Index Of)
Servidores com configuração padrão que não desativam a listagem de arquivos revelam o conteúdo das pastas:
* **Janela de Exposição:** Invasores podem visualizar em tempo real os nomes de arquivos temporários descompactados durante uma atualização.
* **Diretriz Defensiva:** Desativar a diretiva de listagem automática de diretórios de forma global na configuração do servidor.

***

## Modelos de Mitigação Defensiva em Produção

Aplique estas configurações testadas para proteger servidores web em produção:

### 1. Configuração para Nginx (`nginx.conf`)
Bloqueia o acesso direto à pasta de upgrade e proíbe execução de PHP em pastas de conteúdo:

```nginx
# 1. Bloquear acesso direto a pasta de upgrade temporario
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

# 2. Impedir execucao de PHP em pastas de conteudo estatico
location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### 2. Configuração para Apache (`.htaccess`)
Insira esta regra nos arquivos `.htaccess` dentro de `/wp-content/upgrade/` e `/wp-content/uploads/`:

```apache
# Bloquear execucao de qualquer extensao de script
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>

# Desativar listagem de diretorios
Options -Indexes
```

### 3. Configuração no WordPress (`wp-config.php`)
Move os arquivos temporários para fora do DocumentRoot e restringe alterações no painel:

```php
/* Mover pasta temporaria do WordPress para fora da raiz web */
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');

/* Restringir edicao e modificacao de arquivos pelo painel */
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### 4. Regra de Proteção Perimetral no Cloudflare WAF
Regra de borda para descarte imediato de requisições maliciosas:

```text
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
Acao: Block (Descartar conexao imediatamente)
```

***

## Ferramenta Oficial de Auditoria CLI

Navegadores web operam sob restrições rigorosas de sandbox e políticas de CORS que impedem testes de socket de baixo nível e leitura livre de cabeçalhos. Para viabilizar avaliações técnicas reproduzíveis e sem telemetria, a TAVARDT fornece um utilitário em Python para terminais de operação e pipelines de validação contínua.

### Mecanismo de Diagnóstico Determinístico

O utilitário (`audit_wp_race.py`) executa um fluxo de análise estruturado:
* **Higienização de Entrada & Conectividade:** Valida o formato da URL, normaliza protocolos e confirma a conectividade com o host.
* **Fingerprinting de WordPress:** Confirma a presença da plataforma por rotas da API REST, assets canônicos e telas de autenticação.
* **Detecção de Roteador Catch-All:** Distingue respostas reais de erro 403/404 de redirecionamentos genéricos de Single Page Applications.
* **Sondagem de Rotas Críticas:** Inspeciona `/wp-content/upgrade/` e rotas de teste PHP para verificar o bloqueio pelo servidor.
* **Pontuação Automatizada:** Emite uma nota técnica variando de 100 (Blindado) a 25 (Vulnerável).

### Instruções de Execução

Execute a ferramenta determinística diretamente contra o domínio WordPress alvo:

```bash
# 1. Obter o script oficial do repositorio
curl -sO https://raw.githubusercontent.com/TAVARDT-Brasil/wordpress-upgrade-race-checker-br/main/audit_wp_race.py

# 2. Executar auditoria direta contra o dominio
python audit_wp_race.py https://seu-dominio.com

# 3. Gerar resultado em formato JSON
python audit_wp_race.py https://seu-dominio.com -j
```

***

## Perguntas Frequentes de Arquitetura (FAQ Técnico)

### 1. O que provoca a vulnerabilidade de condição de corrida na atualização do WordPress?
Durante rotinas de atualização do core, temas ou plugins, o WordPress descompacta pacotes ZIP na pasta temporária `wp-content/upgrade/` antes de mover os arquivos finais. Se o servidor web permitir execução de scripts em pastas de conteúdo, um atacante pode requisitar arquivos PHP descompactados nessa janela de tempo, obtendo Execução Remota de Código com os privilégios do servidor.

### 2. Por que o bloqueio de acesso HTTP à pasta wp-content/upgrade é fundamental?
A pasta `wp-content/upgrade/` foi projetada unicamente para processos locais do PHP no servidor. Clientes externos na web não possuem necessidade legítima de acessar esse diretório, e permitir requisições públicas expõe arquivos transitórios a explorações automáticas.

### 3. De que forma mover a constante WP_TEMP_DIR neutraliza essa vulnerabilidade?
Definir `WP_TEMP_DIR` fora do DocumentRoot (por exemplo, em `/var/www/tmp/` em vez de `/wp-content/upgrade/`) impede que arquivos descompactados sejam acessíveis via web. Mesmo que um atacante descubra nomes de arquivos temporários, o servidor web não poderá servi-los nem executá-los por estarem fora da raiz pública.

### 4. Como Nginx e Apache impedem a execução de scripts em pastas de conteúdo?
O Nginx utiliza blocos de localização com expressões regulares que retornam HTTP 403 para qualquer requisição com terminação `.php` nas pastas de conteúdo. No Apache, utiliza-se a diretiva `<FilesMatch>` dentro de arquivos `.htaccess` combinada com `Options -Indexes` para proibir tanto a execução quanto a listagem de arquivos.

### 5. A ferramenta de auditoria em Python causa lentidão ou instabilidade no site analisado?
Não. O utilitário opera de forma passiva, emitindo apenas requisições HTTP GET e HEAD convencionais para avaliar os códigos de retorno. Ele verifica se as rotas retornam HTTP 403 ou 404 em vez de HTTP 200 aberto, diagnosticando a postura de segurança sem modificar arquivos ou registros do banco de dados.

***

## Conformidade Regulatória e Padrões de Segurança

Arquitetura defensiva e controles técnicos alinhados à Lei Geral de Proteção de Dados (LGPD, Lei nº 13.709/2018), aos requisitos de segurança da informação do NIST SP 800-53 e às recomendações de segurança do CIS Controls v8.

***

## 4. Consulta Online

Acesse o Guia Interativo em produção:  
[https://tavardt-brasil.github.io/wordpress-upgrade-race-checker-br/](https://tavardt-brasil.github.io/wordpress-upgrade-race-checker-br/)

***

## Links Úteis

* **Portal Corporativo:** https://ag.tavardt.com/br/
* **Suíte de Diagnósticos:** https://tools.tavardt.com/br/
* **Contato Técnico:** https://ag.tavardt.com/br/contato/

***

### Licença
Distribuído sob a Licença MIT. Consulte o arquivo [LICENSE](LICENSE) para obter detalhes completos.

***

© 2026 TAVARDT. Todos os direitos reservados.
