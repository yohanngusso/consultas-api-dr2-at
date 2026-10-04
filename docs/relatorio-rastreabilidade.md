# Relatório de rastreabilidade (capstone)

Liga cada ameaça do threat model (Exercício 4) à categoria OWASP, ao finding que a evidenciou (leitura de código, teste, SAST ou ZAP), à correção no código e à evidência final.

## 1. Findings do OWASP ZAP

| Finding ZAP | Risco | CWE | OWASP 2021 | Ameaça | Correção | Estado na rodada 2 |
|---|---|---|---|---|---|---|
| 10202 Absence of Anti-CSRF Tokens | Médio | 352 | A01 | T-19 | `app/auth/csrf.py`, campo `csrf_token` em `templates/login.html` e `templates/agenda.html`, validação em `app/routes/web.py` | Resolvido |
| 90004 COEP / COOP / CORP ausentes | Baixo | 693 | A05 | T-13 | `CABECALHOS_DE_SEGURANCA` e COEP em `CabecalhosDeSegurancaMiddleware` (`app/middlewares.py`) | Resolvido |
| 10063 Permissions Policy ausente | Baixo | 693 | A05 | T-13 | `Permissions-Policy` em `CABECALHOS_DE_SEGURANCA` | Resolvido |
| 10029 Cookie Poisoning | Informativo | 565 | A08 | T-19 | `garantir_cookie_csrf` não regrava o cookie com valor vindo da requisição | Resolvido |
| 10096 Timestamp Disclosure | Baixo | 497 | A01 | T-12 | Falso positivo (claims do próprio token em `/auth/eu`); `IGNORE` justificado em `.zap/rules.tsv` | Aceito |
| 10049 Non-Storable / Storable Content | Informativo | 524 | A04 | T-13 | `Cache-Control: no-store` intencional; CSS estático cacheável sem dado sensível | Esperado |
| 100000 Client Error response | Informativo | 388 | - | T-01, T-04, T-09 | 401/403/404/422 são os controles de acesso e validação funcionando | Esperado |

## 2. Rastreabilidade ameaça → correção → evidência

| Ameaça | OWASP | Como foi evidenciada | Vulnerabilidade (CVSS) | Correção aplicada | Evidência final |
|---|---|---|---|---|---|
| T-01 BOLA em consultas | A01 | Leitura de código (Ex. 8, V1) e reprodução | V-01 (6.5) | `AutenticacaoJWTMiddleware`, `exigir_posse` + `consulta_legivel`, `GuardaAutorizacaoMiddleware` | `ex09-correcoes-antes-depois.txt`; `test_t01_*` |
| T-02 BOLA em pacientes | A01 | Busca do mesmo padrão (Ex. 9) | V-02 (4.3) | `paciente_legivel`; busca filtrada pelo responsável | `ex09`; `test_t02_*` |
| T-03 Escalada para admin | A01 | Teste do Ex. 6 | - | Escopo `admin` + `exigir_administrador` | `ex06`; `test_t03_*` |
| T-04 Token do laboratório | A01 | Contrato do parceiro (Ex. 7) | - | client_credentials, recorte de escopo, `aud` e rota exclusivos, saída sem PII | `ex07`; `test_t04_*` |
| T-05 Força bruta | A07 | Leitura de código (V5) | V-06 (7.4) | Rate limit 5/min + bloqueio por identidade | `ex10`; `test_t05_*` |
| T-06 JWT forjado | A02/A07 | Threat model | - | `algorithms=["HS256"]`, claims obrigatórias, papel conferido no banco | `test_t06_*` |
| T-07 Token expirado/audiência | A07 | Threat model | - | `exp` 15/10 min, `aud` por tipo, usuário recarregado | `test_t07_*` |
| T-08 Admin sem MFA | A07 | Leitura de código (V5) | V-07 (8.1) | Desafio MFA, `amr`, claim `mfa` exigida | `ex06`; `test_t08_*` |
| T-09 SQL injection | A03 | Leitura de código (V2), Bandit B608, Semgrep | V-03 (7.6) | Whitelist regex/enum + `select()` parametrizado | `ex09`, `ex11`; `test_t09_*` |
| T-10 XSS armazenado | A03 | Leitura de código (V3) | V-04 (7.6) | Autoescape sem `|safe`, CSP `script-src 'self'` | `tela-04` vs `tela-05`; `test_pagina_da_agenda_*` |
| T-11 Mass assignment | A04 | Leitura de código (V4) | V-05 (6.5) | `EntradaEstrita` com `extra="forbid"` | `ex09`; `test_t11_*` |
| T-12 Exposição excessiva | A04 | Ex. 2 e revisão do erro 422 | V-12 (4.3) | `response_model` por consumidor, CPF mascarado, handler 422 sem `input` | `ex02`; `test_resposta_*`, `test_erro_de_validacao_*` |
| T-13 Cabeçalhos | A05 | V6 e ZAP 90004/10063 | V-08 (4.2), V-13 (3.1) | `CabecalhosDeSegurancaMiddleware` | `ex10`; ZAP rodada 2; `test_t13_*` |
| T-14 CORS | A05 | V6 | V-09 (5.3) | Allowlist do `.env`, wildcard recusado | `ex10`; `test_t14_*` |
| T-15 Repúdio | A09 | Threat model | - | `RegistroAuditoria` gravado por `auditar()` | `ex09` (trilha); `test_t15_*` |
| T-16 DoS por volume | A04 | Threat model | - | Rate limit por tipo de rota, janela de 60 dias, tamanhos máximos | `ex10` |
| T-17 Credenciais no código | A07 | Semgrep (rodada 1 do gate) | V-10 (9.1) | `BaseSettings`, `SecretStr`, seed separado e desligado por padrão, exceção com prazo | `gate-rodada1.md` → `gate-rodada2.md`; `test_t17_*` |
| T-18 Dependência vulnerável | A06 | pip-audit | - | Versões fixadas, auditoria semanal, actions e imagens fixadas por SHA/digest | `pipeline/pip-audit.json` |
| T-19 Sessão e CSRF da recepção | A01/A07 | ZAP 10202 | V-11 (4.3) | Cookie HttpOnly/Secure/Strict/Path, token CSRF | ZAP rodada 2; `test_t19_*` |
| T-20 Alteração por não dono | A01 | Busca do padrão (Ex. 9) | - | `consulta_alteravel` | `test_t20_*` |
| T-21 Enumeração no login | A07 | Leitura de código (V5) | (em V-06) | Mensagem única, bcrypt contra hash fictício | `test_t21_*`, `test_login_de_email_inexistente_*` |
| T-22 Documentação exposta | A05 | Auditoria OpenAPI | - | `CLINICA_DOCS_ATIVOS` | `test_t22_*` |

## 3. Estado final

| Verificação | Resultado |
|---|---|
| pytest | 174 testes passando (`evidencias/ex12-ex13-suite-pytest.txt`) |
| Bandit | 0 alto; 1 médio coberto por exceção (router de demonstração); 2 baixos (falsos positivos de "senha" vazia e `aud_demo`) |
| Semgrep | Hashes de avaliação e SQL de demonstração cobertos por exceções com prazo; actions fixadas por SHA |
| pip-audit | Nenhuma vulnerabilidade conhecida |
| ZAP | Nenhum alerta médio ou alto |
| Auditoria OpenAPI | 0 achados |
| Security gate | APROVADO (`evidencias/pipeline/gate-final.md`) |
| GitHub Actions | `main` verde (execuções 37166298281 e 37166685255); PR #1 com SQL concatenado bloqueado pelo gate (37166747797) (`evidencias/github-actions/`) |

## 4. Riscos residuais

| ID | Risco | Por que não foi eliminado | Mitigação atual | Aceitável para o deploy? |
|---|---|---|---|---|
| R-01 | MFA simulado: o código sai no log do servidor | O Assessment pede MFA simulado; não há provedor TOTP/SMS integrado | Desafio de uso único, 5 min, 3 tentativas, rate limit | **Não para produção.** Quem lê o log ganha o segundo fator do administrador. Bloqueia o go-live até integrar TOTP (RFC 6238) ou provedor externo |
| R-06 | Router de demonstração e contas de avaliação no código | São a evidência reprodutível do antes/depois do Assessment | Desligados por padrão; exceções do gate expiram em 2026-12-31 | **Não para produção** enquanto existirem no artefato. Condição: remover `app/routes/inseguro.py`, `templates/agenda_inseguro.html` e `app/seed.py` do build de produção |
| R-05 | SQLite sem criptografia em repouso | Banco de desenvolvimento | `CLINICA_DATABASE_URL` aponta para qualquer SGBD | **Não para produção.** Dado de saúde exige banco gerenciado com criptografia em repouso (PostgreSQL com disco/TDE cifrado) |
| R-03 | TLS terminado fora da aplicação | Responsabilidade do proxy reverso | HSTS e cookie `Secure` | Aceitável, com a condição de que o proxy só aceite HTTPS (TLS 1.2+) |
| R-02 | Rate limit e bloqueio por identidade em memória | Um processo; sem Redis no ambiente do Assessment | Funciona em instância única | Aceitável em instância única; com réplicas, mover para Redis |
| R-04 | JWT sem revogação antes do `exp`; logout da recepção só apaga o cookie | Token stateless | Expiração de 15 min (10 no M2M); usuário/cliente desativado perde acesso na hora | Aceitável: a janela é curta e a desativação é imediata |
| R-07 | CSP de `/docs` com `'unsafe-inline'` | Exigência do Swagger UI | Só nas páginas de documentação, que não exibem dado de usuário | Aceitável com `CLINICA_DOCS_ATIVOS=false` em produção |
| R-08 | IAST não implementado | Sem agente gratuito para Python | SAST + DAST + testes de integração por dentro | Aceitável; reavaliar se houver orçamento |
| R-09 | Bloqueio por identidade pode ser usado para travar contas de terceiros | Efeito colateral do controle | Bloqueio temporário (15 min), não permanente | Aceitável; monitorar picos de bloqueio |
| R-10 | Security gate não é status check obrigatório no merge | Branch protection em repositório privado exige GitHub Pro | O gate falha visivelmente no PR (demonstrado no PR #1); merge na `main` só por revisão | Aceitável para o Assessment; em produção, habilitar branch protection exigindo o job `Security gate` |

## 5. Veredito

**Liberação condicionada.** A aplicação está apta para homologação: nenhum achado médio ou alto aberto, gate aprovado, todas as ameaças do threat model com mitigação e teste. Para o primeiro deploy em produção, três riscos residuais bloqueiam a liberação porque, num serviço que trata dado de saúde, cada um deles sozinho expõe a base inteira:

1. R-01: substituir o MFA simulado por TOTP real;
2. R-06: build de produção sem o router de demonstração, o template vulnerável e o seed de avaliação (com `CLINICA_CARREGAR_DADOS_DEMONSTRACAO=false` e `CLINICA_DOCS_ATIVOS=false`);
3. R-05: banco gerenciado com criptografia em repouso.

Os demais riscos residuais (R-02, R-03, R-04, R-07, R-08, R-09, R-10) são aceitáveis com as condições descritas e ficam registrados para reavaliação.
