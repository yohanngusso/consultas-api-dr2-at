# Threat model da consultas-api

Versão 1.0 | Serviço: consultas-api 1.0.0 | Autor: Yohann Guedes

Artefato oficial de modelagem de ameaças (Exercício 4). Os identificadores T-xx definidos aqui são usados nos testes automatizados (`tests/test_autorizacao.py`, `tests/test_entrada.py`, `tests/test_cabecalhos_e_limites.py`), na tabela CVSS do Exercício 12 e no relatório de rastreabilidade do Exercício 13.

## 1. Sistema

API REST de agendamento de consultas de uma rede de clínicas. Lida com dado pessoal sensível (dado referente à saúde, art. 5º, II, e art. 11 da LGPD).

| Ator | Canal | O que pode fazer |
|---|---|---|
| Paciente (titular) | Frontend JSON | Ler as próprias consultas |
| Profissional de saúde | Frontend JSON | Criar, remarcar e cancelar consultas dos próprios pacientes; ler cadastro dos próprios pacientes |
| Recepcionista | Página HTML interna | Ver a agenda do dia sem dado clínico; cadastrar e buscar pacientes |
| Administrador | Frontend JSON com MFA | Administração de usuários e leitura da trilha de auditoria |
| Laboratório parceiro | M2M (client_credentials) | Somente consultar horários disponíveis |

Componentes analisados:

| Código | Componente | Arquivos |
|---|---|---|
| C1 | API de consultas e pacientes | `app/routes/consultas.py`, `app/routes/pacientes.py` |
| C2 | Autenticação e autorização | `app/auth/`, `app/middlewares.py`, `app/routes/auth.py` |
| C3 | Persistência | `app/database.py`, `app/db_models.py`, `app/config.py` |
| C4 | Página da recepção | `app/routes/web.py`, `templates/` |
| C5 | Integração do laboratório | `app/routes/laboratorio.py` |

## 2. Ativos

| Código | Ativo | Onde vive | Perda mais grave |
|---|---|---|---|
| A1 | Dado de saúde (motivo da consulta, observações, especialidade) | Tabela `consulta` | Exposição de dado sensível, sanção da ANPD, dano ao titular |
| A2 | Dado identificador do paciente (nome, CPF, e-mail, telefone, nascimento) | Tabela `paciente` | Identificação e vinculação do titular ao dado de saúde |
| A3 | Credenciais (hash bcrypt de senha, segredo do laboratório) | Tabelas `usuario` e `clientem2m` | Tomada de conta e acesso em nome de terceiros |
| A4 | Chave de assinatura JWT e URL do banco | `.env` / cofre de segredos | Emissão de token de qualquer papel; acesso direto ao banco |
| A5 | Integridade da agenda | Tabela `consulta` | Consulta remarcada ou cancelada indevidamente, paciente sem atendimento |
| A6 | Trilha de auditoria | Tabela `registroauditoria` | Impossibilidade de responder a incidente e de atender o titular (art. 37 LGPD) |
| A7 | Disponibilidade do serviço | Processo da API | Recepção sem agenda, clínica parada |

## 3. Superfícies de ataque

| Superfície | Exposição | Dados que atravessam |
|---|---|---|
| `POST /auth/token`, `POST /auth/mfa` | Pública | Credenciais, segredo M2M, código MFA |
| `GET/POST/PUT/DELETE /consultas*` | Token de usuário | A1, A2, A5 |
| `GET/POST /pacientes*` | Token de usuário | A2 |
| `GET /laboratorio/horarios-disponiveis` | Token M2M | Ocupação da agenda |
| `GET /admin/*` | Token de administrador com MFA | Usuários, A6 |
| `GET/POST /web/login`, `GET /web/agenda`, `POST /web/logout` | Rede interna, cookie | A2 e observações |
| `/docs`, `/openapi.json` | Pública (desligável) | Mapa da superfície |
| Configuração (`.env`) e dependências | Pipeline e servidor | A4 |

## 4. Misuse cases

| ID | Ator malicioso | Caso de uso abusivo | Ameaças | Mitigação |
|---|---|---|---|---|
| MC-01 | Paciente autenticado | Troca o id em `/consultas/{id}` e enumera consultas de outros pacientes | T-01 | `exigir_posse` + guarda de posse + auditoria |
| MC-02 | Profissional curioso | Lê cadastro e agenda pacientes de outro profissional | T-02, T-20 | Regras `pode_ler_paciente` e `pode_alterar_consulta` |
| MC-03 | Atacante com token do laboratório vazado | Usa o token para ler consultas e pacientes | T-04 | Escopo `horarios:ler`, `aud` próprio, rota exclusiva |
| MC-04 | Atacante externo | Força bruta / credential stuffing no login da recepção | T-05, T-21 | Rate limit 5/min, bloqueio por identidade, mensagem única |
| MC-05 | Profissional mal-intencionado ou conta comprometida | Grava `<script>` nas observações para sequestrar a sessão da recepção | T-10, T-19 | Autoescape, CSP sem inline, cookie HttpOnly |
| MC-06 | Usuário com acesso à busca | Injeta SQL no termo de busca para extrair hashes | T-09 | Whitelist por regex + `select()` parametrizado |
| MC-07 | Profissional | Envia `profissional_id` no corpo para criar consulta em nome de outro | T-11 | `extra="forbid"` |
| MC-08 | Recepcionista | Tenta ver o motivo clínico das consultas | T-12 | `ConsultaAgenda` sem `motivo`; escopo `agenda:ler` sem `consultas:ler` |
| MC-09 | Insider com acesso ao repositório | Usa segredo JWT ou credencial publicada no código | T-17 | `BaseSettings`, `SecretStr`, segredo obrigatório, Semgrep `p/secrets` |
| MC-10 | Site malicioso | Faz o navegador da recepção logada chamar a API (CORS/CSRF) | T-14, T-19 | Allowlist de CORS, SameSite=Strict, token anti-CSRF |

## 5. STRIDE por componente

### C1 API de consultas e pacientes

| STRIDE | Ameaça | ID |
|---|---|---|
| Spoofing | Uso de token alheio ou forjado para operar consultas | T-06, T-07 |
| Tampering | Mass assignment de `profissional_id`, `token_auditoria`, `criado_por_id` | T-11 |
| Repudiation | Profissional nega ter cancelado consulta | T-15 |
| Information disclosure | BOLA em consultas e pacientes; campos internos e CPF completo na resposta | T-01, T-02, T-12 |
| Denial of service | Flood de criação de consultas ou buscas | T-16 |
| Elevation of privilege | Paciente altera consulta; profissional altera consulta de outro | T-20 |

### C2 Autenticação e autorização

| STRIDE | Ameaça | ID |
|---|---|---|
| Spoofing | Força bruta, enumeração de e-mail, administrador sem MFA | T-05, T-21, T-08 |
| Tampering | Token com `alg=none`, assinatura forjada, payload adulterado | T-06 |
| Repudiation | Login e negações sem registro | T-15 |
| Information disclosure | Segredo JWT no código ou em log | T-17 |
| Denial of service | Bloqueio de conta como arma contra usuário legítimo | T-05 |
| Elevation of privilege | Pedido de escopo além do papel; token de usuário com audiência do laboratório | T-03, T-07 |

### C3 Persistência

| STRIDE | Ameaça | ID |
|---|---|---|
| Spoofing | Conexão ao banco com credencial vazada | T-17 |
| Tampering | SQL injection alterando ou lendo tabelas | T-09 |
| Repudiation | Alteração de consulta sem `atualizado_em`/`ip_origem` | T-15 |
| Information disclosure | Leitura de hashes por UNION; banco sem criptografia em repouso | T-09, R-05 |
| Denial of service | Consulta sem limite de tamanho ou janela de datas | T-16 |
| Elevation of privilege | Escrita direta em campos internos | T-11 |

### C4 Página da recepção

| STRIDE | Ameaça | ID |
|---|---|---|
| Spoofing | Roubo do cookie de sessão; CSRF de login/logout | T-19 |
| Tampering | XSS armazenado nas observações | T-10 |
| Repudiation | Acesso à agenda sem registro | T-15 |
| Information disclosure | Clickjacking; cache do navegador com dado de saúde; motivo clínico na tela | T-13, T-12 |
| Denial of service | Script injetado travando a página | T-10 |
| Elevation of privilege | Script executando ações com a sessão da recepção | T-10 |

### C5 Integração do laboratório

| STRIDE | Ameaça | ID |
|---|---|---|
| Spoofing | Segredo do cliente vazado; força bruta no client_secret | T-04, T-05 |
| Tampering | Parâmetros de busca manipulados (especialidade, data) | T-09 |
| Repudiation | Chamadas do parceiro sem registro | T-15 |
| Information disclosure | Token do laboratório lendo dado de paciente; PII na resposta de horários | T-04 |
| Denial of service | Varredura de datas sem limite | T-16 |
| Elevation of privilege | Escopo fora do contrato concedido ao token | T-04 |

## 6. Catálogo de ameaças e mitigações

| ID | Ameaça | OWASP 2021 | Ativo | Mitigação implementada | Onde | Teste |
|---|---|---|---|---|---|---|
| T-01 | BOLA em consultas | A01 | A1 | `exigir_posse` + `pode_ler_consulta` + guarda | `app/auth/dependencies.py`, `app/middlewares.py` | `test_t01_*` |
| T-02 | BOLA em pacientes e busca | A01 | A2 | `paciente_legivel`; busca filtrada pelo responsável | `app/auth/dependencies.py`, `app/routes/pacientes.py` | `test_t02_*` |
| T-03 | Escalada vertical para rotas admin | A01 | A6 | Escopo `admin` + `exigir_administrador` | `app/auth/dependencies.py` | `test_t03_*` |
| T-04 | Token do laboratório além do contrato | A01 | A1, A2 | `client_credentials`, recorte de escopo, `aud` próprio | `app/auth/autenticacao.py` | `test_t04_*` |
| T-05 | Força bruta no login | A07 | A3 | Rate limit 5/min + bloqueio por identidade | `app/limiter.py`, `app/auth/security.py` | `test_t05_*` |
| T-06 | Falsificação de JWT | A02, A07 | A4 | Algoritmo fixo, `iss`/`aud`/`exp` obrigatórios, papel conferido no banco | `app/auth/security.py`, `app/auth/dependencies.py` | `test_t06_*` |
| T-07 | Token expirado, sem `exp`, audiência trocada, usuário desativado | A07 | A3 | `exp` de 15 min, `aud` por tipo, usuário recarregado a cada requisição | `app/auth/dependencies.py` | `test_t07_*` |
| T-08 | Administrador sem MFA | A07 | A6 | Desafio de uso único, `amr`, claim `mfa` exigida | `app/auth/security.py` | `test_t08_*` |
| T-09 | SQL injection | A03 | A1, A2, A3 | Whitelist regex/enum + `select()` parametrizado | `app/validators.py`, `app/database.py` | `test_t09_*` |
| T-10 | XSS armazenado | A03 | A1 | Autoescape Jinja2, CSP `script-src 'self'` | `templates/agenda.html`, `app/middlewares.py` | `test_pagina_da_agenda_*`, `test_t10_*` |
| T-11 | Mass assignment | A04 | A5 | `extra="forbid"` em toda entrada | `app/models.py` | `test_t11_*` |
| T-12 | Exposição excessiva de dados | A04 | A1, A2 | `response_model`, CPF mascarado, agenda sem motivo, erro 422 sem eco | `app/models.py`, `main.py` | `test_resposta_*`, `test_erro_de_validacao_*` |
| T-13 | Cabeçalhos ausentes (clickjacking, sniffing, downgrade, cache) | A05 | A1 | HSTS, XFO, XCTO, CSP, COOP/CORP/COEP, `no-store` | `app/middlewares.py` | `test_t13_*` |
| T-14 | CORS permissivo | A05 | A1 | Allowlist do `.env`, wildcard derruba a subida | `app/config.py`, `main.py` | `test_t14_*` |
| T-15 | Repúdio / ausência de trilha | A09 | A6 | `RegistroAuditoria` gravado por `auditar()` | `app/auth/dependencies.py` | `test_t15_*` |
| T-16 | Negação de serviço por volume | A04 | A7 | Rate limit por tipo de rota, janela de datas, tamanhos máximos | `app/limiter.py`, `app/validators.py` | `test_t05_login_tem_limite_*` |
| T-17 | Credenciais no código | A02, A07 | A3, A4 | `BaseSettings`, `SecretStr`, segredo obrigatório, seed desligado por padrão | `app/config.py`, `app/seed.py` | `test_t17_*` |
| T-18 | Dependência vulnerável | A06 | Todos | Versões fixadas, pip-audit no pipeline | `requirements.txt`, `.github/workflows/security.yml` | pipeline |
| T-19 | Sessão da recepção: roubo de cookie e CSRF | A01, A07 | A1 | HttpOnly, Secure, SameSite=Strict, Path=/web, token CSRF | `app/routes/web.py`, `app/auth/csrf.py` | `test_t19_*` |
| T-20 | Alteração de consulta por quem não é dono | A01 | A5 | `consulta_alteravel` | `app/auth/dependencies.py` | `test_t20_*` |
| T-21 | Enumeração de usuários no login | A07 | A3 | Mensagem única e bcrypt contra hash fictício | `app/auth/autenticacao.py`, `app/auth/security.py` | `test_t21_*`, `test_login_de_email_inexistente_*` |
| T-22 | Documentação expondo a superfície | A05 | Todos | `CLINICA_DOCS_ATIVOS=false` em produção | `main.py` | `test_t22_*` |
