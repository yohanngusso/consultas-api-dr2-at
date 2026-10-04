# consultas-api

API REST de agendamento de consultas de uma rede de clínicas, em FastAPI, desenvolvida no Assessment da disciplina Desenvolvimento Seguro de Aplicações Web. Atende um frontend JSON (pacientes e profissionais), a página HTML interna da recepção e a integração máquina-a-máquina de um laboratório parceiro.

Vídeo de apresentação (YouTube, não listado): `<inserir link>`

## Como executar

```
python -m venv venv
venv\Scripts\activate                 # Windows
source venv/bin/activate              # Linux / macOS
pip install -r requirements-dev.txt
copy .env.example .env                # Windows (cp no Linux / macOS)
```

Preencha `CLINICA_JWT_SECRET` no `.env` (obrigatório, mínimo de 32 caracteres; sem ele a aplicação não sobe):

```
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Para desenvolvimento sem HTTPS, use `CLINICA_COOKIE_SEGURO=false`. Depois:

```
uvicorn main:app --reload --no-server-header
```

- API e documentação: http://localhost:8000/docs
- Página da recepção: http://localhost:8000/web/login

## Credenciais de avaliação

Carregadas apenas com `CLINICA_CARREGAR_DADOS_DEMONSTRACAO=true` (padrão do `.env.example`, nunca em produção). O banco guarda somente hash bcrypt.

| E-mail | Senha | Papel |
|---|---|---|
| admin@clinica.dev | SenhaAdmin#2026 | administrador (exige MFA; o código aparece no log do servidor na linha `[MFA]`) |
| recepcao@clinica.dev | SenhaRecepcao#2026 | recepcionista |
| helena@clinica.dev | SenhaHelena#2026 | profissional (cardiologia), responsável pelos pacientes 1 e 3 |
| marcos@clinica.dev | SenhaMarcos#2026 | profissional (dermatologia), responsável pela paciente 2 |
| joao@paciente.dev | SenhaJoao#2026 | paciente titular (paciente 1) |
| maria@paciente.dev | SenhaMaria#2026 | paciente titular (paciente 2) |

| client_id | client_secret | Escopo contratado |
|---|---|---|
| laboratorio-parceiro | e784ad17f9385f8f221db15796c5bff8 | horarios:ler |

## Estrutura

```
main.py                     app, middlewares, routers
app/config.py               BaseSettings (prefixo CLINICA_)
app/models.py               contratos Pydantic (extra="forbid" nas entradas)
app/db_models.py            tabelas SQLModel
app/database.py             engine, sessão por requisição, consultas parametrizadas
app/validators.py           regex e whitelists
app/middlewares.py          JWT centralizado, guarda de posse, cabeçalhos de segurança
app/limiter.py              rate limiting diferenciado
app/seed.py                 dados de avaliação
app/auth/                   camada de autenticação e autorização
app/routes/                 um APIRouter por recurso (inseguro.py só com a flag de demonstração)
templates/  static/         página da recepção (Jinja2 com herança)
tests/                      174 testes pytest
ci/                         security gate, auditoria OpenAPI, exceções
.github/workflows/          pipeline DevSecOps
.zap/rules.tsv              regras do ZAP
docs/                       um arquivo por exercício, threat model e relatório de rastreabilidade
evidencias/                 saídas de requisições, telas, relatórios do pipeline e do ZAP
```

## Rotas

| Método | Rota | Acesso |
|---|---|---|
| POST | /auth/token | Público (password e client_credentials), 5/min |
| POST | /auth/mfa | Público com desafio válido, 5/min |
| GET | /auth/eu | Token |
| GET | /consultas | `consultas:ler`, filtrado por papel |
| GET | /consultas/agenda | `agenda:ler` (sem motivo clínico) |
| POST | /consultas | Profissional, para paciente sob sua responsabilidade |
| GET | /consultas/{id} | Dono: profissional, paciente titular ou administrador |
| PUT, DELETE | /consultas/{id} | Profissional dono ou administrador |
| GET | /pacientes/busca | `pacientes:ler`, whitelist no termo |
| GET | /pacientes/{id} | Recepção, profissional responsável ou administrador |
| POST | /pacientes | `pacientes:criar` |
| GET | /profissionais | `profissionais:ler` |
| GET | /laboratorio/horarios-disponiveis | Somente token M2M com `horarios:ler` |
| GET | /admin/usuarios, /admin/auditoria | Administrador com MFA |
| GET/POST | /web/login, /web/agenda, /web/logout | Recepção, cookie de sessão + CSRF |

## Testes e pipeline

```
python -m pytest                                  # 174 testes
python ci/auditar_openapi.py                      # auditoria da especificação OpenAPI
python ci/security_gate.py --bandit ... --zap ... # critério de bloqueio
```

O workflow `.github/workflows/security.yml` roda SAST (Bandit, Semgrep), SCA (pip-audit), testes, DAST (ZAP passivo) e o security gate. Para o job de DAST, configure os segredos `DAST_PROFISSIONAL_EMAIL`, `DAST_PROFISSIONAL_SENHA`, `DAST_RECEPCAO_EMAIL` e `DAST_RECEPCAO_SENHA` no repositório.

## Modo de demonstração

`CLINICA_MODO_DEMONSTRACAO_INSEGURA=true` monta o router `/inseguro` com as versões vulneráveis analisadas no Exercício 8 (BOLA, SQL injection, XSS, mass assignment, login sem proteção). O padrão é `false`; com ele as rotas não existem nem aparecem no `/docs`.

## Documentação

| Exercício | Arquivo |
|---|---|
| 1 Fundação | [docs/exercicio-01.md](docs/exercicio-01.md) |
| 2 Exposição de dados e templates | [docs/exercicio-02.md](docs/exercicio-02.md) |
| 3 CIA, frameworks e DFD | [docs/exercicio-03.md](docs/exercicio-03.md) |
| 4 STRIDE e threat model | [docs/exercicio-04.md](docs/exercicio-04.md), [docs/threat-model.md](docs/threat-model.md) |
| 5 Arquitetura e vetores | [docs/exercicio-05.md](docs/exercicio-05.md) |
| 6 Autenticação e autorização | [docs/exercicio-06.md](docs/exercicio-06.md) |
| 7 Escopos e M2M | [docs/exercicio-07.md](docs/exercicio-07.md) |
| 8 Identificação OWASP | [docs/exercicio-08.md](docs/exercicio-08.md) |
| 9 Correções de entrada e saída | [docs/exercicio-09.md](docs/exercicio-09.md) |
| 10 Hardening | [docs/exercicio-10.md](docs/exercicio-10.md) |
| 11 Persistência | [docs/exercicio-11.md](docs/exercicio-11.md) |
| 12 Pipeline DevSecOps | [docs/exercicio-12.md](docs/exercicio-12.md) |
| 13 Capstone | [docs/exercicio-13.md](docs/exercicio-13.md), [docs/relatorio-rastreabilidade.md](docs/relatorio-rastreabilidade.md) |

O relatório técnico consolidado é o `Yohann_Guedes_DR2_AT.pdf`.
