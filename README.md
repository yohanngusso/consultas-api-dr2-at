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
docs/diagramas/             DFD níveis 0 e 1, partições e fluxos OAuth (PNG)
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

O workflow `.github/workflows/security.yml` roda SAST (Bandit, Semgrep), SCA (pip-audit), testes, DAST (ZAP passivo) e o security gate em todo push na `main`, em todo pull request e semanalmente. O Dependabot (`.github/dependabot.yml`) abre PRs de atualização de pacotes e actions. Para o job de DAST, configure os segredos `DAST_PROFISSIONAL_EMAIL`, `DAST_PROFISSIONAL_SENHA`, `DAST_RECEPCAO_EMAIL` e `DAST_RECEPCAO_SENHA` no repositório.

## Modo de demonstração

`CLINICA_MODO_DEMONSTRACAO_INSEGURA=true` monta o router `/inseguro` com as versões vulneráveis analisadas no Exercício 8 (BOLA, SQL injection, XSS, mass assignment, login sem proteção). O padrão é `false`; com ele as rotas não existem nem aparecem no `/docs`.

## Documentação

O relatório técnico `Yohann_Guedes_DR2_AT.pdf` traz uma seção curta por exercício, com as decisões de segurança, o threat model (Exercício 4) e a rastreabilidade, os riscos residuais e o veredito do capstone (Exercício 13). As evidências citadas no relatório estão em `evidencias/`, e os diagramas em `docs/diagramas/`.
