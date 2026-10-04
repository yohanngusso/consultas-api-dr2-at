# Execução 37166747797 do workflow pipeline-de-seguranca

- URL: https://github.com/yohanngusso/consultas-api-dr2-at/actions/runs/37166747797
- Evento: pull_request | branch: demonstracao/gate-bloqueia-sqli | commit: 81080d3 (Busca de paciente por CPF montando o SQL por concatenação)
- Início: 2026-10-04T01:01:39Z | conclusão: **failure**

| Job | Resultado | Duração |
|---|---|---|
| SAST (Bandit e Semgrep) | success | 0m34s |
| Testes de segurança e auditoria OpenAPI | success | 1m07s |
| SCA (pip-audit) | success | 0m25s |
| DAST (ZAP passivo em homologação efêmera) | success | 2m02s |
| Security gate | failure | 0m06s |

## Decisão do security gate

# Security gate
Resultado: **BLOQUEADO**. Achados: 22; bloqueantes: 2; exceções vigentes: 3.
| Decisão | Ferramenta | Regra | Severidade | CWE | Local | Descrição |
|---|---|---|---|---|---|---|
| BLOQUEIA | semgrep | avoid-sqlalchemy-text | ALTA | 89 | `app/database.py:236` | sqlalchemy.text passes the constructed SQL statement to the database mostly unchanged. This means that the usual SQL injection protections are not applied and t |
| exceção | semgrep | avoid-sqlalchemy-text | ALTA | 89 | `app/routes/inseguro.py:44` | sqlalchemy.text passes the constructed SQL statement to the database mostly unchanged. This means that the usual SQL injection protections are not applied and t |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:32` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:34` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:36` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:38` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:40` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:42` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:47` | bcrypt hash detected |
| BLOQUEIA | bandit | B608 | MEDIA | 89 | `app/database.py:235` | Possible SQL injection vector through string-based query construction. |
| exceção | bandit | B608 | MEDIA | 89 | `app/routes/inseguro.py:43` | Possible SQL injection vector through string-based query construction. |
| aviso | bandit | B107 | BAIXA | 259 | `app/routes/auth.py:16` | Possible hardcoded password: '' |
| aviso | bandit | B105 | BAIXA | 259 | `app/routes/inseguro.py:69` | Possible hardcoded password: 'aud_demo' |
| aviso | semgrep | dependabot-missing-cooldown | BAIXA | 829 | `.github/dependabot.yml:3` | This Dependabot configuration does not set a cooldown period. Newly published packages can be malicious or unstable. Add a `cooldown` block with `default-days:  |
| aviso | semgrep | dependabot-missing-cooldown | BAIXA | 829 | `.github/dependabot.yml:11` | This Dependabot configuration does not set a cooldown period. Newly published packages can be malicious or unstable. Add a `cooldown` block with `default-days:  |
| aviso | zap | 10096 | BAIXA | 497 | `http://localhost:8000/auth/eu (2 ocorrências)` | Timestamp Disclosure - Unix |
| aviso | zap | 10049 | INFO | 524 | `http://localhost:8000/ (4 ocorrências)` | Non-Storable Content |
| aviso | zap | 10112 | INFO | 1 | `http://localhost:8000/web/agenda (2 ocorrências)` | Session Management Response Identified |
| aviso | zap | 10049 | INFO | 524 | `http://localhost:8000/static/agenda.css (1 ocorrências)` | Storable and Cacheable Content |
| aviso | zap | 100000 | INFO | 388 | `http://localhost:8000/consultas/10 (13 ocorrências)` | A Client Error response code was returned by the server |
| aviso | zap | 10111 | INFO | 1 | `http://localhost:8000/auth/token (1 ocorrências)` | Authentication Request Identified |
| aviso | zap | 10049 | INFO | 524 | `http://localhost:8000/auth/eu (5 ocorrências)` | Non-Storable Content |
##[error]Process completed with exit code 1.
