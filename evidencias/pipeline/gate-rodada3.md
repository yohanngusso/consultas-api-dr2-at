# Security gate

Resultado: **BLOQUEADO**. Achados: 20; bloqueantes: 2; exceções vigentes: 3.

| Decisão | Ferramenta | Regra | Severidade | CWE | Local | Descrição |
|---|---|---|---|---|---|---|
| BLOQUEIA | semgrep | gha-curl-pipe-shell | ALTA | 78 | `.github/workflows/security.yml:116` | A `run:` step pipes the output of `curl` or `wget` directly into a shell interpreter. This is the "curl / bash" install pattern — if the remote server is compro |
| BLOQUEIA | semgrep | nan-injection | ALTA | 704 | `app/auth/csrf.py:40` | Found user input going directly into typecast for bool(), float(), or complex(). This allows an attacker to inject Python's not-a-number (NaN) into the typecast |
| exceção | semgrep | avoid-sqlalchemy-text | ALTA | 89 | `app/routes/inseguro.py:44` | sqlalchemy.text passes the constructed SQL statement to the database mostly unchanged. This means that the usual SQL injection protections are not applied and t |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:32` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:34` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:36` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:38` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:40` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:42` | bcrypt hash detected |
| exceção | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/seed.py:47` | bcrypt hash detected |
| exceção | bandit | B608 | MEDIA | 89 | `app\routes\inseguro.py:43` | Possible SQL injection vector through string-based query construction. |
| aviso | bandit | B107 | BAIXA | 259 | `app\routes\auth.py:16` | Possible hardcoded password: '' |
| aviso | bandit | B105 | BAIXA | 259 | `app\routes\inseguro.py:69` | Possible hardcoded password: 'aud_demo' |
| aviso | zap | 10096 | BAIXA | 497 | `http://host.docker.internal:8000/auth/eu (2 ocorrências)` | Timestamp Disclosure - Unix |
| aviso | zap | 10049 | INFO | 524 | `http://host.docker.internal:8000/ (4 ocorrências)` | Non-Storable Content |
| aviso | zap | 10112 | INFO | 1 | `http://host.docker.internal:8000/web/agenda (3 ocorrências)` | Session Management Response Identified |
| aviso | zap | 10049 | INFO | 524 | `http://host.docker.internal:8000/static/agenda.css (1 ocorrências)` | Storable and Cacheable Content |
| aviso | zap | 100000 | INFO | 388 | `http://host.docker.internal:8000/consultas/10 (13 ocorrências)` | A Client Error response code was returned by the server |
| aviso | zap | 10111 | INFO | 1 | `http://host.docker.internal:8000/auth/token (1 ocorrências)` | Authentication Request Identified |
| aviso | zap | 10049 | INFO | 524 | `http://host.docker.internal:8000/auth/eu (5 ocorrências)` | Non-Storable Content |
