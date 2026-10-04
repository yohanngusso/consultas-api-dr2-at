# Security gate

Resultado: **APROVADO**. Achados: 11; bloqueantes: 0; exceções vigentes: 3.

| Decisão | Ferramenta | Regra | Severidade | CWE | Local | Descrição |
|---|---|---|---|---|---|---|
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
