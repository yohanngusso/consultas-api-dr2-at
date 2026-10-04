# Security gate

Resultado: **BLOQUEADO**. Achados: 11; bloqueantes: 9; exceções vigentes: 0.

| Decisão | Ferramenta | Regra | Severidade | CWE | Local | Descrição |
|---|---|---|---|---|---|---|
| BLOQUEIA | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/database.py:59` | bcrypt hash detected |
| BLOQUEIA | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/database.py:61` | bcrypt hash detected |
| BLOQUEIA | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/database.py:63` | bcrypt hash detected |
| BLOQUEIA | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/database.py:65` | bcrypt hash detected |
| BLOQUEIA | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/database.py:67` | bcrypt hash detected |
| BLOQUEIA | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/database.py:69` | bcrypt hash detected |
| BLOQUEIA | semgrep | detected-bcrypt-hash | ALTA | 798 | `app/database.py:74` | bcrypt hash detected |
| BLOQUEIA | semgrep | avoid-sqlalchemy-text | ALTA | 89 | `app/routes/inseguro.py:44` | sqlalchemy.text passes the constructed SQL statement to the database mostly unchanged. This means that the usual SQL injection protections are not applied and t |
| BLOQUEIA | bandit | B608 | MEDIA | 89 | `app\routes\inseguro.py:43` | Possible SQL injection vector through string-based query construction. |
| aviso | bandit | B107 | BAIXA | 259 | `app\routes\auth.py:16` | Possible hardcoded password: '' |
| aviso | bandit | B105 | BAIXA | 259 | `app\routes\inseguro.py:69` | Possible hardcoded password: 'aud_demo' |
