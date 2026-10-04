# Security gate

Resultado: **BLOQUEADO**. Achados: 12; bloqueantes: 1; exceções vigentes: 3.

| Decisão | Ferramenta | Regra | Severidade | CWE | Local | Descrição |
|---|---|---|---|---|---|---|
| BLOQUEIA | zap | 10202 | MEDIA | 352 | `http://host.docker.internal:8000/web/agenda (3 ocorrências)` | Absence of Anti-CSRF Tokens |
| aviso | zap | 90004 | BAIXA | 693 | `http://host.docker.internal:8000/web/agenda (2 ocorrências)` | Cross-Origin-Embedder-Policy Header Missing or Invalid |
| aviso | zap | 90004 | BAIXA | 693 | `http://host.docker.internal:8000/web/agenda (2 ocorrências)` | Cross-Origin-Opener-Policy Header Missing or Invalid |
| aviso | zap | 90004 | BAIXA | 693 | `http://host.docker.internal:8000/ (4 ocorrências)` | Cross-Origin-Resource-Policy Header Missing or Invalid |
| aviso | zap | 10063 | BAIXA | 693 | `http://host.docker.internal:8000/web/agenda (3 ocorrências)` | Permissions Policy Header Not Set |
| aviso | zap | 90004 | BAIXA | 693 | `http://host.docker.internal:8000/ (5 ocorrências)` | Cross-Origin-Resource-Policy Header Missing or Invalid |
| aviso | zap | 10096 | BAIXA | 497 | `http://host.docker.internal:8000/auth/eu (2 ocorrências)` | Timestamp Disclosure - Unix |
| aviso | zap | 10049 | INFO | 524 | `http://host.docker.internal:8000/ (4 ocorrências)` | Non-Storable Content |
| aviso | zap | 10049 | INFO | 524 | `http://host.docker.internal:8000/static/agenda.css (1 ocorrências)` | Storable and Cacheable Content |
| aviso | zap | 100000 | INFO | 388 | `http://host.docker.internal:8000/consultas/10 (13 ocorrências)` | A Client Error response code was returned by the server |
| aviso | zap | 10111 | INFO | 1 | `http://host.docker.internal:8000/auth/token (1 ocorrências)` | Authentication Request Identified |
| aviso | zap | 10049 | INFO | 524 | `http://host.docker.internal:8000/consultas/10 (5 ocorrências)` | Non-Storable Content |
