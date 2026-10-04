# Exercício 10 - Hardening de rede e proteção contra abuso

## CORS com allowlist explícita

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.origens_permitidas,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)
```

- As origens vêm de `CLINICA_CORS_ORIGENS` no `.env`, separadas por vírgula.
- `Configuracoes.recusar_coringa` (`app/config.py`) derruba a inicialização se houver `*` em qualquer posição. O controle não depende da disciplina de quem edita o `.env`, que é o ponto em que o outro serviço foi reprovado.
- Métodos e cabeçalhos também são enumerados. O wildcard em `allow_headers` ou `allow_methods` transformaria o preflight em autorização em branco.
- A página da recepção não depende de CORS: é servida pela própria origem.

Evidência: preflight da origem `http://localhost:5173` recebe `access-control-allow-origin`; o de `https://atacante.exemplo` recebe 400 sem o cabeçalho. `Configuracoes(cors_origens="*")` levanta `ValidationError`.

## Cabeçalhos de segurança

`CabecalhosDeSegurancaMiddleware` é o middleware mais externo, então os cabeçalhos saem em toda resposta, inclusive 401 do middleware JWT, 404 do framework e 429 do limitador.

| Cabeçalho | Valor | Ameaça |
|---|---|---|
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` | Downgrade para HTTP e interceptação do token (só tem efeito quando servido por HTTPS, por isso o TLS fica na borda) |
| X-Frame-Options | `DENY` | Clickjacking na agenda da recepção |
| X-Content-Type-Options | `nosniff` | Navegador interpretando JSON com HTML como página |
| Referrer-Policy | `no-referrer` | URLs com id de consulta vazando em navegação externa |
| Content-Security-Policy | `default-src 'self'; script-src 'self'; style-src 'self'; ... frame-ancestors 'none'; object-src 'none'` | Segunda barreira contra XSS |
| Cache-Control | `no-store` | Dado de saúde em cache de navegador compartilhado na recepção |
| Permissions-Policy, Cross-Origin-Opener/Resource/Embedder-Policy | restritivos | Acrescentados após o scan ZAP do Exercício 13 |

A CSP da documentação (`/docs`, `/redoc`) é diferente porque o Swagger carrega recursos do jsDelivr e um script inline. A concessão vale só para essas páginas, que não exibem dado de usuário, e a documentação pode ser desligada em produção.

## Rate limiting diferenciado

`app/limiter.py` (slowapi, chave por IP, valores no `.env`):

| Tipo de rota | Limite | Justificativa |
|---|---|---|
| `POST /auth/token`, `POST /auth/mfa`, `POST /web/login` | 5/min | Um acerto entrega uma conta; usuário legítimo raramente erra mais de 3 vezes |
| Escrita (criar, remarcar, cancelar, cadastrar) | 20/min | Abuso aqui é flood de conteúdo |
| Leitura (listagens, busca, horários) | 60/min | Maior volume legítimo, inclusive do laboratório |
| Demais rotas | 120/min | Teto padrão |

Um limite único para a API erraria dos dois lados: baixo trava a navegação; alto deixa passar centenas de senhas por minuto. O 429 traz `Retry-After` e não informa quantas tentativas restam.

Rate limiting por IP não para ataque distribuído. Por isso há uma segunda camada, por identidade (`app/auth/security.py`): 5 falhas seguidas para o mesmo e-mail ou client_id bloqueiam a conta por 15 minutos, independentemente do IP. A mensagem de bloqueio não diz se a senha estava certa.

Evidência (`evidencias/ex10-cors-cabecalhos-rate-limit.txt`): tentativas 1 a 5 com 401, a 6ª e a 7ª com 429 e `Retry-After: 60`; 20 leituras no mesmo intervalo com 200; após zerar o contador por IP, a senha correta continua recebendo 429 por causa do bloqueio da conta.
