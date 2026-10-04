# Exercício 11 - Persistência segura

## SQLModel com queries parametrizadas

- Tabelas em `app/db_models.py`; contratos de API em `app/models.py`. A separação é o que permite ao banco ter campos internos sem risco de expô-los.
- Repositório em `app/database.py`: toda consulta é montada com `select()`, `where()`, `col()` e `sessao.get()`. Nenhuma string SQL é construída por concatenação ou f-string em código de produção; a única ocorrência do projeto é a versão vulnerável preservada em `app/routes/inseguro.py`, detectada por Bandit (B608) e Semgrep (`avoid-sqlalchemy-text`).
- O nome de coluna e a ordenação nunca vêm do cliente.
- `contains(termo, autoescape=True)` gera `LIKE '%' || ? || '%' ESCAPE '/'`: o termo vai como parâmetro e `%`/`_` perdem o significado de coringa.

SQL capturado no driver ao chamar o repositório com payloads, sem a whitelist na frente:

```
SELECT paciente.id, paciente.nome, ... FROM paciente
WHERE (paciente.nome LIKE '%' || ? || '%' ESCAPE '/') ORDER BY paciente.nome
parâmetros ligados: ("' OR '1'='1",)

SELECT usuario.id, ... FROM usuario WHERE usuario.email = ?
parâmetros ligados: ("admin@clinica.dev' --",)
```

Resultado: nenhuma linha. O payload chega ao banco como valor, nunca como comando.

## Sessão por injeção de dependência

```python
def get_session() -> Iterator[Session]:
    with Session(engine) as sessao:
        yield sessao

SessaoDep = Annotated[Session, Depends(get_session)]
```

Cada requisição recebe a própria sessão, fechada ao final mesmo quando o handler levanta exceção. Não há sessão global compartilhada entre requisições concorrentes. Nos testes, a mesma injeção permite substituir a sessão por um mock (`tests/test_unitarios_mock.py`).

## Credenciais com BaseSettings e .env

`app/config.py`:

| Decisão | Efeito |
|---|---|
| `jwt_secret: SecretStr` sem valor padrão | Sem `CLINICA_JWT_SECRET` a aplicação não sobe; serviço nunca roda com chave conhecida |
| Validador de tamanho mínimo (32) | Segredo fraco também impede a subida |
| `SecretStr` | O valor não aparece em `repr`, log ou traceback (`SecretStr('**********')`) |
| `database_url` vinda do ambiente | Usuário e senha do banco nunca entram no código; trocar SQLite por PostgreSQL é mudar uma linha do `.env` |
| `.env` no `.gitignore` e fora do ZIP | Entrega só o `.env.example`, sem segredos |
| `carregar_dados_demonstracao=False` por padrão | Contas de avaliação não existem em produção |

O `.env.example` documenta todas as variáveis com o prefixo `CLINICA_` e deixa `CLINICA_JWT_SECRET` vazio, com o comando para gerar um valor.

Evidência: `evidencias/ex11-persistencia-e-credenciais.txt`.
