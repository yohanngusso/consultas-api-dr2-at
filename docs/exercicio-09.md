# Exercício 9 - Correção de vulnerabilidades de entrada e saída

As correções são centralizadas: cada uma está escrita em um lugar e é declarada pelas rotas, para que um endpoint novo criado por outra pessoa herde a proteção sem copiar código.

## Middleware JWT centralizado

`AutenticacaoJWTMiddleware` (`app/middlewares.py`) é o único ponto do sistema que decodifica JWT. Ele é fail-closed: tudo que não está em `ROTAS_PUBLICAS` (`/`, `/auth/token`, `/auth/mfa`, `/web/login`, documentação e `/static/`) exige token válido antes de chegar a qualquer rota. Uma rota nova esquecida sem dependência de autenticação responde 401, não dados. As claims validadas ficam em `request.state.claims`, e `obter_principal` apenas as converte em identidade e permissão, sem repetir a validação.

Token ausente, expirado ou inválido dá 401 nas rotas JSON e redireciona para `/web/login` nas páginas da recepção.

## Verificação de ownership: V1

`exigir_posse(...)` (`app/auth/dependencies.py`) é uma fábrica de dependências. Cada recurso sensível é uma declaração:

```python
consulta_legivel = exigir_posse(
    carregar=database.obter_consulta,
    pode_acessar=pode_ler_consulta,
    nome_parametro="consulta_id",
    escopos=["consultas:ler"],
    recurso="Consulta",
    acao="ler_consulta",
)
```

A dependência confere escopo, carrega o objeto, responde 404 se ele não existe (antes de 403, para não virar oráculo de ids), aplica a regra de posse, grava a decisão na trilha de auditoria e marca `request.state.posse_verificada`. O `GuardaAutorizacaoMiddleware` confere essa marca: rota de objeto de titular que responder 2xx sem ter passado pela verificação tem a resposta trocada por 500. Esquecer a dependência vira falha visível no primeiro teste, não vazamento silencioso.

Antes: `GET /inseguro/consultas/2` com o token do João → 200 com o motivo da Maria. Depois: `GET /consultas/2` com o mesmo token → 403, registrado como `ler_consulta Consulta#2 negado`.

## Mesmo padrão em endpoint não citado: GET /pacientes/{id}

A leitura do código procurando o padrão "token com escopo, objeto carregado só pelo id" encontrou outros pontos além de `/consultas/{id}`:

- `GET /pacientes/{id}`: qualquer profissional lia o cadastro de paciente de outro profissional.
- `PUT` e `DELETE /consultas/{id}`: qualquer profissional alterava consulta alheia.
- `GET /pacientes/busca`: listava pacientes de todos os profissionais.
- `POST /consultas`: aceitava `paciente_id` de paciente que não é do profissional.

A mesma fábrica foi aplicada: `paciente_legivel` em `GET /pacientes/{id}`, `consulta_alteravel` em `PUT` e `DELETE`; a busca do profissional filtra por `profissional_responsavel_id`; a criação reutiliza `pode_ler_paciente`. Antes: `GET /inseguro/pacientes/2` com o token da Dra. Helena → 200. Depois: `GET /pacientes/2` → 403 e `GET /pacientes/1` (paciente dela) → 200.

## Validação whitelist e regex: V2

`app/validators.py`:

| Entrada | Regra |
|---|---|
| Termo de busca | `^[0-9A-Za-zÀ-ÖØ-öø-ÿ .\-]{2,60}$`, aplicada como dependência antes do handler; erro 422 que descreve a regra sem refletir o payload |
| Especialidade, status | `Enum` (whitelist de valores) |
| Nome de pessoa, telefone, CPF | Regex de formato; CPF também com dígitos verificadores |
| Datas | Consulta no futuro, até 60 dias, das 7h às 19h, em intervalos de 15 min |
| Texto livre (motivo, observações) | Tamanho máximo e recusa de caracteres de controle; `<` e `>` são aceitos e tratados na saída |

A whitelist recusa cedo; a parametrização do Exercício 11 é a segunda camada, independente. O `autoescape=True` do `contains()` impede que `%` e `_` virem coringas do LIKE.

Antes: `' OR '1'='1` → 200 com todos os CPFs; `UNION` → hashes. Depois: as duas → 422.

## Pydantic com extra="forbid": V4

Toda entrada herda de `EntradaEstrita` (`model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)`). `profissional_id`, `criado_por_id`, `token_auditoria` e `status` (na criação) não existem em `ConsultaCreate`; enviá-los dá 422 `extra_forbidden`. Os campos de controle são preenchidos pelo servidor a partir do token. O handler de `RequestValidationError` em `main.py` remove `input` e `ctx` do erro, para que a resposta não reflita o valor enviado.

## Output encoding via autoescape: V3

`templates/agenda.html` exibe `{{ c.observacoes }}` sem `|safe`; o Jinja2 codifica `<`, `>`, `"` e `'`. O mesmo payload salvo pela mesma rota aparece como texto na agenda corrigida (`tela-04`) e executa na vulnerável (`tela-05`). A CSP `script-src 'self'` do Exercício 10 é a segunda barreira.

## Evidências

`evidencias/ex09-correcoes-antes-depois.txt` executa os mesmos payloads do Exercício 8 contra as rotas corrigidas e termina com a trilha de auditoria. Os testes `test_t01_*`, `test_t02_*`, `test_t09_*`, `test_t11_*` e `test_pagina_da_agenda_exibe_payload_xss_como_texto` fixam o comportamento.
