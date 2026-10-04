# Exercício 8 - Identificação de vulnerabilidades OWASP Top 10

## Material analisado

A análise foi feita lendo o código, sem scanner. As versões vulneráveis das rotas estão preservadas em `app/routes/inseguro.py` e `templates/agenda_inseguro.html`, montadas apenas com `CLINICA_MODO_DEMONSTRACAO_INSEGURA=true` (padrão `false`), para que o "antes" das correções do Exercício 9 possa ser reproduzido a qualquer momento. As respostas desse router também saem sem os cabeçalhos de segurança, reproduzindo o estado anterior ao Exercício 10.

O roteiro de leitura foi: para cada rota, (1) quem pode chamar, (2) sobre qual objeto, (3) o que entra e como chega ao banco ou à página, (4) o que sai.

## V1 - BOLA em `GET /consultas/{id}` (A01:2021 Broken Access Control, CWE-639)

```python
25  @router.get("/consultas/{consulta_id}", response_model=ConsultaPublic)
26  def obter_consulta(
27      consulta_id: int,
28      sessao: SessaoDep,
29      _: Annotated[Principal, Security(obter_principal, scopes=["consultas:ler"])],
30  ):
31      consulta = database.detalhar_consulta(sessao, consulta_id)
```

O padrão: a rota responde as perguntas (1) e não a (2). A linha 29 garante token válido com escopo `consultas:ler`, que todo paciente tem. O principal é descartado (`_`) e a linha 31 carrega o objeto só pelo id da URL. Nada compara `consulta.paciente_id` com quem chamou.

Reprodução (`evidencias/ex08-reproducao-vulnerabilidades.txt`): o paciente João, dono da consulta 1, pede `/inseguro/consultas/2` e recebe 200 com nome, profissional e motivo clínico da paciente Maria ("Lesão de pele suspeita no braço esquerdo"). Os ids são sequenciais, então um laço com uma conta legítima varre a base.

Por que é grave aqui: o objeto vazado é dado de saúde de terceiro, o titular não tem como perceber o acesso e não havia registro de quem leu.

## V2 - SQL injection na busca de pacientes (A03:2021 Injection, CWE-89)

```python
43      sql = f"SELECT id, nome, cpf, email FROM paciente WHERE nome LIKE '%{nome}%' ORDER BY nome"
44      linhas = sessao.connection().execute(text(sql)).all()
```

O parâmetro `nome` entra por f-string no texto do comando. Uma aspa encerra o literal e o restante vira SQL. Reprodução: `' OR '1'='1` devolve todos os pacientes com CPF completo; `x' UNION SELECT id, email, senha_hash, papel FROM usuario --` devolve e-mail e hash bcrypt de todos os usuários no lugar de nome e CPF. Agravante: a rota sem `response_model` (linha 37) também devolve o CPF inteiro.

## V3 - XSS armazenado na agenda (A03:2021 Injection, CWE-79)

```html
18                <td>{{ c.observacoes|safe }}</td>
```

`|safe` desliga o autoescape. O campo `observacoes` é escrito pela profissional e exibido para a recepção: um `<script>` gravado em uma consulta executa no navegador da recepção sempre que a agenda for aberta. A página vulnerável também exibe o `motivo` clínico para a recepção (exposição excessiva). Reprodução em `tela-05-agenda-insegura-xss-executado.png`.

## V4 - Mass assignment na criação de consulta (A04:2021 Insecure Design, CWE-915)

```python
62      corpo: dict,
...
66      dados = {
67          "profissional_id": principal.usuario.profissional_id,
68          "criado_por_id": principal.usuario.id,
69          "token_auditoria": "aud_demo",
70          **corpo,
71      }
```

O corpo é um `dict` sem contrato e é espalhado por último, então sobrescreve os campos que o servidor deveria controlar. Reprodução: a Dra. Helena cria uma consulta com `profissional_id: 2`, `criado_por_id: 4` e `token_auditoria: "aud_forjado"`, que fica registrada em nome do Dr. Marcos, para paciente que não é dela, com a trilha falsificada. A resposta (linha 77) ainda devolve o registro inteiro, campos internos inclusive.

## V5 - Falhas de autenticação no login (A07:2021 Identification and Authentication Failures, CWE-307, CWE-204, CWE-308)

```python
91  @limiter.exempt
...
99      if usuario is None:
100         raise HTTPException(status_code=401, detail="Usuário não cadastrado")
101     if not security.verificar_senha(password, usuario.senha_hash):
102         raise HTTPException(status_code=401, detail="Senha incorreta")
```

Três defeitos: sem limite de requisições nem bloqueio (linha 91), mensagens diferentes que transformam o login num oráculo de e-mails cadastrados (linhas 100 e 102) e emissão de token para administrador sem segundo fator (linha 106 grava `mfa: False` para qualquer papel). Reprodução: 8 tentativas seguidas recebem 401 sem 429; e-mail inexistente responde "Usuário não cadastrado"; o administrador recebe token só com a senha.

## V6 - Configuração insegura de resposta (A05:2021 Security Misconfiguration, CWE-693)

As respostas do router vulnerável saem sem `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options` e CSP. Sem CSP, o XSS de V3 executa; sem `X-Frame-Options`, a agenda pode ser emoldurada por outro site. A versão anterior ao Exercício 10 também usava CORS com `allow_origins=["*"]`, padrão que reprovou o outro serviço citado no enunciado.

## Resumo

| ID | Vulnerabilidade | OWASP 2021 | CWE | Ameaça | Correção |
|---|---|---|---|---|---|
| V1 | BOLA em consulta | A01 | 639 | T-01 | Exercício 9 |
| V2 | SQL injection na busca | A03 | 89 | T-09 | Exercícios 9 e 11 |
| V3 | XSS armazenado | A03 | 79 | T-10 | Exercício 9 |
| V4 | Mass assignment | A04 | 915 | T-11 | Exercício 9 |
| V5 | Login sem limite, enumeração e sem MFA | A07 | 307, 204, 308 | T-05, T-21, T-08 | Exercícios 6 e 10 |
| V6 | Sem cabeçalhos de segurança / CORS aberto | A05 | 693, 942 | T-13, T-14 | Exercício 10 |

São cinco categorias distintas do OWASP Top 10 (A01, A03, A04, A05, A07), incluindo a BOLA exigida.
