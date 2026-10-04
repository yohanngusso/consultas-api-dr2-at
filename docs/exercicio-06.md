# Exercício 6 - Autenticação e autorização

## OAuth2PasswordBearer e bcrypt

- `oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token", scopes=ESCOPOS_DISPONIVEIS)` em `app/auth/dependencies.py` declara o fluxo no OpenAPI (o Swagger mostra os escopos no botão Authorize). Ele usa `auto_error=False` porque quem valida o token é o middleware centralizado do Exercício 9; o esquema fica para documentação e para o Swagger enviar o cabeçalho.
- Senhas e o segredo do laboratório são guardados com bcrypt custo 12 (`app/auth/security.py`). A biblioteca `bcrypt` é usada diretamente: o passlib não é mantido e falha no Python 3.14.
- O bcrypt só considera os primeiros 72 bytes. Em vez de truncar em silêncio (duas senhas diferentes passariam a valer igual), senha acima de 72 bytes é recusada no cadastro e tratada como credencial inválida no login.
- Login de e-mail inexistente ainda executa um `checkpw` contra um hash fictício, para que o tempo de resposta não revele quais e-mails existem. A mensagem é a mesma nos dois casos.
- No banco só existe hash. As contas de avaliação são carregadas por `app/seed.py` com hashes pré-computados, e o módulo só roda com `CLINICA_CARREGAR_DADOS_DEMONSTRACAO=true`.

## JWT com expiração

| Claim | Valor | Motivo |
|---|---|---|
| `iss` | `consultas-api` | Recusa token de outro emissor |
| `aud` | `consultas-api` (pessoas) ou `consultas-api:laboratorio` (parceiro) | Separa populações; conferida contra o `tipo` |
| `sub` | id do usuário ou client_id | Identidade |
| `tipo` | `usuario` ou `servico` | Rotas exclusivas de pessoa ou de serviço |
| `papel` | recepcionista, profissional, paciente, administrador | RBAC; conferido contra o cadastro a cada requisição |
| `scope` | escopos concedidos | Autorização grossa |
| `amr`, `mfa` | `["pwd"]` ou `["pwd","otp"]` | Rota administrativa exige `mfa=true` |
| `iat`, `exp`, `jti` | 15 min para pessoas, 10 min para o laboratório | Janela curta reduz o impacto de vazamento |

`decodificar_token` fixa `algorithms=["HS256"]` (impede `alg=none` e troca de algoritmo) e exige `exp`, `iat`, `sub`, `iss`, `aud` e `jti`. `obter_principal` recarrega o usuário do banco: conta desativada ou com papel alterado perde o acesso na hora, sem esperar o token vencer.

## MFA simulado para contas administrativas

1. `POST /auth/token` com a senha correta de um usuário com `mfa_obrigatorio` devolve um desafio (`challenge_id`), nunca um token.
2. O código de 6 dígitos é gerado com `secrets` e entregue pelo canal simulado (log `[MFA]` do servidor).
3. `POST /auth/mfa` valida com `secrets.compare_digest`. O desafio vale 5 minutos, aceita no máximo 3 tentativas e é de uso único.
4. O token emitido carrega `amr=["pwd","otp"]` e `mfa=true`. `exigir_administrador` recusa token de administrador sem essa claim, de modo que um token forjado ou emitido por outro caminho não abre as rotas administrativas.

## Sessão segura da recepção

A página interna usa cookie em vez de Bearer, porque é um navegador comum. O cookie `sessao_clinica` é `HttpOnly` (JavaScript não lê), `Secure` (configurável apenas para desenvolvimento sem HTTPS), `SameSite=Strict`, `Path=/web`, expira em 15 minutos e carrega um token com apenas o escopo `agenda:ler`, mesmo que o papel tenha outros. O login e o logout exigem token anti-CSRF (Exercício 13).

## Modelo de autorização escolhido

| Modelo | Avaliação para este sistema |
|---|---|
| RBAC puro | Resolve "recepcionista não acessa rota administrativa", mas não "profissional só vê os próprios pacientes": os dois profissionais têm o mesmo papel |
| ABAC | Expressaria tudo por atributos, mas exige motor de políticas, é difícil de auditar e de testar, e as regras deste domínio são poucas e estáveis |
| Autorização por recurso (ownership) | Resolve exatamente o caso do enunciado: o dono do objeto é um atributo do próprio registro |

Decisão: **RBAC para permissões grossas + autorização por recurso**. O papel define os escopos que o token pode receber (`app/auth/permissoes.py`); a posse do objeto é verificada por `exigir_posse` com regras explícitas:

| Regra | Quem passa |
|---|---|
| `pode_ler_consulta` | Administrador; profissional dono (`consulta.profissional_id`); paciente titular (`consulta.paciente_id`) |
| `pode_alterar_consulta` | Administrador; profissional dono |
| `pode_ler_paciente` | Administrador; recepção; profissional responsável |
| Criar consulta | Somente profissional, e só para paciente sob sua responsabilidade |

Matriz de escopos por papel:

| Escopo | Recepcionista | Profissional | Paciente | Administrador | Laboratório |
|---|---|---|---|---|---|
| `consultas:ler` | | x | x | x | |
| `consultas:escrever` | | x | | x | |
| `agenda:ler` | x | | | x | |
| `pacientes:ler` | x | x | | x | |
| `pacientes:criar` | x | | | x | |
| `profissionais:ler` | x | x | x | x | |
| `admin` | | | | x | |
| `horarios:ler` | | | | | x |

## Teste de autorização

`tests/test_autorizacao.py::test_t03_usuario_sem_papel_de_administrador_nao_acessa_rota_administrativa` é parametrizado para profissional, recepcionista e paciente contra `/admin/usuarios` e `/admin/auditoria` e espera 403 em todos. É o primeiro teste da suíte de autorização ampliada no Exercício 12.

Evidência: `evidencias/ex06-autenticacao-autorizacao.txt`.
