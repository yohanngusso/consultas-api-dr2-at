# Auditoria da especificação OpenAPI

Operações analisadas: 23. Achados: 12.

| Severidade | Operação | Achado |
|---|---|---|
| BAIXA | `GET /inseguro/consultas/{consulta_id}` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /inseguro/pacientes/busca` | respostas de erro não documentadas: 401, 403, 429 |
| MEDIA | `GET /inseguro/pacientes/busca` | parâmetro 'nome' sem limite de tamanho, padrão ou enum |
| BAIXA | `GET /inseguro/pacientes/{paciente_id}` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `POST /inseguro/consultas` | respostas de erro não documentadas: 401, 403, 429 |
| MEDIA | `POST /inseguro/consultas` | corpo JSON aceita campos não declarados (falta extra='forbid') |
| ALTA | `GET /inseguro/web/agenda` | operação não pública sem requisito de segurança |
| BAIXA | `GET /inseguro/web/agenda` | respostas de erro não documentadas: 401, 403, 429 |
| ALTA | `POST /inseguro/auth/token` | operação não pública sem requisito de segurança |
| BAIXA | `POST /inseguro/auth/token` | respostas de erro não documentadas: 401, 403, 429 |
| MEDIA | `POST /inseguro/auth/token` | campo 'username' do corpo sem limite de tamanho, padrão ou enum |
| MEDIA | `POST /inseguro/auth/token` | campo 'password' do corpo sem limite de tamanho, padrão ou enum |
