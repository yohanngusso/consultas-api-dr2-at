# Auditoria da especificação OpenAPI

Operações analisadas: 17. Achados: 15.

| Severidade | Operação | Achado |
|---|---|---|
| MEDIA | `securitySchemes` | fluxo OAuth2 'clientCredentials' aceito pelo /auth/token não está declarado |
| BAIXA | `GET /auth/eu` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /consultas` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `POST /consultas` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /consultas/agenda` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /consultas/{consulta_id}` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `PUT /consultas/{consulta_id}` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `DELETE /consultas/{consulta_id}` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /pacientes/busca` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /pacientes/{paciente_id}` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `POST /pacientes` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /profissionais` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /laboratorio/horarios-disponiveis` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /admin/usuarios` | respostas de erro não documentadas: 401, 403, 429 |
| BAIXA | `GET /admin/auditoria` | respostas de erro não documentadas: 401, 403, 429 |
