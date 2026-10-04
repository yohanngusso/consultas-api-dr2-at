# Exercício 4 - Modelagem de ameaças com STRIDE

O threat model consolidado está em [threat-model.md](threat-model.md) e é o documento de referência para os exercícios seguintes. Este arquivo resume o método e as decisões.

## Método

1. Partir do DFD do Exercício 3 e listar os ativos pela consequência de perda (seção 2 do threat model).
2. Enumerar as superfícies de ataque por rota e por canal (seção 3).
3. Escrever misuse cases a partir dos atores reais do enunciado, inclusive os internos: paciente autenticado, profissional curioso, recepcionista, parceiro com token vazado e insider com acesso ao repositório (seção 4).
4. Aplicar STRIDE a cinco componentes (C1 a C5), uma linha por letra, para não deixar categoria sem análise (seção 5).
5. Consolidar em um catálogo único T-01 a T-22, cada ameaça com categoria OWASP, ativo, mitigação, arquivo e teste (seção 6).

## Misuse cases principais

| ID | Caso | Por que importa neste domínio |
|---|---|---|
| MC-01 | Paciente enumera consultas trocando o id | É o incidente descrito no Exercício 8; expõe dado de saúde de terceiros |
| MC-03 | Token do laboratório vazado usado para ler pacientes | O contrato limita o parceiro a horários; a limitação precisa valer mesmo com o token comprometido |
| MC-04 | Força bruta no login da recepção | Já ocorreu em testes anteriores segundo o Exercício 10 |
| MC-05 | Script nas observações sequestrando a sessão da recepção | A recepção vê a agenda de todos os profissionais: um XSS ali alcança dado de toda a clínica |
| MC-08 | Recepcionista lendo motivo clínico | Ameaça interna; a recepção não precisa do dado para trabalhar |

## Decisões

- Ameaça interna entra no modelo. Em saúde, boa parte dos incidentes envolve pessoas com acesso legítimo olhando o que não deveriam; por isso MC-02 e MC-08 existem e a trilha de auditoria (T-15) registra também os acessos permitidos.
- Cada ameaça tem um teste com o ID no nome (`test_t01_...`). Assim o threat model deixa de ser só documento: se uma mitigação regredir, o pipeline do Exercício 12 aponta qual ameaça voltou a ficar aberta.
- A priorização de risco das ameaças que viraram vulnerabilidades reais está no Exercício 12, com CVSS 3.1. A rastreabilidade até a evidência final está no Exercício 13.
