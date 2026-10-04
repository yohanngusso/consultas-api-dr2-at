"""Contas e registros de avaliação. Carregados apenas com CLINICA_CARREGAR_DADOS_DEMONSTRACAO=true."""

import secrets
from datetime import date, datetime, time, timedelta

from sqlmodel import Session, select

from app.db_models import ClienteM2M, Consulta, Paciente, Profissional, Usuario
from app.validators import agora_na_clinica


def popular_dados_iniciais(sessao: Session) -> None:
    if sessao.exec(select(Usuario)).first() is not None:
        return

    sessao.add_all([
        Profissional(id=1, nome="Dra. Helena Prado", especialidade="cardiologia", registro_conselho="CRM-RJ 52.1234-5"),
        Profissional(id=2, nome="Dr. Marcos Teixeira", especialidade="dermatologia", registro_conselho="CRM-RJ 52.9876-1"),
    ])
    sessao.flush()
    sessao.add_all([
        Paciente(id=1, nome="João Batista", cpf="526.018.159-06", data_nascimento=date(1980, 5, 12),
                 email="joao@paciente.dev", telefone="(21) 99876-5432", profissional_responsavel_id=1),
        Paciente(id=2, nome="Maria Fernandes", cpf="083.016.613-05", data_nascimento=date(1992, 11, 3),
                 email="maria@paciente.dev", telefone="(21) 98765-4321", profissional_responsavel_id=2),
        Paciente(id=3, nome="Pedro Albuquerque", cpf="186.091.390-34", data_nascimento=date(1975, 2, 28),
                 email="pedro@paciente.dev", telefone="(21) 3456-7890", profissional_responsavel_id=1),
    ])
    sessao.flush()
    sessao.add_all([
        Usuario(id=1, nome="Administração", email="admin@clinica.dev", papel="administrador", mfa_obrigatorio=True,
                senha_hash="$2b$12$fwB2FDZ9Gj0AymHy.RkmquA2JSi9iEcxGAeIUT/NI6cB4i6LYRw56"),
        Usuario(id=2, nome="Renata Lopes", email="recepcao@clinica.dev", papel="recepcionista",
                senha_hash="$2b$12$BTq.nr9QnFgoXbBGM2vtNu4Pgdz1s5baw9aUKIYc8gCc9zeWPxz2."),
        Usuario(id=3, nome="Dra. Helena Prado", email="helena@clinica.dev", papel="profissional", profissional_id=1,
                senha_hash="$2b$12$Vl3JjiAI8TU9lkKrYO8efuPk2p6SL0KkiefsQXcTtcheB08sld93y"),
        Usuario(id=4, nome="Dr. Marcos Teixeira", email="marcos@clinica.dev", papel="profissional", profissional_id=2,
                senha_hash="$2b$12$m267d2ro5w/FB.lEjQR1ZOYXNaZM/ySKXPNvqBltIyhT1Ls9.60iO"),
        Usuario(id=5, nome="João Batista", email="joao@paciente.dev", papel="paciente", paciente_id=1,
                senha_hash="$2b$12$Yb85/qgxz7ZvNSwYL9Ivp.B7VNkB9aSVJ/1qNa20rKuQb3dX5supy"),
        Usuario(id=6, nome="Maria Fernandes", email="maria@paciente.dev", papel="paciente", paciente_id=2,
                senha_hash="$2b$12$EJ.EU/sX7rkZ8zNE3EkKXeQJO7stdgJ9dtcM5n0uL7omIDmq5ltY."),
    ])
    sessao.add(ClienteM2M(
        client_id="laboratorio-parceiro",
        nome="Laboratório Análises Vida",
        segredo_hash="$2b$12$pRlG6Ef3viDtB7oRRZGQWO9ZLWbLjr8KGBcVXNvw6.W5yrIjPUmyS",
        escopos_contratados=["horarios:ler"],
    ))
    sessao.flush()

    hoje = agora_na_clinica().date()
    for id_, paciente, profissional, dia, hora, motivo, obs in [
        (1, 1, 1, hoje, 9, "Dor no peito ao esforço, avaliar ECG", "Trazer exames anteriores"),
        (2, 2, 2, hoje, 10, "Lesão de pele suspeita no braço esquerdo", "Paciente prefere contato por e-mail"),
        (3, 3, 1, hoje, 14, "Controle de hipertensão", ""),
        (4, 1, 1, hoje + timedelta(days=1), 11, "Retorno com resultado de holter", ""),
    ]:
        sessao.add(Consulta(
            id=id_, paciente_id=paciente, profissional_id=profissional,
            inicio=datetime.combine(dia, time(hora, 0)), motivo=motivo, observacoes=obs,
            token_auditoria=f"aud_{secrets.token_hex(8)}", criado_por_id=3 if profissional == 1 else 4,
            ip_origem="127.0.0.1",
        ))
    sessao.commit()
