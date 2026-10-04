import pytest

from conftest import HELENA, RECEPCAO, amanha_as

PAYLOADS_SQLI = [
    "' OR '1'='1",
    "x' UNION SELECT id, email, senha_hash, papel FROM usuario --",
    "Jo%",
    "Jo_o",
    "'; DROP TABLE paciente; --",
    "Maria\") OR 1=1 --",
    "a/**/OR/**/1=1",
]


def test_busca_legitima_de_paciente_funciona(cliente, autenticar):
    resposta = cliente.get("/pacientes/busca?nome=Pedro", headers=autenticar(RECEPCAO))
    assert resposta.status_code == 200
    assert [p["nome"] for p in resposta.json()] == ["Pedro Albuquerque"]
    assert resposta.json()[0]["cpf_mascarado"] == "***.091.390-**"


def test_busca_aceita_nome_acentuado(cliente, autenticar):
    resposta = cliente.get("/pacientes/busca?nome=João", headers=autenticar(RECEPCAO))
    assert [p["nome"] for p in resposta.json()] == ["João Batista"]


@pytest.mark.parametrize("payload", PAYLOADS_SQLI)
def test_t09_payload_de_sql_injection_e_recusado_na_busca(cliente, autenticar, payload):
    resposta = cliente.get("/pacientes/busca", params={"nome": payload}, headers=autenticar(RECEPCAO))
    assert resposta.status_code == 422
    assert payload not in resposta.text


def test_t09_termo_curto_ou_longo_demais_e_recusado(cliente, autenticar):
    cabecalhos = autenticar(RECEPCAO)
    assert cliente.get("/pacientes/busca?nome=a", headers=cabecalhos).status_code == 422
    assert cliente.get("/pacientes/busca", params={"nome": "a" * 61}, headers=cabecalhos).status_code == 422


@pytest.mark.parametrize("especialidade", ["cardiologia' OR '1'='1", "neurologia", "CARDIOLOGIA"])
def test_t09_especialidade_fora_da_whitelist_e_recusada(cliente, autenticar, especialidade):
    resposta = cliente.get("/laboratorio/horarios-disponiveis", params={"especialidade": especialidade},
                           headers=autenticar("laboratorio"))
    assert resposta.status_code == 422


def test_data_fora_da_janela_e_recusada(cliente, autenticar):
    resposta = cliente.get("/consultas/agenda?data=2099-01-01", headers=autenticar(RECEPCAO))
    assert resposta.status_code == 422


@pytest.mark.parametrize("alteracao, motivo", [
    ({"inicio": "2020-01-10T10:00:00"}, "passado"),
    ({"inicio": amanha_as(22)}, "fora do expediente"),
    ({"inicio": amanha_as(10, 10)}, "fora da grade de 15 minutos"),
    ({"duracao_minutos": 500}, "duração acima do limite"),
    ({"duracao_minutos": 20}, "duração fora do múltiplo de 15"),
    ({"motivo": "x"}, "motivo curto demais"),
    ({"motivo": "a" * 301}, "motivo longo demais"),
    ({"observacoes": "texto\x00com nulo"}, "caractere de controle"),
    ({"paciente_id": -1}, "id negativo"),
    ({"paciente_id": "1 OR 1=1"}, "id não inteiro"),
])
def test_corpo_de_consulta_invalido_e_recusado(cliente, autenticar, alteracao, motivo):
    nova = {"paciente_id": 3, "inicio": amanha_as(15), "motivo": "Avaliação de rotina", **alteracao}
    resposta = cliente.post("/consultas", json=nova, headers=autenticar(HELENA))
    assert resposta.status_code == 422, motivo


def test_status_fora_da_whitelist_e_recusado(cliente, autenticar):
    alteracao = {"inicio": amanha_as(15), "duracao_minutos": 30, "status": "apagada", "motivo": "Retorno"}
    assert cliente.put("/consultas/4", json=alteracao, headers=autenticar(HELENA)).status_code == 422


PACIENTE_VALIDO = {
    "nome": "Ana Clara D'Ávila",
    "cpf": "996.030.824-30",
    "data_nascimento": "1990-04-20",
    "email": "ana.clara@paciente.dev",
    "telefone": "(21) 99999-0000",
    "profissional_responsavel_id": 1,
}


def test_recepcao_cadastra_paciente_valido(cliente, autenticar):
    resposta = cliente.post("/pacientes", json=PACIENTE_VALIDO, headers=autenticar(RECEPCAO))
    assert resposta.status_code == 201
    assert resposta.json()["cpf_mascarado"] == "***.030.824-**"
    assert "cpf" not in resposta.json()


@pytest.mark.parametrize("alteracao", [
    {"cpf": "111.111.111-11"},
    {"cpf": "996.030.824-31"},
    {"cpf": "99603082430"},
    {"nome": "<script>alert(1)</script>"},
    {"nome": "Robert'); DROP TABLE paciente;--"},
    {"telefone": "21999990000"},
    {"email": "nao-e-email"},
    {"data_nascimento": "2999-01-01"},
    {"profissional_responsavel_id": 0},
    {"papel": "administrador"},
])
def test_cadastro_de_paciente_invalido_e_recusado(cliente, autenticar, alteracao):
    resposta = cliente.post("/pacientes", json={**PACIENTE_VALIDO, **alteracao}, headers=autenticar(RECEPCAO))
    assert resposta.status_code == 422


def test_cpf_duplicado_e_recusado(cliente, autenticar):
    cabecalhos = autenticar(RECEPCAO)
    duplicado = {**PACIENTE_VALIDO, "cpf": "526.018.159-06"}
    assert cliente.post("/pacientes", json=duplicado, headers=cabecalhos).status_code == 409


def test_profissional_nao_cadastra_paciente(cliente, autenticar):
    assert cliente.post("/pacientes", json=PACIENTE_VALIDO, headers=autenticar(HELENA)).status_code == 403


def test_t10_observacao_com_html_e_armazenada_como_texto_no_json(cliente, autenticar):
    payload = '<img src=x onerror="alert(document.cookie)">'
    alteracao = {"inicio": amanha_as(15), "duracao_minutos": 30, "status": "agendada",
                 "motivo": "Retorno", "observacoes": payload}
    resposta = cliente.put("/consultas/4", json=alteracao, headers=autenticar(HELENA))
    assert resposta.status_code == 200
    assert resposta.json()["observacoes"] == payload
    assert resposta.headers["content-type"] == "application/json"
    assert resposta.headers["x-content-type-options"] == "nosniff"


def test_senha_acima_do_limite_do_bcrypt_e_tratada_como_credencial_invalida(cliente):
    resposta = cliente.post("/auth/token", data={"username": "helena@clinica.dev", "password": "A" * 100})
    assert resposta.status_code == 401


def test_grant_type_desconhecido_e_recusado(cliente):
    resposta = cliente.post("/auth/token", data={"grant_type": "implicit", "username": "x", "password": "y"})
    assert resposta.status_code == 422


def test_erro_de_validacao_nao_reflete_o_valor_enviado(cliente, autenticar):
    nova = {"paciente_id": 3, "inicio": amanha_as(15), "motivo": "Avaliação", "token_auditoria": "valor-sensivel-refletido"}
    resposta = cliente.post("/consultas", json=nova, headers=autenticar(HELENA))
    assert resposta.status_code == 422
    assert "valor-sensivel-refletido" not in resposta.text
    assert set(resposta.json()["detail"][0]) == {"type", "loc", "msg"}
