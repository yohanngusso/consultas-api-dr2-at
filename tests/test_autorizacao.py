"""Testes de autorização. Ex. 6: rota administrativa. Ex. 12: vetores do threat model, identificados pelo ID da ameaça."""

import base64
import json
import time

import jwt
import pytest

from app.auth.permissoes import AUDIENCIA_LABORATORIO, AUDIENCIA_USUARIOS
from app.config import configuracoes
from conftest import HELENA, JOAO, MARCOS, MARIA, RECEPCAO, amanha_as, entrar_na_recepcao

ROTAS_ADMINISTRATIVAS = ["/admin/usuarios", "/admin/auditoria"]


def _token_assinado(claims: dict, segredo: str | None = None, algoritmo: str = "HS256") -> dict:
    agora = int(time.time())
    payload = {"iss": "consultas-api", "iat": agora, "exp": agora + 600, "jti": "teste", **claims}
    chave = segredo or configuracoes().jwt_secret.get_secret_value()
    return {"Authorization": f"Bearer {jwt.encode(payload, chave, algorithm=algoritmo)}"}


def _claims_da_helena(**alteracoes) -> dict:
    return {
        "sub": "3",
        "aud": AUDIENCIA_USUARIOS,
        "tipo": "usuario",
        "papel": "profissional",
        "scope": "consultas:ler consultas:escrever pacientes:ler profissionais:ler",
        "mfa": False,
        **alteracoes,
    }


@pytest.mark.parametrize("credenciais", [HELENA, RECEPCAO, JOAO], ids=["profissional", "recepcionista", "paciente"])
@pytest.mark.parametrize("rota", ROTAS_ADMINISTRATIVAS)
def test_t03_usuario_sem_papel_de_administrador_nao_acessa_rota_administrativa(cliente, autenticar, credenciais, rota):
    resposta = cliente.get(rota, headers=autenticar(credenciais))
    assert resposta.status_code == 403


def test_t03_administrador_com_mfa_acessa_rota_administrativa(cliente, autenticar):
    resposta = cliente.get("/admin/usuarios", headers=autenticar("admin"))
    assert resposta.status_code == 200
    assert all("senha_hash" not in u for u in resposta.json())


def test_t03_profissional_que_pede_escopo_admin_nao_o_recebe(cliente):
    email, senha = HELENA
    resposta = cliente.post("/auth/token", data={"username": email, "password": senha, "scope": "admin consultas:ler"})
    assert resposta.json()["scope"] == "consultas:ler"


def test_t08_senha_do_administrador_sozinha_nao_emite_token(cliente):
    resposta = cliente.post("/auth/token", data={"username": "admin@clinica.dev", "password": "SenhaAdmin#2026"})
    assert resposta.status_code == 200
    assert "access_token" not in resposta.json()
    assert resposta.json()["mfa_required"] is True


def test_t08_codigo_mfa_errado_e_recusado(cliente):
    desafio = cliente.post("/auth/token", data={"username": "admin@clinica.dev", "password": "SenhaAdmin#2026"}).json()
    resposta = cliente.post("/auth/mfa", json={"challenge_id": desafio["challenge_id"], "codigo": "000000"})
    assert resposta.status_code == 401


def test_t08_token_de_administrador_sem_claim_mfa_e_recusado(cliente):
    claims = {"sub": "1", "aud": AUDIENCIA_USUARIOS, "tipo": "usuario", "papel": "administrador", "scope": "admin", "mfa": False}
    resposta = cliente.get("/admin/usuarios", headers=_token_assinado(claims))
    assert resposta.status_code == 403


def test_t01_paciente_le_a_propria_consulta(cliente, autenticar):
    assert cliente.get("/consultas/1", headers=autenticar(JOAO)).status_code == 200


@pytest.mark.parametrize("consulta_id", [2, 3])
def test_t01_paciente_nao_le_consulta_de_outro_paciente(cliente, autenticar, consulta_id):
    resposta = cliente.get(f"/consultas/{consulta_id}", headers=autenticar(JOAO))
    assert resposta.status_code == 403
    assert "motivo" not in resposta.text


def test_t01_profissional_nao_le_consulta_de_outro_profissional(cliente, autenticar):
    assert cliente.get("/consultas/2", headers=autenticar(HELENA)).status_code == 403
    assert cliente.get("/consultas/1", headers=autenticar(MARCOS)).status_code == 403


def test_t01_enumeracao_sequencial_nao_vaza_nenhum_registro_alheio(cliente, autenticar):
    cabecalhos = autenticar(MARIA)
    vazados = [i for i in range(1, 10) if cliente.get(f"/consultas/{i}", headers=cabecalhos).status_code == 200]
    assert vazados == [2]


def test_t01_id_inexistente_responde_404_e_nao_403(cliente, autenticar):
    assert cliente.get("/consultas/999", headers=autenticar(JOAO)).status_code == 404


def test_t02_profissional_nao_le_cadastro_de_paciente_de_outro_profissional(cliente, autenticar):
    assert cliente.get("/pacientes/2", headers=autenticar(HELENA)).status_code == 403
    assert cliente.get("/pacientes/1", headers=autenticar(HELENA)).status_code == 200


def test_t02_busca_do_profissional_so_retorna_os_proprios_pacientes(cliente, autenticar):
    resultado = cliente.get("/pacientes/busca?nome=Maria", headers=autenticar(HELENA))
    assert resultado.status_code == 200
    assert resultado.json() == []


def test_t02_profissional_nao_agenda_consulta_para_paciente_de_outro(cliente, autenticar):
    nova = {"paciente_id": 2, "inicio": amanha_as(15), "motivo": "Consulta indevida"}
    assert cliente.post("/consultas", json=nova, headers=autenticar(HELENA)).status_code == 403


def test_t20_paciente_nao_altera_nem_cancela_consulta(cliente, autenticar):
    cabecalhos = autenticar(JOAO)
    alteracao = {"inicio": amanha_as(15), "duracao_minutos": 30, "status": "cancelada", "motivo": "Teste"}
    assert cliente.put("/consultas/1", json=alteracao, headers=cabecalhos).status_code == 403
    assert cliente.delete("/consultas/1", headers=cabecalhos).status_code == 403


def test_t20_profissional_nao_altera_consulta_de_outro_profissional(cliente, autenticar):
    alteracao = {"inicio": amanha_as(15), "duracao_minutos": 30, "status": "cancelada", "motivo": "Teste"}
    assert cliente.put("/consultas/2", json=alteracao, headers=autenticar(HELENA)).status_code == 403
    assert cliente.delete("/consultas/2", headers=autenticar(HELENA)).status_code == 403


def test_t04_laboratorio_le_horarios_disponiveis(cliente, autenticar):
    dia = amanha_as(8)[:10]
    resposta = cliente.get(f"/laboratorio/horarios-disponiveis?data={dia}&especialidade=cardiologia",
                           headers=autenticar("laboratorio"))
    assert resposta.status_code == 200
    horarios = resposta.json()
    assert horarios
    assert all(set(h) == {"profissional_id", "profissional_nome", "especialidade", "inicio", "fim"} for h in horarios)
    assert not any(h["inicio"].endswith("T11:00:00") for h in horarios)


@pytest.mark.parametrize("rota", ["/consultas", "/consultas/1", "/pacientes/1", "/pacientes/busca?nome=Jo", "/admin/usuarios"])
def test_t04_token_do_laboratorio_nao_alcanca_dados_de_pacientes(cliente, autenticar, rota):
    assert cliente.get(rota, headers=autenticar("laboratorio")).status_code == 403


def test_t04_laboratorio_nao_obtem_escopo_fora_do_contrato(cliente):
    base = {"grant_type": "client_credentials", "client_id": "laboratorio-parceiro",
            "client_secret": "e784ad17f9385f8f221db15796c5bff8"}
    somente_fora = cliente.post("/auth/token", data={**base, "scope": "consultas:ler pacientes:ler"})
    assert somente_fora.status_code == 400
    misto = cliente.post("/auth/token", data={**base, "scope": "horarios:ler consultas:ler admin"})
    assert misto.json()["scope"] == "horarios:ler"


def test_t04_token_do_laboratorio_nao_carrega_dados_pessoais(cliente, autenticar):
    token = autenticar("laboratorio")["Authorization"].split()[1]
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert claims["aud"] == AUDIENCIA_LABORATORIO
    assert claims["tipo"] == "servico"
    assert claims["scope"] == "horarios:ler"
    assert not {"email", "nome", "amr"} & set(claims)


def test_t04_usuario_nao_usa_a_rota_do_laboratorio(cliente, autenticar):
    resposta = cliente.get("/laboratorio/horarios-disponiveis?especialidade=cardiologia", headers=autenticar(HELENA))
    assert resposta.status_code == 403


def test_t06_token_com_alg_none_e_recusado(cliente):
    cabecalho = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    agora = int(time.time())
    corpo = base64.urlsafe_b64encode(json.dumps({
        **_claims_da_helena(papel="administrador", scope="admin", mfa=True, sub="1"),
        "iss": "consultas-api", "iat": agora, "exp": agora + 600, "jti": "x",
    }).encode()).rstrip(b"=").decode()
    resposta = cliente.get("/admin/usuarios", headers={"Authorization": f"Bearer {cabecalho}.{corpo}."})
    assert resposta.status_code == 401


def test_t06_token_assinado_com_outra_chave_e_recusado(cliente):
    cabecalhos = _token_assinado(_claims_da_helena(), segredo="chave-do-atacante-com-mais-de-32-caracteres")
    assert cliente.get("/consultas", headers=cabecalhos).status_code == 401


def test_t06_payload_adulterado_sem_reassinatura_e_recusado(cliente, autenticar):
    token = autenticar(HELENA)["Authorization"].split()[1]
    cabecalho, corpo, assinatura = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(corpo + "=="))
    claims.update(papel="administrador", scope="admin", mfa=True, sub="1")
    corpo_falso = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    resposta = cliente.get("/admin/usuarios", headers={"Authorization": f"Bearer {cabecalho}.{corpo_falso}.{assinatura}"})
    assert resposta.status_code == 401


def test_t06_papel_divergente_do_cadastro_e_recusado(cliente):
    cabecalhos = _token_assinado(_claims_da_helena(papel="administrador", scope="admin", mfa=True))
    assert cliente.get("/admin/usuarios", headers=cabecalhos).status_code == 401


def test_t07_token_expirado_e_recusado(cliente):
    agora = int(time.time())
    payload = {**_claims_da_helena(), "iss": "consultas-api", "iat": agora - 3600, "exp": agora - 60, "jti": "x"}
    token = jwt.encode(payload, configuracoes().jwt_secret.get_secret_value(), algorithm="HS256")
    resposta = cliente.get("/consultas", headers={"Authorization": f"Bearer {token}"})
    assert resposta.status_code == 401
    assert resposta.json()["detail"] == "Token expirado"


def test_t07_token_sem_expiracao_e_recusado(cliente):
    payload = {**_claims_da_helena(), "iss": "consultas-api", "iat": int(time.time()), "jti": "x"}
    token = jwt.encode(payload, configuracoes().jwt_secret.get_secret_value(), algorithm="HS256")
    assert cliente.get("/consultas", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_t07_token_de_usuario_com_audiencia_do_laboratorio_e_recusado(cliente):
    cabecalhos = _token_assinado(_claims_da_helena(aud=AUDIENCIA_LABORATORIO))
    assert cliente.get("/consultas", headers=cabecalhos).status_code == 401


def test_t07_usuario_desativado_perde_acesso_com_token_ainda_valido(cliente, autenticar):
    from sqlmodel import Session

    from app import database

    cabecalhos = autenticar(HELENA)
    with Session(database.engine) as sessao:
        usuario = database.obter_usuario_por_id(sessao, 3)
        usuario.ativo = False
        sessao.add(usuario)
        sessao.commit()
    assert cliente.get("/consultas", headers=cabecalhos).status_code == 401


@pytest.mark.parametrize("campo_extra", [
    {"profissional_id": 2},
    {"token_auditoria": "aud_forjado"},
    {"criado_por_id": 1},
    {"status": "realizada"},
])
def test_t11_mass_assignment_e_recusado_com_422(cliente, autenticar, campo_extra):
    nova = {"paciente_id": 3, "inicio": amanha_as(15), "motivo": "Avaliação", **campo_extra}
    resposta = cliente.post("/consultas", json=nova, headers=autenticar(HELENA))
    assert resposta.status_code == 422
    assert resposta.json()["detail"][0]["type"] == "extra_forbidden"


def test_t15_acesso_negado_fica_registrado_na_trilha_de_auditoria(cliente, autenticar):
    cliente.get("/consultas/2", headers=autenticar(JOAO))
    trilha = cliente.get("/admin/auditoria", headers=autenticar("admin")).json()
    assert any(
        r["ator"] == "5" and r["acao"] == "ler_consulta" and r["recurso_id"] == "2" and r["resultado"] == "negado"
        for r in trilha
    )


@pytest.mark.parametrize("rota", ["/consultas", "/consultas/1", "/pacientes/1", "/profissionais", "/auth/eu"])
def test_t01_rotas_protegidas_exigem_token(cliente, rota):
    resposta = cliente.get(rota)
    assert resposta.status_code == 401
    assert resposta.headers["www-authenticate"] == "Bearer"


def test_t19_agenda_web_sem_sessao_redireciona_para_login(cliente):
    resposta = cliente.get("/web/agenda", follow_redirects=False)
    assert resposta.status_code == 303
    assert resposta.headers["location"] == "/web/login"


def test_t19_profissional_nao_entra_na_agenda_da_recepcao(cliente):
    resposta = entrar_na_recepcao(cliente, HELENA)
    assert resposta.status_code == 403
    assert "sessao_clinica" not in resposta.headers.get("set-cookie", "")
