"""Testes unitários com mocking (Ex. 13): regras de entrada e de autorização isoladas do banco e do relógio."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import validators
from app.auth import autenticacao, security
from app.auth.dependencies import (
    Principal,
    exigir_posse,
    obter_principal,
    pode_alterar_consulta,
    pode_ler_consulta,
    pode_ler_paciente,
)
from app.middlewares import GuardaAutorizacaoMiddleware

AGORA_FIXO = datetime(2026, 10, 5, 8, 0)


def _principal(papel: str, profissional_id=None, paciente_id=None) -> Principal:
    usuario = SimpleNamespace(id=99, profissional_id=profissional_id, paciente_id=paciente_id, ativo=True, papel=papel)
    return Principal(sub="99", tipo="usuario", papel=papel, escopos=[], usuario=usuario)


CONSULTA_DO_PROFISSIONAL_1 = SimpleNamespace(id=10, profissional_id=1, paciente_id=7)
PACIENTE_DO_PROFISSIONAL_1 = SimpleNamespace(id=7, profissional_responsavel_id=1)


@pytest.mark.parametrize("principal, esperado", [
    (_principal("profissional", profissional_id=1), True),
    (_principal("profissional", profissional_id=2), False),
    (_principal("paciente", paciente_id=7), True),
    (_principal("paciente", paciente_id=8), False),
    (_principal("recepcionista"), False),
    (_principal("administrador"), True),
    (_principal("papel_desconhecido"), False),
])
def test_regra_de_leitura_de_consulta(principal, esperado):
    assert pode_ler_consulta(principal, CONSULTA_DO_PROFISSIONAL_1) is esperado


@pytest.mark.parametrize("principal, esperado", [
    (_principal("profissional", profissional_id=1), True),
    (_principal("profissional", profissional_id=2), False),
    (_principal("paciente", paciente_id=7), False),
    (_principal("recepcionista"), False),
    (_principal("administrador"), True),
])
def test_regra_de_alteracao_de_consulta(principal, esperado):
    assert pode_alterar_consulta(principal, CONSULTA_DO_PROFISSIONAL_1) is esperado


@pytest.mark.parametrize("principal, esperado", [
    (_principal("profissional", profissional_id=1), True),
    (_principal("profissional", profissional_id=2), False),
    (_principal("recepcionista"), True),
    (_principal("paciente", paciente_id=7), False),
])
def test_regra_de_leitura_de_paciente(principal, esperado):
    assert pode_ler_paciente(principal, PACIENTE_DO_PROFISSIONAL_1) is esperado


def _requisicao(path_params: dict) -> MagicMock:
    requisicao = MagicMock()
    requisicao.path_params = path_params
    requisicao.state = SimpleNamespace()
    requisicao.client.host = "10.0.0.1"
    return requisicao


def _dependencia(carregar, pode_acessar):
    return exigir_posse(carregar=carregar, pode_acessar=pode_acessar, nome_parametro="consulta_id",
                        escopos=["consultas:ler"], recurso="Consulta", acao="ler_consulta")


@patch("app.auth.dependencies.database.registrar_auditoria")
def test_posse_negada_responde_403_audita_e_nao_marca_a_requisicao(auditoria):
    carregar = MagicMock(return_value=CONSULTA_DO_PROFISSIONAL_1)
    requisicao = _requisicao({"consulta_id": "10"})
    dependencia = _dependencia(carregar, pode_ler_consulta)

    with pytest.raises(HTTPException) as erro:
        dependencia(request=requisicao, sessao=MagicMock(), principal=_principal("profissional", profissional_id=2))

    assert erro.value.status_code == 403
    carregar.assert_called_once()
    assert auditoria.call_args.kwargs["resultado"] == "negado"
    assert not hasattr(requisicao.state, "posse_verificada")


@patch("app.auth.dependencies.database.registrar_auditoria")
def test_posse_confirmada_devolve_o_objeto_e_marca_a_requisicao(auditoria):
    requisicao = _requisicao({"consulta_id": "10"})
    dependencia = _dependencia(MagicMock(return_value=CONSULTA_DO_PROFISSIONAL_1), pode_ler_consulta)

    objeto = dependencia(request=requisicao, sessao=MagicMock(), principal=_principal("profissional", profissional_id=1))

    assert objeto is CONSULTA_DO_PROFISSIONAL_1
    assert requisicao.state.posse_verificada is True
    assert auditoria.call_args.kwargs["resultado"] == "permitido"


@pytest.mark.parametrize("bruto, retorno", [("abc", None), ("999", None)])
@patch("app.auth.dependencies.database.registrar_auditoria")
def test_objeto_inexistente_ou_id_malformado_responde_404_sem_consultar_regra(auditoria, bruto, retorno):
    regra = MagicMock()
    dependencia = _dependencia(MagicMock(return_value=retorno), regra)

    with pytest.raises(HTTPException) as erro:
        dependencia(request=_requisicao({"consulta_id": bruto}), sessao=MagicMock(), principal=_principal("administrador"))

    assert erro.value.status_code == 404
    regra.assert_not_called()
    auditoria.assert_not_called()


def _requisicao_com_claims(claims: dict | None) -> MagicMock:
    requisicao = _requisicao({})
    requisicao.state = SimpleNamespace(claims=claims) if claims is not None else SimpleNamespace()
    return requisicao


CLAIMS_HELENA = {"sub": "3", "aud": "consultas-api", "tipo": "usuario", "papel": "profissional",
                 "scope": "consultas:ler", "mfa": False}


@patch("app.auth.dependencies.database.obter_usuario_por_id")
def test_obter_principal_recusa_usuario_desativado(obter_usuario):
    obter_usuario.return_value = SimpleNamespace(id=3, ativo=False, papel="profissional")
    with pytest.raises(HTTPException) as erro:
        obter_principal(_requisicao_com_claims(CLAIMS_HELENA), SimpleNamespace(scopes=[]), MagicMock(), None)
    assert erro.value.status_code == 401


def test_obter_principal_sem_claims_do_middleware_recusa_com_401():
    with pytest.raises(HTTPException) as erro:
        obter_principal(_requisicao_com_claims(None), SimpleNamespace(scopes=[]), MagicMock(), None)
    assert erro.value.status_code == 401


@patch("app.auth.dependencies.database.registrar_auditoria")
@patch("app.auth.dependencies.database.obter_usuario_por_id")
def test_obter_principal_recusa_escopo_ausente_com_403(obter_usuario, auditoria):
    obter_usuario.return_value = SimpleNamespace(id=3, ativo=True, papel="profissional")
    with pytest.raises(HTTPException) as erro:
        obter_principal(_requisicao_com_claims(CLAIMS_HELENA), SimpleNamespace(scopes=["admin"]), MagicMock(), None)
    assert erro.value.status_code == 403
    assert auditoria.call_args.kwargs["resultado"] == "negado"


def test_guarda_bloqueia_rota_sensivel_que_esqueceu_a_verificacao_de_posse():
    app = FastAPI()
    app.add_middleware(GuardaAutorizacaoMiddleware)

    @app.get("/consultas/{consulta_id}")
    def rota_esquecida(consulta_id: int):
        return {"id": consulta_id, "motivo": "dado clínico"}

    resposta = TestClient(app).get("/consultas/1")
    assert resposta.status_code == 500
    assert "dado clínico" not in resposta.text


@patch("app.auth.autenticacao.auditar")
@patch("app.auth.autenticacao.security.verificar_senha", return_value=False)
@patch("app.auth.autenticacao.database.obter_usuario_por_email", return_value=None)
def test_login_de_email_inexistente_ainda_executa_o_bcrypt(_obter, verificar, _auditar):
    security.resetar_estado_em_memoria()
    with pytest.raises(HTTPException) as erro:
        autenticacao.autenticar_usuario(MagicMock(), MagicMock(), "ninguem@clinica.dev", "x")
    assert erro.value.status_code == 401
    verificar.assert_called_once_with("x", None)


@patch("app.auth.autenticacao.auditar")
@patch("app.auth.autenticacao.database.obter_usuario_por_email")
def test_bloqueio_por_identidade_impede_login_mesmo_com_senha_correta(obter_usuario, _auditar):
    security.resetar_estado_em_memoria()
    obter_usuario.return_value = SimpleNamespace(id=3, ativo=True, senha_hash=security.hash_senha("correta"))
    for _ in range(5):
        with pytest.raises(HTTPException):
            autenticacao.autenticar_usuario(MagicMock(), MagicMock(), "helena@clinica.dev", "errada")

    with pytest.raises(HTTPException) as erro:
        autenticacao.autenticar_usuario(MagicMock(), MagicMock(), "helena@clinica.dev", "correta")
    assert erro.value.status_code == 429


def test_desafio_mfa_expira_pelo_relogio():
    security.resetar_estado_em_memoria()
    with patch("app.auth.security.time.monotonic", return_value=1000.0):
        challenge_id, codigo = security.gerar_desafio_mfa(1)
    with patch("app.auth.security.time.monotonic", return_value=1000.0 + 301):
        assert security.validar_desafio_mfa(challenge_id, codigo) is None


def test_desafio_mfa_e_descartado_apos_tres_tentativas_erradas():
    security.resetar_estado_em_memoria()
    challenge_id, codigo = security.gerar_desafio_mfa(1)
    errado = "000000" if codigo != "000000" else "111111"
    for _ in range(3):
        assert security.validar_desafio_mfa(challenge_id, errado) is None
    assert security.validar_desafio_mfa(challenge_id, codigo) is None


def test_desafio_mfa_e_de_uso_unico():
    security.resetar_estado_em_memoria()
    challenge_id, codigo = security.gerar_desafio_mfa(1)
    assert security.validar_desafio_mfa(challenge_id, codigo) == 1
    assert security.validar_desafio_mfa(challenge_id, codigo) is None


def test_hash_de_senha_nunca_guarda_o_texto_e_usa_sal():
    primeiro, segundo = security.hash_senha("SenhaForte#1"), security.hash_senha("SenhaForte#1")
    assert primeiro != segundo
    assert "SenhaForte" not in primeiro
    assert primeiro.startswith("$2b$12$")
    assert security.verificar_senha("SenhaForte#1", primeiro)


def test_senha_acima_de_72_bytes_nao_e_aceita():
    with pytest.raises(ValueError):
        security.hash_senha("ç" * 40)
    assert security.verificar_senha("A" * 73, security.hash_senha("A" * 72)) is False


@pytest.mark.parametrize("termo, valido", [
    ("Maria", True),
    ("João Batista", True),
    ("Ana-Clara", True),
    ("' OR '1'='1", False),
    ("Jo%", False),
    ("a_b", False),
    ("x;--", False),
    ("<script>", False),
    ("a", False),
])
def test_whitelist_do_termo_de_busca(termo, valido):
    assert validators.termo_de_busca_e_valido(termo) is valido


@pytest.mark.parametrize("cpf, valido", [
    ("526.018.159-06", True),
    ("526.018.159-07", False),
    ("000.000.000-00", False),
    ("123", False),
])
def test_validacao_de_cpf(cpf, valido):
    assert validators.cpf_e_valido(cpf) is valido


def test_mascara_de_cpf_esconde_os_digitos_identificadores():
    assert validators.mascarar_cpf("526.018.159-06") == "***.018.159-**"


@patch("app.validators.agora_na_clinica", return_value=AGORA_FIXO)
@pytest.mark.parametrize("inicio, aceito", [
    (AGORA_FIXO + timedelta(hours=2), True),
    (AGORA_FIXO - timedelta(minutes=15), False),
    (AGORA_FIXO + timedelta(days=61), False),
    (AGORA_FIXO.replace(hour=19), False),
    (AGORA_FIXO + timedelta(hours=2, minutes=5), False),
])
def test_horario_de_atendimento_com_relogio_fixo(_agora, inicio, aceito):
    if aceito:
        assert validators.validar_horario_de_atendimento(inicio) == inicio
    else:
        with pytest.raises(ValueError):
            validators.validar_horario_de_atendimento(inicio)
