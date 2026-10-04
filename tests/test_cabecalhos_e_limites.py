import pytest
from pydantic import ValidationError

from app.config import Configuracoes, configuracoes
from app.limiter import resetar_limites
from conftest import HELENA, RECEPCAO, entrar_na_recepcao

CABECALHOS_OBRIGATORIOS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
}


@pytest.mark.parametrize("rota", ["/", "/consultas", "/rota-inexistente", "/web/login", "/openapi.json"])
def test_t13_cabecalhos_de_seguranca_em_toda_resposta(cliente, rota):
    resposta = cliente.get(rota, follow_redirects=False)
    for nome, valor in CABECALHOS_OBRIGATORIOS.items():
        assert resposta.headers.get(nome) == valor, f"{nome} ausente em {rota}"
    assert "frame-ancestors 'none'" in resposta.headers["content-security-policy"]


def test_t13_cabecalhos_de_isolamento_entre_origens(cliente):
    resposta = cliente.get("/web/login")
    assert resposta.headers["cross-origin-opener-policy"] == "same-origin"
    assert resposta.headers["cross-origin-resource-policy"] == "same-origin"
    assert resposta.headers["cross-origin-embedder-policy"] == "require-corp"
    assert "camera=()" in resposta.headers["permissions-policy"]


def test_t13_respostas_com_dados_de_saude_nao_sao_armazenadas_em_cache(cliente, autenticar):
    resposta = cliente.get("/consultas/1", headers=autenticar(HELENA))
    assert resposta.headers["cache-control"] == "no-store"


def test_t13_csp_da_pagina_da_recepcao_nao_permite_script_inline(cliente):
    csp = cliente.get("/web/login").headers["content-security-policy"]
    assert "script-src 'self';" in csp
    assert "unsafe-inline" not in csp


def test_t14_cors_libera_apenas_origem_da_allowlist(cliente):
    preflight = {"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "Authorization"}
    autorizada = cliente.options("/consultas", headers={"Origin": "http://localhost:5173", **preflight})
    assert autorizada.status_code == 200
    assert autorizada.headers["access-control-allow-origin"] == "http://localhost:5173"

    maliciosa = cliente.options("/consultas", headers={"Origin": "https://atacante.exemplo", **preflight})
    assert maliciosa.status_code == 400
    assert "access-control-allow-origin" not in maliciosa.headers

    simples = cliente.get("/", headers={"Origin": "https://atacante.exemplo"})
    assert "access-control-allow-origin" not in simples.headers


@pytest.mark.parametrize("origens", ["*", "http://localhost:5173,*"])
def test_t14_configuracao_recusa_cors_com_wildcard(origens):
    with pytest.raises(ValidationError):
        Configuracoes(cors_origens=origens, jwt_secret="x" * 40)


def test_t17_aplicacao_nao_sobe_sem_segredo_jwt(monkeypatch):
    monkeypatch.delenv("CLINICA_JWT_SECRET", raising=False)
    with pytest.raises(ValidationError):
        Configuracoes(_env_file=None)


def test_t17_segredo_jwt_curto_e_recusado():
    with pytest.raises(ValidationError):
        Configuracoes(jwt_secret="curto", _env_file=None)


def test_t05_login_tem_limite_mais_restritivo_que_leitura(cliente):
    respostas = [
        cliente.post("/auth/token", data={"username": "helena@clinica.dev", "password": f"errada{i}"}).status_code
        for i in range(6)
    ]
    assert respostas[:5] == [401] * 5
    assert respostas[5] == 429

    resetar_limites()
    leituras = [cliente.get("/").status_code for _ in range(20)]
    assert set(leituras) == {200}


def test_t05_resposta_429_traz_retry_after(cliente):
    for _ in range(6):
        resposta = cliente.post("/auth/token", data={"username": "x@clinica.dev", "password": "y"})
    assert resposta.status_code == 429
    assert resposta.headers["retry-after"] == "60"


def test_t05_conta_e_bloqueada_apos_falhas_consecutivas_mesmo_trocando_de_ip(cliente):
    email, senha = HELENA
    for _ in range(5):
        cliente.post("/auth/token", data={"username": email, "password": "senha-errada"})
    resetar_limites()

    resposta = cliente.post("/auth/token", data={"username": email, "password": senha})
    assert resposta.status_code == 429
    assert "conta" in resposta.json()["detail"]


def test_t21_mensagem_de_login_nao_revela_se_o_email_existe(cliente):
    inexistente = cliente.post("/auth/token", data={"username": "ninguem@clinica.dev", "password": "x"})
    senha_errada = cliente.post("/auth/token", data={"username": "helena@clinica.dev", "password": "x"})
    assert inexistente.status_code == senha_errada.status_code == 401
    assert inexistente.json() == senha_errada.json()


def test_t19_cookie_de_sessao_da_recepcao_e_httponly_strict_e_secure(cliente, monkeypatch):
    pagina = cliente.get("/web/login")
    monkeypatch.setattr(configuracoes(), "cookie_seguro", True)
    resposta = cliente.post(
        "/web/login",
        data={"email": RECEPCAO[0], "senha": RECEPCAO[1], "csrf_token": pagina.cookies["csrf_clinica"]},
        follow_redirects=False,
    )
    assert resposta.status_code == 303
    cookie = next(c for c in resposta.headers.get_list("set-cookie") if c.startswith("sessao_clinica")).lower()
    for atributo in ("httponly", "samesite=strict", "secure", "path=/web", "max-age=900"):
        assert atributo in cookie


def test_t19_cookie_da_recepcao_carrega_apenas_o_escopo_da_agenda(cliente):
    entrar_na_recepcao(cliente, RECEPCAO)
    token = cliente.cookies.get("sessao_clinica")
    assert cliente.get("/pacientes/busca?nome=Jo", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_t22_documentacao_pode_ser_desligada_por_configuracao():
    assert Configuracoes(jwt_secret="x" * 40, docs_ativos=False, _env_file=None).docs_ativos is False


def test_t19_login_da_recepcao_sem_token_csrf_e_recusado(cliente):
    cliente.get("/web/login")
    resposta = cliente.post("/web/login", data={"email": RECEPCAO[0], "senha": RECEPCAO[1]}, follow_redirects=False)
    assert resposta.status_code == 403
    assert "sessao_clinica" not in resposta.headers.get("set-cookie", "")


def test_t19_login_da_recepcao_com_token_csrf_divergente_e_recusado(cliente):
    cliente.get("/web/login")
    dados = {"email": RECEPCAO[0], "senha": RECEPCAO[1], "csrf_token": "token-forjado-pelo-atacante"}
    assert cliente.post("/web/login", data=dados, follow_redirects=False).status_code == 403


def test_t19_logout_sem_token_csrf_e_recusado(cliente):
    entrar_na_recepcao(cliente, RECEPCAO)
    assert cliente.post("/web/logout", follow_redirects=False).status_code == 403
    assert cliente.get("/web/agenda", follow_redirects=False).status_code == 200
