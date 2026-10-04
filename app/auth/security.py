import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.auth.permissoes import AUDIENCIA_LABORATORIO, AUDIENCIA_USUARIOS
from app.config import configuracoes

ALGORITMO = "HS256"
EMISSOR = "consultas-api"
EXPIRACAO_USUARIO_MINUTOS = 15
EXPIRACAO_M2M_MINUTOS = 10
EXPIRACAO_DESAFIO_MFA_SEGUNDOS = 300
MAX_TENTATIVAS_MFA = 3
LIMITE_BYTES_BCRYPT = 72

_HASH_FICTICIO = bcrypt.hashpw(b"senha-ficticia-para-tempo-constante", bcrypt.gensalt(12))


def hash_senha(senha: str) -> str:
    dados = senha.encode("utf-8")
    if len(dados) > LIMITE_BYTES_BCRYPT:
        raise ValueError(f"Senha acima de {LIMITE_BYTES_BCRYPT} bytes.")
    return bcrypt.hashpw(dados, bcrypt.gensalt(12)).decode()


def verificar_senha(senha: str, senha_hash: str | None) -> bool:
    """Sem hash (usuário inexistente) compara contra um hash fictício para não vazar a existência da conta pelo tempo de resposta."""
    dados = senha.encode("utf-8")
    if len(dados) > LIMITE_BYTES_BCRYPT:
        bcrypt.checkpw(b"x", _HASH_FICTICIO)
        return False
    if not senha_hash:
        bcrypt.checkpw(dados, _HASH_FICTICIO)
        return False
    return bcrypt.checkpw(dados, senha_hash.encode())


def _chave() -> str:
    return configuracoes().jwt_secret.get_secret_value()


def criar_token(
    *,
    sub: str,
    tipo: str,
    audiencia: str,
    escopos: list[str],
    expira_em_minutos: int,
    extras: dict | None = None,
) -> tuple[str, int]:
    agora = datetime.now(timezone.utc)
    expira = agora + timedelta(minutes=expira_em_minutos)
    payload = {
        "iss": EMISSOR,
        "sub": sub,
        "aud": audiencia,
        "tipo": tipo,
        "scope": " ".join(escopos),
        "iat": int(agora.timestamp()),
        "exp": int(expira.timestamp()),
        "jti": uuid.uuid4().hex,
        **(extras or {}),
    }
    return jwt.encode(payload, _chave(), algorithm=ALGORITMO), expira_em_minutos * 60


def decodificar_token(token: str) -> dict:
    return jwt.decode(
        token,
        _chave(),
        algorithms=[ALGORITMO],
        issuer=EMISSOR,
        audience=[AUDIENCIA_USUARIOS, AUDIENCIA_LABORATORIO],
        options={"require": ["exp", "iat", "sub", "iss", "aud", "jti"]},
    )


_desafios_mfa: dict[str, dict] = {}


def gerar_desafio_mfa(usuario_id: int) -> tuple[str, str]:
    challenge_id = secrets.token_urlsafe(24)
    codigo = f"{secrets.randbelow(1_000_000):06d}"
    _desafios_mfa[challenge_id] = {
        "usuario_id": usuario_id,
        "codigo": codigo,
        "expira_em": time.monotonic() + EXPIRACAO_DESAFIO_MFA_SEGUNDOS,
        "tentativas": 0,
    }
    return challenge_id, codigo


def validar_desafio_mfa(challenge_id: str, codigo: str) -> int | None:
    desafio = _desafios_mfa.get(challenge_id)
    if desafio is None:
        return None
    if time.monotonic() > desafio["expira_em"]:
        _desafios_mfa.pop(challenge_id, None)
        return None
    desafio["tentativas"] += 1
    if desafio["tentativas"] > MAX_TENTATIVAS_MFA:
        _desafios_mfa.pop(challenge_id, None)
        return None
    if not secrets.compare_digest(desafio["codigo"], codigo):
        return None
    _desafios_mfa.pop(challenge_id, None)
    return desafio["usuario_id"]


_falhas_de_login: dict[str, dict] = {}


def identidade_bloqueada(chave: str) -> bool:
    registro = _falhas_de_login.get(chave)
    return bool(registro and registro["bloqueado_ate"] > time.monotonic())


def registrar_falha_de_login(chave: str) -> None:
    cfg = configuracoes()
    registro = _falhas_de_login.setdefault(chave, {"falhas": 0, "bloqueado_ate": 0.0})
    registro["falhas"] += 1
    if registro["falhas"] >= cfg.bloqueio_tentativas:
        registro["bloqueado_ate"] = time.monotonic() + cfg.bloqueio_minutos * 60
        registro["falhas"] = 0


def limpar_falhas_de_login(chave: str) -> None:
    _falhas_de_login.pop(chave, None)


def resetar_estado_em_memoria() -> None:
    _desafios_mfa.clear()
    _falhas_de_login.clear()
