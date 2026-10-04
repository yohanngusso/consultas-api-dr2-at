from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.openapi.models import OAuthFlowClientCredentials, OAuthFlows
from fastapi.security import OAuth2, OAuth2PasswordBearer, SecurityScopes
from sqlmodel import Session

from app import database
from app.auth.permissoes import AUDIENCIA_LABORATORIO, AUDIENCIA_USUARIOS, ESCOPOS_DISPONIVEIS
from app.database import get_session
from app.db_models import Consulta, Paciente, Usuario

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/token",
    scopes=ESCOPOS_DISPONIVEIS,
    auto_error=False,
    description="OAuth2 password para pessoas (profissionais, recepção, administração e pacientes).",
)

esquema_laboratorio = OAuth2(
    flows=OAuthFlows(clientCredentials=OAuthFlowClientCredentials(
        tokenUrl="auth/token",
        scopes={"horarios:ler": ESCOPOS_DISPONIVEIS["horarios:ler"]},
    )),
    scheme_name="OAuth2Laboratorio",
    auto_error=False,
    description="OAuth2 client_credentials do laboratório parceiro.",
)

SessaoDep = Annotated[Session, Depends(get_session)]

RESPOSTAS_DE_ERRO = {
    401: {"description": "Token ausente, inválido ou expirado"},
    403: {"description": "Escopo, papel ou posse do recurso insuficiente"},
    429: {"description": "Limite de requisições excedido"},
}


@dataclass
class Principal:
    sub: str
    tipo: str
    papel: str
    escopos: list[str]
    mfa: bool = False
    usuario: Usuario | None = None
    claims: dict = field(default_factory=dict)

    @property
    def e_administrador(self) -> bool:
        return self.papel == "administrador"


def ip_de(request: Request) -> str:
    return request.client.host if request.client else ""


def auditar(
    sessao: Session,
    request: Request,
    *,
    ator: str,
    tipo_ator: str,
    acao: str,
    recurso: str,
    resultado: str,
    recurso_id: Any = "",
) -> None:
    database.registrar_auditoria(
        sessao,
        ator=ator,
        tipo_ator=tipo_ator,
        acao=acao,
        recurso=recurso,
        recurso_id=str(recurso_id),
        resultado=resultado,
        ip=ip_de(request),
    )


def _nao_autenticado(detalhe: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detalhe,
        headers={"WWW-Authenticate": "Bearer"},
    )


def obter_principal(
    request: Request,
    security_scopes: SecurityScopes,
    sessao: SessaoDep,
    _token: Annotated[str | None, Depends(oauth2_scheme)],
) -> Principal:
    """As claims já foram validadas pelo AutenticacaoJWTMiddleware; aqui elas viram identidade e permissão."""
    claims = getattr(request.state, "claims", None)
    if not claims:
        raise _nao_autenticado("Autenticação necessária")

    tipo = claims.get("tipo")
    audiencia_esperada = {"usuario": AUDIENCIA_USUARIOS, "servico": AUDIENCIA_LABORATORIO}.get(tipo)
    if audiencia_esperada is None or claims.get("aud") != audiencia_esperada:
        raise _nao_autenticado("Token inválido")

    principal = Principal(
        sub=str(claims["sub"]),
        tipo=tipo,
        papel=claims.get("papel", ""),
        escopos=claims.get("scope", "").split(),
        mfa=bool(claims.get("mfa", False)),
        claims=claims,
    )

    if tipo == "usuario":
        usuario = database.obter_usuario_por_id(sessao, int(principal.sub))
        if usuario is None or not usuario.ativo or usuario.papel != principal.papel:
            raise _nao_autenticado("Sessão não é mais válida")
        principal.usuario = usuario
    else:
        cliente = database.obter_cliente_m2m(sessao, principal.sub)
        if cliente is None or not cliente.ativo:
            raise _nao_autenticado("Cliente não está mais autorizado")

    faltantes = [escopo for escopo in security_scopes.scopes if escopo not in principal.escopos]
    if faltantes:
        auditar(sessao, request, ator=principal.sub, tipo_ator=tipo, acao=f"{request.method} {request.url.path}",
                recurso="escopo", recurso_id=" ".join(faltantes), resultado="negado")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Escopo insuficiente: a operação exige {' '.join(faltantes)}",
        )
    return principal


def exigir_usuario(principal: Annotated[Principal, Depends(obter_principal)]) -> Usuario:
    if principal.tipo != "usuario" or principal.usuario is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operação exclusiva de usuários")
    return principal.usuario


def exigir_profissional(usuario: Annotated[Usuario, Depends(exigir_usuario)]) -> Usuario:
    if usuario.papel != "profissional" or usuario.profissional_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operação exclusiva de profissionais de saúde")
    return usuario


def exigir_laboratorio(
    principal: Annotated[Principal, Security(obter_principal, scopes=["horarios:ler"])],
    _token: Annotated[str | None, Depends(esquema_laboratorio)],
) -> Principal:
    if principal.tipo != "servico":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Rota exclusiva da integração do laboratório")
    return principal


def exigir_administrador(
    request: Request,
    sessao: SessaoDep,
    principal: Annotated[Principal, Security(obter_principal, scopes=["admin"])],
) -> Principal:
    if not principal.e_administrador or not principal.mfa:
        auditar(sessao, request, ator=principal.sub, tipo_ator=principal.tipo,
                acao=f"{request.method} {request.url.path}", recurso="admin", resultado="negado")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Rota administrativa exige papel de administrador autenticado com segundo fator",
        )
    return principal


def exigir_posse(
    *,
    carregar: Callable[[Session, int], Any | None],
    pode_acessar: Callable[[Principal, Any], bool],
    nome_parametro: str,
    escopos: list[str],
    recurso: str,
    acao: str,
):
    """Fábrica de dependências de autorização por objeto: 404 se não existe, 403 se não pertence ao chamador."""

    def dependencia(
        request: Request,
        sessao: SessaoDep,
        principal: Annotated[Principal, Security(obter_principal, scopes=escopos)],
    ):
        try:
            recurso_id = int(request.path_params[nome_parametro])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{recurso} não encontrado")

        objeto = carregar(sessao, recurso_id)
        if objeto is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{recurso} não encontrado")

        autorizado = pode_acessar(principal, objeto)
        auditar(sessao, request, ator=principal.sub, tipo_ator=principal.tipo, acao=acao,
                recurso=recurso, recurso_id=recurso_id, resultado="permitido" if autorizado else "negado")
        if not autorizado:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado a este recurso")

        request.state.posse_verificada = True
        return objeto

    return dependencia


def _profissional_id(principal: Principal) -> int | None:
    return principal.usuario.profissional_id if principal.usuario else None


def _paciente_id(principal: Principal) -> int | None:
    return principal.usuario.paciente_id if principal.usuario else None


def pode_ler_consulta(principal: Principal, consulta: Consulta) -> bool:
    if principal.e_administrador:
        return True
    if principal.papel == "profissional":
        return _profissional_id(principal) == consulta.profissional_id
    if principal.papel == "paciente":
        return _paciente_id(principal) == consulta.paciente_id
    return False


def pode_alterar_consulta(principal: Principal, consulta: Consulta) -> bool:
    if principal.e_administrador:
        return True
    return principal.papel == "profissional" and _profissional_id(principal) == consulta.profissional_id


def pode_ler_paciente(principal: Principal, paciente: Paciente) -> bool:
    if principal.e_administrador or principal.papel == "recepcionista":
        return True
    return principal.papel == "profissional" and _profissional_id(principal) == paciente.profissional_responsavel_id


consulta_legivel = exigir_posse(
    carregar=database.obter_consulta,
    pode_acessar=pode_ler_consulta,
    nome_parametro="consulta_id",
    escopos=["consultas:ler"],
    recurso="Consulta",
    acao="ler_consulta",
)

consulta_alteravel = exigir_posse(
    carregar=database.obter_consulta,
    pode_acessar=pode_alterar_consulta,
    nome_parametro="consulta_id",
    escopos=["consultas:escrever"],
    recurso="Consulta",
    acao="alterar_consulta",
)

paciente_legivel = exigir_posse(
    carregar=database.obter_paciente,
    pode_acessar=pode_ler_paciente,
    nome_parametro="paciente_id",
    escopos=["pacientes:ler"],
    recurso="Paciente",
    acao="ler_paciente",
)
