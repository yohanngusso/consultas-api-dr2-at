import secrets
from collections.abc import Iterator
from datetime import date, datetime, time, timedelta
from enum import Enum

from sqlmodel import Session, SQLModel, col, create_engine, select

from app.config import configuracoes
from app.db_models import (
    ClienteM2M,
    Consulta,
    Paciente,
    Profissional,
    RegistroAuditoria,
    Usuario,
    agora_utc,
)
from app.validators import HORA_ABERTURA, HORA_FECHAMENTO, agora_na_clinica


def _criar_engine():
    cfg = configuracoes()
    argumentos = {"check_same_thread": False} if cfg.database_url.startswith("sqlite") else {}
    return create_engine(cfg.database_url, echo=cfg.echo_sql, connect_args=argumentos)


engine = _criar_engine()


def criar_tabelas() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as sessao:
        yield sessao


def obter_usuario_por_email(sessao: Session, email: str) -> Usuario | None:
    return sessao.exec(select(Usuario).where(col(Usuario.email) == email.strip().lower())).first()


def obter_usuario_por_id(sessao: Session, usuario_id: int) -> Usuario | None:
    return sessao.get(Usuario, usuario_id)


def listar_usuarios(sessao: Session) -> list[Usuario]:
    return list(sessao.exec(select(Usuario).order_by(col(Usuario.id))).all())


def obter_cliente_m2m(sessao: Session, client_id: str) -> ClienteM2M | None:
    return sessao.get(ClienteM2M, client_id)


def obter_profissional(sessao: Session, profissional_id: int) -> Profissional | None:
    return sessao.get(Profissional, profissional_id)


def listar_profissionais(sessao: Session) -> list[Profissional]:
    consulta = select(Profissional).where(col(Profissional.ativo).is_(True)).order_by(col(Profissional.nome))
    return list(sessao.exec(consulta).all())


def obter_paciente(sessao: Session, paciente_id: int) -> Paciente | None:
    return sessao.get(Paciente, paciente_id)


def buscar_pacientes(sessao: Session, termo: str, profissional_id: int | None = None) -> list[Paciente]:
    consulta = select(Paciente).where(col(Paciente.nome).contains(termo, autoescape=True))
    if profissional_id is not None:
        consulta = consulta.where(col(Paciente.profissional_responsavel_id) == profissional_id)
    return list(sessao.exec(consulta.order_by(col(Paciente.nome))).all())


def criar_paciente(sessao: Session, dados) -> Paciente:
    paciente = Paciente(**dados.model_dump())
    sessao.add(paciente)
    sessao.commit()
    sessao.refresh(paciente)
    return paciente


def cpf_ja_cadastrado(sessao: Session, cpf: str) -> bool:
    return sessao.exec(select(Paciente.id).where(col(Paciente.cpf) == cpf)).first() is not None


def _consulta_detalhada():
    return (
        select(Consulta, Paciente.nome, Profissional.nome, Profissional.especialidade)
        .join(Paciente, col(Paciente.id) == col(Consulta.paciente_id))
        .join(Profissional, col(Profissional.id) == col(Consulta.profissional_id))
    )


def _montar(linha) -> dict:
    consulta, paciente_nome, profissional_nome, especialidade = linha
    return {
        **consulta.model_dump(),
        "paciente_nome": paciente_nome,
        "profissional_nome": profissional_nome,
        "especialidade": especialidade,
    }


def _intervalo_do_dia(dia: date) -> tuple[datetime, datetime]:
    inicio = datetime.combine(dia, time.min)
    return inicio, inicio + timedelta(days=1)


def obter_consulta(sessao: Session, consulta_id: int) -> Consulta | None:
    return sessao.get(Consulta, consulta_id)


def detalhar_consulta(sessao: Session, consulta_id: int) -> dict | None:
    linha = sessao.exec(_consulta_detalhada().where(col(Consulta.id) == consulta_id)).first()
    return _montar(linha) if linha else None


def listar_consultas(
    sessao: Session,
    *,
    profissional_id: int | None = None,
    paciente_id: int | None = None,
    dia: date | None = None,
) -> list[dict]:
    consulta = _consulta_detalhada()
    if profissional_id is not None:
        consulta = consulta.where(col(Consulta.profissional_id) == profissional_id)
    if paciente_id is not None:
        consulta = consulta.where(col(Consulta.paciente_id) == paciente_id)
    if dia is not None:
        inicio, fim = _intervalo_do_dia(dia)
        consulta = consulta.where(col(Consulta.inicio) >= inicio, col(Consulta.inicio) < fim)
    return [_montar(linha) for linha in sessao.exec(consulta.order_by(col(Consulta.inicio))).all()]


def existe_conflito(
    sessao: Session, profissional_id: int, inicio: datetime, duracao: int, ignorar_id: int | None = None
) -> bool:
    dia_inicio, dia_fim = _intervalo_do_dia(inicio.date())
    consulta = select(Consulta).where(
        col(Consulta.profissional_id) == profissional_id,
        col(Consulta.status) != "cancelada",
        col(Consulta.inicio) >= dia_inicio,
        col(Consulta.inicio) < dia_fim,
    )
    fim = inicio + timedelta(minutes=duracao)
    for existente in sessao.exec(consulta).all():
        if existente.id == ignorar_id:
            continue
        existente_fim = existente.inicio + timedelta(minutes=existente.duracao_minutos)
        if inicio < existente_fim and existente.inicio < fim:
            return True
    return False


def criar_consulta(sessao: Session, dados, *, profissional_id: int, criado_por_id: int, ip: str) -> Consulta:
    consulta = Consulta(
        **dados.model_dump(),
        profissional_id=profissional_id,
        criado_por_id=criado_por_id,
        token_auditoria=f"aud_{secrets.token_hex(8)}",
        ip_origem=ip,
    )
    sessao.add(consulta)
    sessao.commit()
    sessao.refresh(consulta)
    return consulta


def atualizar_consulta(sessao: Session, consulta: Consulta, dados, ip: str) -> Consulta:
    for campo, valor in dados.model_dump().items():
        setattr(consulta, campo, valor.value if isinstance(valor, Enum) else valor)
    consulta.atualizado_em = agora_utc()
    consulta.ip_origem = ip
    sessao.add(consulta)
    sessao.commit()
    sessao.refresh(consulta)
    return consulta


def cancelar_consulta(sessao: Session, consulta: Consulta, ip: str) -> Consulta:
    consulta.status = "cancelada"
    consulta.atualizado_em = agora_utc()
    consulta.ip_origem = ip
    sessao.add(consulta)
    sessao.commit()
    sessao.refresh(consulta)
    return consulta


def horarios_disponiveis(sessao: Session, dia: date, especialidade: str) -> list[dict]:
    profissionais = sessao.exec(
        select(Profissional).where(
            col(Profissional.especialidade) == especialidade,
            col(Profissional.ativo).is_(True),
        )
    ).all()
    agora = agora_na_clinica()
    livres = []
    for profissional in profissionais:
        slot = datetime.combine(dia, time(HORA_ABERTURA, 0))
        fechamento = datetime.combine(dia, time(HORA_FECHAMENTO, 0))
        while slot < fechamento:
            if slot > agora and not existe_conflito(sessao, profissional.id, slot, 30):
                livres.append({
                    "profissional_id": profissional.id,
                    "profissional_nome": profissional.nome,
                    "especialidade": profissional.especialidade,
                    "inicio": slot,
                    "fim": slot + timedelta(minutes=30),
                })
            slot += timedelta(minutes=30)
    return livres


def registrar_auditoria(
    sessao: Session, *, ator: str, tipo_ator: str, acao: str, recurso: str, recurso_id: str, resultado: str, ip: str
) -> None:
    sessao.add(RegistroAuditoria(
        ator=ator, tipo_ator=tipo_ator, acao=acao, recurso=recurso,
        recurso_id=recurso_id, resultado=resultado, ip=ip,
    ))
    sessao.commit()


def listar_auditoria(sessao: Session, limite: int = 100) -> list[RegistroAuditoria]:
    consulta = select(RegistroAuditoria).order_by(col(RegistroAuditoria.id).desc()).limit(limite)
    return list(sessao.exec(consulta).all())


def buscar_paciente_por_cpf(sessao: Session, cpf: str) -> list[dict]:
    from sqlalchemy import text

    sql = f"SELECT id, nome, cpf FROM paciente WHERE cpf = '{cpf}'"
    return [dict(linha._mapping) for linha in sessao.connection().execute(text(sql)).all()]
