from datetime import date, datetime, timezone

from pydantic import NaiveDatetime
from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def agora_utc() -> datetime:
    return datetime.now(timezone.utc)


class Profissional(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nome: str = Field(max_length=120)
    especialidade: str = Field(max_length=40, index=True)
    registro_conselho: str = Field(max_length=30)
    ativo: bool = Field(default=True)


class Paciente(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nome: str = Field(max_length=120, index=True)
    cpf: str = Field(max_length=14, unique=True)
    data_nascimento: date
    email: str = Field(max_length=180)
    telefone: str = Field(max_length=20)
    profissional_responsavel_id: int = Field(foreign_key="profissional.id", index=True)


class Usuario(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nome: str = Field(max_length=120)
    email: str = Field(max_length=180, unique=True, index=True)
    papel: str = Field(max_length=20)
    senha_hash: str = Field(max_length=80)
    mfa_obrigatorio: bool = Field(default=False)
    ativo: bool = Field(default=True)
    profissional_id: int | None = Field(default=None, foreign_key="profissional.id")
    paciente_id: int | None = Field(default=None, foreign_key="paciente.id")


class ClienteM2M(SQLModel, table=True):
    client_id: str = Field(primary_key=True, max_length=60)
    nome: str = Field(max_length=120)
    segredo_hash: str = Field(max_length=80)
    escopos_contratados: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    ativo: bool = Field(default=True)


class Consulta(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    paciente_id: int = Field(foreign_key="paciente.id", index=True)
    profissional_id: int = Field(foreign_key="profissional.id", index=True)
    inicio: NaiveDatetime = Field(index=True)
    duracao_minutos: int = Field(default=30)
    status: str = Field(default="agendada", max_length=20)
    motivo: str = Field(max_length=300)
    observacoes: str = Field(default="", max_length=500)

    token_auditoria: str = Field(max_length=40)
    criado_por_id: int
    criado_em: datetime = Field(default_factory=agora_utc)
    atualizado_em: datetime = Field(default_factory=agora_utc)
    ip_origem: str = Field(default="", max_length=45)


class RegistroAuditoria(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    momento: datetime = Field(default_factory=agora_utc, index=True)
    ator: str = Field(max_length=80)
    tipo_ator: str = Field(max_length=20)
    acao: str = Field(max_length=40)
    recurso: str = Field(max_length=40)
    recurso_id: str = Field(default="", max_length=40)
    resultado: str = Field(max_length=20)
    ip: str = Field(default="", max_length=45)
