from datetime import date, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.validators import (
    PADRAO_NOME_PESSOA,
    PADRAO_TELEFONE,
    PADRAO_TEXTO_LIVRE,
    cpf_e_valido,
    mascarar_cpf,
    validar_horario_de_atendimento,
)


class EntradaEstrita(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SaidaDeRegistro(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class StatusConsulta(str, Enum):
    agendada = "agendada"
    confirmada = "confirmada"
    cancelada = "cancelada"
    realizada = "realizada"


class Especialidade(str, Enum):
    cardiologia = "cardiologia"
    dermatologia = "dermatologia"
    clinica_geral = "clinica_geral"
    pediatria = "pediatria"
    ortopedia = "ortopedia"


class ConsultaCreate(EntradaEstrita):
    paciente_id: int = Field(gt=0)
    inicio: datetime
    duracao_minutos: int = Field(default=30, ge=15, le=120, multiple_of=15)
    motivo: str = Field(min_length=3, max_length=300, pattern=PADRAO_TEXTO_LIVRE)
    observacoes: str = Field(default="", max_length=500, pattern=PADRAO_TEXTO_LIVRE)

    @field_validator("inicio")
    @classmethod
    def checar_inicio(cls, valor: datetime) -> datetime:
        return validar_horario_de_atendimento(valor)


class ConsultaUpdate(EntradaEstrita):
    inicio: datetime
    duracao_minutos: int = Field(ge=15, le=120, multiple_of=15)
    status: StatusConsulta
    motivo: str = Field(min_length=3, max_length=300, pattern=PADRAO_TEXTO_LIVRE)
    observacoes: str = Field(default="", max_length=500, pattern=PADRAO_TEXTO_LIVRE)

    @field_validator("inicio")
    @classmethod
    def checar_inicio(cls, valor: datetime) -> datetime:
        return validar_horario_de_atendimento(valor)


class ConsultaPublic(SaidaDeRegistro):
    id: int
    paciente_id: int
    paciente_nome: str
    profissional_id: int
    profissional_nome: str
    inicio: datetime
    duracao_minutos: int
    status: StatusConsulta
    motivo: str
    observacoes: str


class ConsultaAgenda(SaidaDeRegistro):
    id: int
    inicio: datetime
    duracao_minutos: int
    paciente_nome: str
    profissional_nome: str
    especialidade: Especialidade
    status: StatusConsulta
    observacoes: str


class PacienteCreate(EntradaEstrita):
    nome: str = Field(min_length=3, max_length=120, pattern=PADRAO_NOME_PESSOA)
    cpf: str = Field(pattern=r"^\d{3}\.\d{3}\.\d{3}-\d{2}$")
    data_nascimento: date
    email: EmailStr
    telefone: str = Field(pattern=PADRAO_TELEFONE)
    profissional_responsavel_id: int = Field(gt=0)

    @field_validator("cpf")
    @classmethod
    def checar_cpf(cls, valor: str) -> str:
        if not cpf_e_valido(valor):
            raise ValueError("CPF inválido.")
        return valor

    @field_validator("data_nascimento")
    @classmethod
    def checar_nascimento(cls, valor: date) -> date:
        if valor >= date.today() or valor.year < 1900:
            raise ValueError("Data de nascimento fora do intervalo aceito.")
        return valor


class PacientePublic(BaseModel):
    id: int
    nome: str
    cpf_mascarado: str
    data_nascimento: date
    email: EmailStr
    telefone: str
    profissional_responsavel_id: int

    @classmethod
    def de(cls, paciente) -> "PacientePublic":
        return cls(
            id=paciente.id,
            nome=paciente.nome,
            cpf_mascarado=mascarar_cpf(paciente.cpf),
            data_nascimento=paciente.data_nascimento,
            email=paciente.email,
            telefone=paciente.telefone,
            profissional_responsavel_id=paciente.profissional_responsavel_id,
        )


class ProfissionalPublic(SaidaDeRegistro):
    id: int
    nome: str
    especialidade: Especialidade


class HorarioDisponivel(BaseModel):
    profissional_id: int
    profissional_nome: str
    especialidade: Especialidade
    inicio: datetime
    fim: datetime


class UsuarioPublic(SaidaDeRegistro):
    id: int
    nome: str
    email: EmailStr
    papel: str
    ativo: bool
    mfa_obrigatorio: bool


class RegistroAuditoriaPublic(SaidaDeRegistro):
    momento: datetime
    ator: str
    tipo_ator: str
    acao: str
    recurso: str
    recurso_id: str
    resultado: str
    ip: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: str


class DesafioMFA(BaseModel):
    mfa_required: bool = True
    challenge_id: str
    metodo: str = "totp_simulado"
    detalhe: str


class VerificacaoMFA(EntradaEstrita):
    challenge_id: str = Field(min_length=10, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    codigo: str = Field(pattern=r"^\d{6}$")
