from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Configuracoes(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CLINICA_",
        extra="ignore",
    )

    database_url: str = "sqlite:///./clinica.db"
    echo_sql: bool = False

    jwt_secret: SecretStr

    cors_origens: str = "http://localhost:5173"
    cookie_seguro: bool = True
    docs_ativos: bool = True

    rate_limit_ativo: bool = True
    rate_limit_padrao: str = "120/minute"
    rate_limit_login: str = "5/minute"
    rate_limit_escrita: str = "20/minute"
    rate_limit_leitura: str = "60/minute"

    bloqueio_tentativas: int = 5
    bloqueio_minutos: int = 15

    carregar_dados_demonstracao: bool = False
    modo_demonstracao_insegura: bool = False

    @field_validator("jwt_secret")
    @classmethod
    def exigir_segredo_forte(cls, valor: SecretStr) -> SecretStr:
        if len(valor.get_secret_value()) < 32:
            raise ValueError("CLINICA_JWT_SECRET precisa ter pelo menos 32 caracteres.")
        return valor

    @field_validator("cors_origens")
    @classmethod
    def recusar_coringa(cls, valor: str) -> str:
        if "*" in valor:
            raise ValueError("CORS com wildcard não é permitido: informe as origens em CLINICA_CORS_ORIGENS.")
        return valor

    @property
    def origens_permitidas(self) -> list[str]:
        return [origem.strip() for origem in self.cors_origens.split(",") if origem.strip()]


@lru_cache
def configuracoes() -> Configuracoes:
    return Configuracoes()
