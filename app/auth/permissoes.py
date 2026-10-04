ESCOPOS_DISPONIVEIS: dict[str, str] = {
    "consultas:ler": "Ler consultas sob sua responsabilidade ou titularidade",
    "consultas:escrever": "Criar, remarcar e cancelar consultas dos próprios pacientes",
    "agenda:ler": "Ver a agenda do dia da clínica, sem dados clínicos",
    "pacientes:ler": "Consultar cadastro de pacientes",
    "pacientes:criar": "Cadastrar pacientes",
    "profissionais:ler": "Listar profissionais de saúde",
    "horarios:ler": "Consultar horários disponíveis (integração do laboratório)",
    "admin": "Administração da plataforma: usuários e trilha de auditoria",
}

ESCOPOS_POR_PAPEL: dict[str, list[str]] = {
    "recepcionista": ["agenda:ler", "pacientes:ler", "pacientes:criar", "profissionais:ler"],
    "profissional": ["consultas:ler", "consultas:escrever", "pacientes:ler", "profissionais:ler"],
    "paciente": ["consultas:ler", "profissionais:ler"],
    "administrador": [
        "consultas:ler",
        "consultas:escrever",
        "agenda:ler",
        "pacientes:ler",
        "pacientes:criar",
        "profissionais:ler",
        "admin",
    ],
}

AUDIENCIA_USUARIOS = "consultas-api"
AUDIENCIA_LABORATORIO = "consultas-api:laboratorio"


def escopos_do_papel(papel: str) -> list[str]:
    return list(ESCOPOS_POR_PAPEL.get(papel, []))


def recortar_escopos(pedidos: list[str], permitidos: list[str]) -> list[str]:
    if not pedidos:
        return list(permitidos)
    return [escopo for escopo in pedidos if escopo in permitidos]
