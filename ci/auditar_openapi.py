"""Auditoria estática da especificação OpenAPI. Uso: python ci/auditar_openapi.py [--arquivo openapi.json] [--saida relatorio.md]"""

import argparse
import json
import os
import pathlib
import sys

OPERACOES_PUBLICAS = {("get", "/"), ("post", "/auth/token"), ("post", "/auth/mfa")}
CAMPOS_PROIBIDOS_NA_SAIDA = {
    "token_auditoria", "criado_por_id", "criado_em", "atualizado_em", "ip_origem",
    "senha_hash", "segredo_hash", "cpf",
}
RESPOSTAS_EXIGIDAS_EM_ROTA_PROTEGIDA = {"401", "403", "429"}
FORMATOS_LIMITADOS = {"date", "date-time", "email", "uuid"}


def carregar_especificacao(arquivo: str | None) -> dict:
    if arquivo:
        return json.loads(pathlib.Path(arquivo).read_text(encoding="utf-8"))
    raiz = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(raiz))
    os.chdir(raiz)
    os.environ.setdefault("CLINICA_JWT_SECRET", "segredo-somente-para-gerar-a-especificacao-openapi")
    import main

    return main.app.openapi()


def resolver(especificacao: dict, esquema: dict) -> dict:
    while "$ref" in esquema:
        nome = esquema["$ref"].rsplit("/", 1)[-1]
        esquema = especificacao["components"]["schemas"][nome]
    return esquema


def propriedades_de_saida(especificacao: dict, esquema: dict, visitados: set | None = None) -> set[str]:
    visitados = visitados or set()
    esquema = resolver(especificacao, esquema)
    if id(esquema) in visitados:
        return set()
    visitados.add(id(esquema))
    nomes = set()
    for alternativa in esquema.get("anyOf", []) + esquema.get("oneOf", []):
        nomes |= propriedades_de_saida(especificacao, alternativa, visitados)
    if "items" in esquema:
        nomes |= propriedades_de_saida(especificacao, esquema["items"], visitados)
    for nome, filho in esquema.get("properties", {}).items():
        nomes.add(nome)
        nomes |= propriedades_de_saida(especificacao, filho, visitados)
    return nomes


def string_sem_limite(esquema: dict) -> bool:
    alternativas = esquema.get("anyOf") or [esquema]
    for alternativa in alternativas:
        if alternativa.get("type") != "string":
            continue
        limitada = (
            "maxLength" in alternativa or "enum" in alternativa or "pattern" in alternativa
            or alternativa.get("format") in FORMATOS_LIMITADOS
        )
        if not limitada:
            return True
    return False


def auditar(especificacao: dict) -> list[tuple[str, str, str]]:
    achados = []
    esquemas_de_seguranca = especificacao.get("components", {}).get("securitySchemes", {})
    fluxos = {fluxo for esquema in esquemas_de_seguranca.values() for fluxo in esquema.get("flows", {})}
    for fluxo in ("password", "clientCredentials"):
        if fluxo not in fluxos:
            achados.append(("MEDIA", "securitySchemes", f"fluxo OAuth2 '{fluxo}' aceito pelo /auth/token não está declarado"))

    for caminho, operacoes in especificacao.get("paths", {}).items():
        for metodo, operacao in operacoes.items():
            alvo = f"{metodo.upper()} {caminho}"
            publica = (metodo, caminho) in OPERACOES_PUBLICAS

            if not publica and not operacao.get("security"):
                achados.append(("ALTA", alvo, "operação não pública sem requisito de segurança"))

            if not publica:
                faltantes = RESPOSTAS_EXIGIDAS_EM_ROTA_PROTEGIDA - set(operacao.get("responses", {}))
                if faltantes:
                    achados.append(("BAIXA", alvo, f"respostas de erro não documentadas: {', '.join(sorted(faltantes))}"))

            for codigo, resposta in operacao.get("responses", {}).items():
                if not codigo.startswith("2"):
                    continue
                for conteudo in resposta.get("content", {}).values():
                    expostos = propriedades_de_saida(especificacao, conteudo.get("schema", {})) & CAMPOS_PROIBIDOS_NA_SAIDA
                    if expostos:
                        achados.append(("ALTA", alvo, f"resposta {codigo} expõe campos internos: {', '.join(sorted(expostos))}"))

            for parametro in operacao.get("parameters", []):
                if string_sem_limite(parametro.get("schema", {})):
                    achados.append(("MEDIA", alvo, f"parâmetro '{parametro['name']}' sem limite de tamanho, padrão ou enum"))

            corpo = operacao.get("requestBody", {}).get("content", {})
            for tipo, conteudo in corpo.items():
                esquema = resolver(especificacao, conteudo.get("schema", {}))
                if tipo == "application/json" and esquema.get("additionalProperties") is not False:
                    achados.append(("MEDIA", alvo, "corpo JSON aceita campos não declarados (falta extra='forbid')"))
                for nome, propriedade in esquema.get("properties", {}).items():
                    if string_sem_limite(resolver(especificacao, propriedade)):
                        achados.append(("MEDIA", alvo, f"campo '{nome}' do corpo sem limite de tamanho, padrão ou enum"))
    return achados


def main() -> int:
    argumentos = argparse.ArgumentParser()
    argumentos.add_argument("--arquivo")
    argumentos.add_argument("--saida")
    opcoes = argumentos.parse_args()

    especificacao = carregar_especificacao(opcoes.arquivo)
    achados = auditar(especificacao)
    operacoes = sum(len(v) for v in especificacao.get("paths", {}).values())

    linhas = [
        "# Auditoria da especificação OpenAPI",
        "",
        f"Operações analisadas: {operacoes}. Achados: {len(achados)}.",
        "",
        "| Severidade | Operação | Achado |",
        "|---|---|---|",
        *[f"| {severidade} | `{alvo}` | {descricao} |" for severidade, alvo, descricao in achados],
    ]
    relatorio = "\n".join(linhas) + "\n"
    print(relatorio)
    if opcoes.saida:
        pathlib.Path(opcoes.saida).write_text(relatorio, encoding="utf-8")
    return 1 if any(severidade == "ALTA" for severidade, _, _ in achados) else 0


if __name__ == "__main__":
    sys.exit(main())
