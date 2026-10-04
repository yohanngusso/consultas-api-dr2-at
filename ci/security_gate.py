"""Security gate do pipeline (Ex. 12).

Bloqueia quando houver:
  1. achado de severidade alta ou crítica (equivalente a CVSS >= 7.0) em qualquer ferramenta;
  2. achado médio cuja CWE pertença às classes que, no histórico deste Assessment, resultaram em CVSS >= 7.0:
     controle de acesso (A01), injeção (A03) e credencial no código (A07);
  3. vulnerabilidade conhecida em dependência (o pip-audit não informa severidade, então vale como alta).
Achados abaixo disso são listados como aviso. Exceções exigem arquivo, justificativa e data de validade em ci/excecoes-seguranca.json.
"""

import argparse
import datetime
import json
import os
import pathlib
import sys
from dataclasses import dataclass

CWES_BLOQUEANTES = {
    22, 200, 201, 284, 285, 352, 359, 425, 639, 862, 863,
    78, 79, 89, 94, 943,
    259, 798,
}
ARQUIVO_DE_EXCECOES = pathlib.Path(__file__).with_name("excecoes-seguranca.json")


@dataclass
class Achado:
    ferramenta: str
    identificador: str
    severidade: str
    cwe: int | None
    local: str
    descricao: str

    @property
    def bloqueia(self) -> bool:
        if self.severidade in {"CRITICA", "ALTA"}:
            return True
        return self.severidade == "MEDIA" and self.cwe in CWES_BLOQUEANTES


def _ler(caminho: str | None) -> dict | list | None:
    if not caminho:
        return None
    if not pathlib.Path(caminho).exists():
        sys.exit(f"Relatório ausente: {caminho}. Sem evidência a etapa conta como reprovada.")
    texto = pathlib.Path(caminho).read_text(encoding="utf-8").strip()
    return json.loads(texto) if texto else None


def _cwe(valor) -> int | None:
    if isinstance(valor, dict):
        valor = valor.get("id")
    if isinstance(valor, list):
        valor = valor[0] if valor else None
    if isinstance(valor, str):
        valor = "".join(c for c in valor.split(":")[0] if c.isdigit()) or None
    try:
        return int(valor) if valor is not None and int(valor) > 0 else None
    except (TypeError, ValueError):
        return None


def achados_bandit(dados) -> list[Achado]:
    mapa = {"HIGH": "ALTA", "MEDIUM": "MEDIA", "LOW": "BAIXA"}
    resultado = []
    for item in (dados or {}).get("results", []):
        severidade = mapa.get(item["issue_severity"], "BAIXA")
        if severidade == "ALTA" and item["issue_confidence"] == "LOW":
            severidade = "MEDIA"
        resultado.append(Achado("bandit", item["test_id"], severidade, _cwe(item.get("issue_cwe")),
                                f"{item['filename']}:{item['line_number']}", item["issue_text"]))
    return resultado


def achados_semgrep(dados) -> list[Achado]:
    mapa = {"ERROR": "ALTA", "WARNING": "MEDIA", "INFO": "BAIXA"}
    resultado = []
    for item in (dados or {}).get("results", []):
        extra = item.get("extra", {})
        resultado.append(Achado("semgrep", item["check_id"].rsplit(".", 1)[-1], mapa.get(extra.get("severity"), "BAIXA"),
                                _cwe(extra.get("metadata", {}).get("cwe")),
                                f"{item['path']}:{item['start']['line']}", extra.get("message", "")[:160]))
    return resultado


def achados_pip_audit(dados) -> list[Achado]:
    resultado = []
    for dependencia in (dados or {}).get("dependencies", []):
        for vulnerabilidade in dependencia.get("vulns", []):
            correcao = ", ".join(vulnerabilidade.get("fix_versions", [])) or "sem versão corrigida"
            resultado.append(Achado("pip-audit", vulnerabilidade["id"], "ALTA", None,
                                    f"{dependencia['name']}=={dependencia['version']}", f"corrigido em: {correcao}"))
    return resultado


def achados_zap(dados) -> list[Achado]:
    mapa = {"3": "ALTA", "2": "MEDIA", "1": "BAIXA", "0": "INFO"}
    resultado = []
    for site in (dados or {}).get("site", []):
        for alerta in site.get("alerts", []):
            instancias = alerta.get("instances", [])
            local = instancias[0]["uri"] if instancias else site.get("@name", "")
            resultado.append(Achado("zap", alerta["pluginid"], mapa.get(str(alerta["riskcode"]), "INFO"),
                                    _cwe(alerta.get("cweid")), f"{local} ({len(instancias)} ocorrências)", alerta["alert"]))
    return resultado


def excecoes_vigentes() -> list[dict]:
    hoje = datetime.date.today()
    return [
        excecao for excecao in _ler(str(ARQUIVO_DE_EXCECOES)) or []
        if excecao.get("justificativa") and datetime.date.fromisoformat(excecao["expira_em"]) >= hoje
    ]


def coberto_por_excecao(achado: Achado, excecoes: list[dict]) -> bool:
    local = achado.local.replace("\\", "/")
    return any(
        e["ferramenta"] == achado.ferramenta and e["identificador"] == achado.identificador
        and local.startswith(e["arquivo"])
        for e in excecoes
    )


def main() -> int:
    argumentos = argparse.ArgumentParser()
    argumentos.add_argument("--bandit")
    argumentos.add_argument("--semgrep")
    argumentos.add_argument("--pip-audit", dest="pip_audit")
    argumentos.add_argument("--zap", action="append", default=[])
    argumentos.add_argument("--saida")
    opcoes = argumentos.parse_args()

    achados = achados_bandit(_ler(opcoes.bandit)) + achados_semgrep(_ler(opcoes.semgrep)) + achados_pip_audit(_ler(opcoes.pip_audit))
    for relatorio_zap in opcoes.zap:
        achados += achados_zap(_ler(relatorio_zap))

    excecoes = excecoes_vigentes()
    bloqueantes = [a for a in achados if a.bloqueia and not coberto_por_excecao(a, excecoes)]
    ordem = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAIXA": 3, "INFO": 4}
    achados.sort(key=lambda a: (not a.bloqueia, ordem[a.severidade], a.ferramenta))

    linhas = [
        "# Security gate",
        "",
        f"Resultado: **{'BLOQUEADO' if bloqueantes else 'APROVADO'}**. "
        f"Achados: {len(achados)}; bloqueantes: {len(bloqueantes)}; exceções vigentes: {len(excecoes)}.",
        "",
        "| Decisão | Ferramenta | Regra | Severidade | CWE | Local | Descrição |",
        "|---|---|---|---|---|---|---|",
    ]
    for achado in achados:
        if achado.bloqueia and coberto_por_excecao(achado, excecoes):
            decisao = "exceção"
        else:
            decisao = "BLOQUEIA" if achado.bloqueia else "aviso"
        descricao = achado.descricao.replace("|", "/").replace("\n", " ")
        linhas.append(f"| {decisao} | {achado.ferramenta} | {achado.identificador} | {achado.severidade} | "
                      f"{achado.cwe or '-'} | `{achado.local}` | {descricao} |")
    relatorio = "\n".join(linhas) + "\n"

    print(relatorio)
    for destino in filter(None, [opcoes.saida, os.environ.get("GITHUB_STEP_SUMMARY")]):
        with open(destino, "a", encoding="utf-8") as arquivo:
            arquivo.write(relatorio)
    return 1 if bloqueantes else 0


if __name__ == "__main__":
    sys.exit(main())
