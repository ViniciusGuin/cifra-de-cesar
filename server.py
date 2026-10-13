"""Servidor HTTP (somente biblioteca padrão) da cifra de César.

GET  /            -> formulário
POST /            -> processa o formulário e devolve a página com o resultado
GET  /static/...  -> arquivos estáticos (CSS)

Uso: python3 server.py  (porta definida pela variável PORT, padrão 3000)
"""

from __future__ import annotations

import html
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from urllib.parse import parse_qs

from cesar import Alfabeto, CaractereDesconhecido, ErroConfiguracao, carregar_alfabeto, transformar

RAIZ = Path(__file__).resolve().parent
PASTA_ESTATICA = RAIZ / "static"
MODELO = Template((RAIZ / "templates" / "index.html").read_text(encoding="utf-8"))

LIMITE_TEXTO = 5000
LIMITE_CORPO = 64 * 1024
LIMITE_PASSOS = 80
LIMITE_CHAVE = 10**9

CABECALHOS_SEGURANCA = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def esc(valor: object) -> str:
    return html.escape(str(valor), quote=True)


def visivel(caractere: str) -> str:
    return "␣" if caractere == " " else caractere


def renderizar_alfabeto(alfabeto: Alfabeto) -> str:
    itens = "".join(
        f'<li><span class="chip-char">{esc(visivel(alfabeto.caractere_de[v]))}</span>'
        f'<span class="chip-val">{v}</span></li>'
        for v in range(1, alfabeto.n + 1)
    )
    return f'<ul class="chips" role="list">{itens}</ul>'


def renderizar_resultado(resultado, erro: str | None) -> str:
    if erro:
        return f'<div class="alerta" role="alert">{esc(erro)}</div>'
    if resultado is None:
        return (
            '<p class="vazio">Digite um texto, escolha a chave e clique em '
            "<strong>Processar</strong> para ver o resultado aqui.</p>"
        )

    operacao = "decifrado" if resultado.decifrar else "cifrado"
    sinal = "−" if resultado.decifrar else "+"
    linhas = []
    for passo in resultado.passos[:LIMITE_PASSOS]:
        if passo.valor is None:
            linhas.append(
                f'<tr class="ignorado"><td>{esc(visivel(passo.original))}</td>'
                '<td colspan="2">fora do alfabeto (mantido)</td>'
                f"<td>{esc(visivel(passo.resultado))}</td></tr>"
            )
        else:
            linhas.append(
                f"<tr><td>{esc(visivel(passo.original))}</td><td>{passo.valor}</td>"
                f"<td>(({passo.valor} − 1 {sinal} {resultado.deslocamento}) mod {resultado.n}) + 1 = "
                f"<strong>{passo.valor_resultante}</strong></td>"
                f"<td>{esc(visivel(passo.resultado))}</td></tr>"
            )
    restante = len(resultado.passos) - LIMITE_PASSOS
    rodape = (
        f'<p class="nota">Exibindo os primeiros {LIMITE_PASSOS} de {len(resultado.passos)} caracteres.</p>'
        if restante > 0
        else ""
    )
    aviso = (
        '<p class="nota">Caracteres fora do alfabeto mantidos sem alteração: '
        + " ".join(f"<code>{esc(visivel(c))}</code>" for c in resultado.desconhecidos)
        + "</p>"
        if resultado.desconhecidos
        else ""
    )
    reducao = (
        f'<p class="nota">A chave {resultado.chave_informada} é equivalente a '
        f"{resultado.chave_informada} mod {resultado.n} = <strong>{resultado.deslocamento}</strong>.</p>"
        if resultado.chave_informada != resultado.deslocamento
        else ""
    )
    identidade = (
        '<p class="alerta">Deslocamento 0: o texto de saída é idêntico ao de entrada.</p>'
        if resultado.deslocamento == 0
        else ""
    )

    return f"""
      <div class="saida-cabecalho">
        <h2 id="titulo-resultado">Texto {operacao}</h2>
        <span class="selo">k = {resultado.deslocamento} · N = {resultado.n}</span>
      </div>
      <output class="saida" for="texto chave" aria-labelledby="titulo-resultado">{esc(resultado.texto)}</output>
      {identidade}{reducao}{aviso}
      <details class="passos">
        <summary>Passo a passo por caractere</summary>
        <div class="tabela-rolagem">
          <table>
            <thead><tr><th scope="col">Caractere</th><th scope="col">v</th>
            <th scope="col">Cálculo</th><th scope="col">Saída</th></tr></thead>
            <tbody>{''.join(linhas)}</tbody>
          </table>
        </div>
        {rodape}
      </details>
    """


def renderizar_pagina(
    alfabeto: Alfabeto, texto: str = "", chave: str = "3", decifrar: bool = False,
    resultado=None, erro: str | None = None,
) -> str:
    return MODELO.substitute(
        texto=esc(texto),
        chave=esc(chave),
        checked_cifrar="" if decifrar else "checked",
        checked_decifrar="checked" if decifrar else "",
        limite_texto=LIMITE_TEXTO,
        n=alfabeto.n,
        n_menos_1=alfabeto.n - 1,
        resultado=renderizar_resultado(resultado, erro),
        alfabeto=renderizar_alfabeto(alfabeto),
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "CifraCesar/1.0"

    def responder(self, status: HTTPStatus, corpo: bytes, tipo: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        for nome, valor in CABECALHOS_SEGURANCA.items():
            self.send_header(nome, valor)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(corpo)

    def responder_html(self, status: HTTPStatus, conteudo: str) -> None:
        self.responder(status, conteudo.encode("utf-8"), "text/html; charset=utf-8")

    def carregar(self) -> Alfabeto | None:
        # Recarregado a cada requisição para que alterações no arquivo de
        # configuração tenham efeito sem reiniciar o servidor.
        try:
            return carregar_alfabeto()
        except ErroConfiguracao as erro:
            self.responder_html(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"<h1>Configuração inválida</h1><p>{esc(erro)}</p>",
            )
            return None

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        caminho = self.path.split("?", 1)[0]
        if caminho.startswith("/static/"):
            self.servir_estatico(caminho.removeprefix("/static/"))
            return
        if caminho not in ("/", "/index.html"):
            self.responder_html(HTTPStatus.NOT_FOUND, "<h1>404 - Página não encontrada</h1>")
            return
        alfabeto = self.carregar()
        if alfabeto:
            self.responder_html(HTTPStatus.OK, renderizar_pagina(alfabeto))

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/":
            self.responder_html(HTTPStatus.NOT_FOUND, "<h1>404 - Página não encontrada</h1>")
            return
        try:
            tamanho = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            tamanho = -1
        if tamanho < 0 or tamanho > LIMITE_CORPO:
            self.responder_html(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "<h1>Requisição grande demais</h1>")
            return

        alfabeto = self.carregar()
        if not alfabeto:
            return

        campos = parse_qs(self.rfile.read(tamanho).decode("utf-8", errors="replace"))
        texto = campos.get("texto", [""])[0]
        chave_bruta = campos.get("chave", [""])[0].strip()
        decifrar = campos.get("modo", ["cifrar"])[0] == "decifrar"

        erro = None
        resultado = None
        try:
            chave = int(chave_bruta)
        except ValueError:
            erro = "A chave deve ser um número inteiro."
        else:
            if abs(chave) > LIMITE_CHAVE:
                erro = f"A chave deve estar entre −{LIMITE_CHAVE} e {LIMITE_CHAVE}."
            elif not texto:
                erro = "Informe um texto para processar."
            elif len(texto) > LIMITE_TEXTO:
                erro = f"O texto deve ter no máximo {LIMITE_TEXTO} caracteres."
            else:
                try:
                    resultado = transformar(texto, chave, alfabeto, decifrar=decifrar)
                except CaractereDesconhecido as exc:
                    erro = str(exc)

        status = HTTPStatus.OK if erro is None else HTTPStatus.BAD_REQUEST
        self.responder_html(
            status,
            renderizar_pagina(alfabeto, texto, chave_bruta, decifrar, resultado, erro),
        )

    def servir_estatico(self, relativo: str) -> None:
        arquivo = (PASTA_ESTATICA / relativo).resolve()
        if not arquivo.is_file() or PASTA_ESTATICA not in arquivo.parents:
            self.responder_html(HTTPStatus.NOT_FOUND, "<h1>404 - Arquivo não encontrado</h1>")
            return
        tipo = mimetypes.guess_type(arquivo.name)[0] or "application/octet-stream"
        if tipo.startswith("text/"):
            tipo += "; charset=utf-8"
        self.responder(HTTPStatus.OK, arquivo.read_bytes(), tipo)


def main() -> None:
    porta = int(os.environ.get("PORT", "3000"))
    servidor = ThreadingHTTPServer(("0.0.0.0", porta), Handler)
    print(f"Cifra de César disponível em http://localhost:{porta}", flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.server_close()


if __name__ == "__main__":
    main()
