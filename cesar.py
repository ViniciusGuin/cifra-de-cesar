"""Núcleo da cifra de César sobre um alfabeto configurável.

Cada caractere do alfabeto possui um valor v em 1..N (definido em
config/alfabeto.json). Para uma chave k, o valor cifrado é

    c = ((v - 1 + k) mod N) + 1

e a decifragem aplica o deslocamento inverso (-k).
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_PADRAO = Path(__file__).resolve().parent / "config" / "alfabeto.json"


class ErroConfiguracao(ValueError):
    """O arquivo de configuração do alfabeto é inválido."""


class CaractereDesconhecido(ValueError):
    """O texto contém um caractere fora do alfabeto e a configuração não permite preservá-lo."""


@dataclass(frozen=True)
class Alfabeto:
    valor_de: dict[str, int]
    caractere_de: dict[int, str]
    preservar_desconhecidos: bool = True

    @property
    def n(self) -> int:
        return len(self.valor_de)


@dataclass(frozen=True)
class Passo:
    original: str
    valor: int | None
    valor_resultante: int | None
    resultado: str


@dataclass
class Resultado:
    texto: str
    chave_informada: int
    deslocamento: int
    n: int
    decifrar: bool
    passos: list[Passo] = field(default_factory=list)
    desconhecidos: list[str] = field(default_factory=list)


def carregar_alfabeto(caminho: Path | str = CONFIG_PADRAO) -> Alfabeto:
    try:
        dados = json.loads(Path(caminho).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as erro:
        raise ErroConfiguracao(f"Não foi possível ler {caminho}: {erro}") from erro

    mapa = dados.get("alfabeto")
    if not isinstance(mapa, dict) or not mapa:
        raise ErroConfiguracao('A chave "alfabeto" deve ser um objeto não vazio.')

    valor_de: dict[str, int] = {}
    caractere_de: dict[int, str] = {}
    for caractere, valor in mapa.items():
        caractere = unicodedata.normalize("NFC", caractere)
        if len(caractere) != 1:
            raise ErroConfiguracao(f"{caractere!r} não é um único caractere.")
        # bool é subclasse de int em Python, por isso a exclusão explícita.
        if not isinstance(valor, int) or isinstance(valor, bool):
            raise ErroConfiguracao(f"O valor de {caractere!r} deve ser inteiro.")
        if caractere in valor_de:
            raise ErroConfiguracao(f"O caractere {caractere!r} está duplicado.")
        if valor in caractere_de:
            raise ErroConfiguracao(
                f"O valor {valor} foi atribuído a {caractere_de[valor]!r} e {caractere!r}."
            )
        valor_de[caractere] = valor
        caractere_de[valor] = caractere

    n = len(valor_de)
    if set(caractere_de) != set(range(1, n + 1)):
        faltando = sorted(set(range(1, n + 1)) - set(caractere_de))
        raise ErroConfiguracao(
            f"Os valores devem cobrir exatamente 1..{n}. Faltando: {faltando[:10]}"
        )

    return Alfabeto(
        valor_de=valor_de,
        caractere_de=caractere_de,
        preservar_desconhecidos=bool(dados.get("preservar_desconhecidos", True)),
    )


def deslocar(valor: int, deslocamento: int, n: int) -> int:
    # O operador % do Python sempre devolve resultado em [0, n) para n > 0,
    # inclusive com deslocamentos negativos (decifragem).
    return (valor - 1 + deslocamento) % n + 1


def transformar(texto: str, chave: int, alfabeto: Alfabeto, decifrar: bool = False) -> Resultado:
    n = alfabeto.n
    deslocamento = chave % n
    efetivo = -deslocamento if decifrar else deslocamento

    resultado = Resultado(
        texto="",
        chave_informada=chave,
        deslocamento=deslocamento,
        n=n,
        decifrar=decifrar,
    )
    saida: list[str] = []
    desconhecidos: dict[str, None] = {}

    for caractere in unicodedata.normalize("NFC", texto):
        valor = alfabeto.valor_de.get(caractere)
        if valor is None:
            if not alfabeto.preservar_desconhecidos:
                raise CaractereDesconhecido(f"O caractere {caractere!r} não pertence ao alfabeto.")
            desconhecidos[caractere] = None
            saida.append(caractere)
            resultado.passos.append(Passo(caractere, None, None, caractere))
            continue

        novo_valor = deslocar(valor, efetivo, n)
        novo_caractere = alfabeto.caractere_de[novo_valor]
        saida.append(novo_caractere)
        resultado.passos.append(Passo(caractere, valor, novo_valor, novo_caractere))

    resultado.texto = "".join(saida)
    resultado.desconhecidos = list(desconhecidos)
    return resultado


def cifrar(texto: str, chave: int, alfabeto: Alfabeto) -> Resultado:
    return transformar(texto, chave, alfabeto, decifrar=False)


def decifrar(texto: str, chave: int, alfabeto: Alfabeto) -> Resultado:
    return transformar(texto, chave, alfabeto, decifrar=True)
