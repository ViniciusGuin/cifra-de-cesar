import json
import tempfile
import unittest
from pathlib import Path

from cesar import ErroConfiguracao, carregar_alfabeto, cifrar, decifrar


class TestCifraCesar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alfabeto = carregar_alfabeto()

    def test_tamanho_do_alfabeto(self):
        self.assertEqual(self.alfabeto.n, 100)

    def test_deslocamento_simples(self):
        self.assertEqual(cifrar("abc", 3, self.alfabeto).texto, "def")

    def test_volta_ao_inicio(self):
        # "'" tem valor 100 (o último); com k = 1 volta para "a" (valor 1).
        self.assertEqual(cifrar("'", 1, self.alfabeto).texto, "a")

    def test_ida_e_volta(self):
        texto = "Atacar ao amanhecer, às 6h! Ação: 'coração'."
        for chave in (1, 3, 47, 99, 100, 250, -7):
            cifrado = cifrar(texto, chave, self.alfabeto).texto
            self.assertEqual(decifrar(cifrado, chave, self.alfabeto).texto, texto)

    def test_chaves_congruentes_sao_equivalentes(self):
        texto = "Olá, mundo"
        self.assertEqual(
            cifrar(texto, 3, self.alfabeto).texto,
            cifrar(texto, 103, self.alfabeto).texto,
        )

    def test_chave_zero_e_identidade(self):
        self.assertEqual(cifrar("Teste", 100, self.alfabeto).texto, "Teste")

    def test_caracteres_desconhecidos_preservados(self):
        resultado = cifrar("a@b", 1, self.alfabeto)
        self.assertEqual(resultado.texto, "b@c")
        self.assertEqual(resultado.desconhecidos, ["@"])

    def test_normaliza_acentos_decompostos(self):
        decomposto = "a\u0301"  # "a" + acento agudo combinante
        self.assertEqual(cifrar(decomposto, 0, self.alfabeto).texto, "á")

    def test_configuracao_com_lacuna_e_rejeitada(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = Path(pasta) / "alfabeto.json"
            caminho.write_text(json.dumps({"alfabeto": {"a": 1, "b": 3}}), encoding="utf-8")
            with self.assertRaises(ErroConfiguracao):
                carregar_alfabeto(caminho)


if __name__ == "__main__":
    unittest.main()
