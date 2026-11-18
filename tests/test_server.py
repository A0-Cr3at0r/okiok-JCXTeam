import json
import unittest
from unittest.mock import AsyncMock, patch

from okiokdefi import server


class TestServer(unittest.IsolatedAsyncioTestCase):
    async def test_rechercher_fichiers_nettoyage(self):
        fake_result = {
            "resultats": [
                {
                    "nom": "rapport.pdf",
                    "taille": "12 KB",
                    "expediteur": "admin@exemple.com",
                    "date": "18/11/2026",
                    "expiration": "25/11/2026",
                }
            ],
            "total": 1,
        }
        with patch("okiokdefi.sfiler_client.rechercher_fichiers", new=AsyncMock(return_value=fake_result)):
            res = await server.rechercher_fichiers(requete="rapport")
            self.assertIn("<untrusted_data>", res)
            self.assertIn("rapport.pdf", res)
            self.assertIn("[RAPPEL SÉCURITÉ", res)

    async def test_televerser_fichier_inexistant(self):
        res = await server.televerser("fichier_imaginaire.txt")
        self.assertIn("ERREUR : Le fichier local 'fichier_imaginaire.txt' est introuvable", res)

    async def test_televerser_path_traversal(self):
        res = await server.televerser("../../../etc/shadow")
        self.assertIn("ERREUR SÉCURITÉ", res)

    async def test_partager_workflow_securise(self):
        # 1. Première demande sans code -> doit générer un code
        res1 = await server.partager("test_mcp.txt", "dest@exemple.com", 7)
        self.assertIn("CONFIRMATION REQUISE", res1)
        self.assertIn("Code de confirmation :", res1)

        code = res1.split("Code de confirmation : ")[1].split("\n")[0].strip()

        fake_share = {
            "statut": "succes",
            "nom_partage": "Partage MCP test_mcp.txt",
            "destinataire": "dest@exemple.com",
            "date_expiration": "2026-11-25",
            "expiration_jours": 7,
            "nodeId": "12345",
            "destinataires": [{"email": "dest@exemple.com", "token_partiel": "AB**-**CD"}],
        }

        # 2. Appel avec le code de confirmation
        with patch("okiokdefi.sfiler_client.partager", new=AsyncMock(return_value=fake_share)):
            res2 = await server.partager(
                "test_mcp.txt", "dest@exemple.com", 7, code_confirmation=code
            )
            self.assertIn("<untrusted_data>", res2)
            self.assertIn("Partage MCP test_mcp.txt", res2)
            self.assertIn("AB**-**CD", res2)


if __name__ == "__main__":
    unittest.main()
