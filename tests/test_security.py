import unittest
from pathlib import Path
from okiokdefi import security


class TestSecurity(unittest.TestCase):
    def test_valider_chemin_local_valide(self):
        # Fichier valide dans le workspace
        result = security.valider_chemin_local("test_mcp.txt")
        self.assertIsNone(result)

    def test_valider_chemin_local_traversal(self):
        # Path traversal
        result = security.valider_chemin_local("../../etc/passwd")
        self.assertIsNotNone(result)
        self.assertIn("Accès refusé hors du répertoire autorisé", result)

    def test_valider_chemin_local_hidden(self):
        # Fichier caché
        result = security.valider_chemin_local(".env")
        self.assertIsNotNone(result)
        self.assertIn("Accès refusé aux fichiers ou dossiers cachés", result)

    def test_valider_chemin_local_null_byte(self):
        # Null byte injection
        result = security.valider_chemin_local("test.txt\x00.png")
        self.assertIsNotNone(result)
        self.assertIn("Chemin de fichier invalide", result)

    def test_valider_texte_sfiler_valide(self):
        self.assertIsNone(security.valider_texte_sfiler("mon_fichier.pdf", "fichier"))
        self.assertIsNone(security.valider_texte_sfiler("Dossier Comptabilité 2026", "dossier"))
        self.assertIsNone(security.valider_texte_sfiler("user@exemple.com", "envoyeur"))

    def test_valider_texte_sfiler_injections(self):
        # Injection SQL / HTML
        self.assertIsNotNone(security.valider_texte_sfiler("<script>alert(1)</script>", "requete"))
        self.assertIsNotNone(security.valider_texte_sfiler("'; DROP TABLE--", "requete"))
        # Injection LDAP
        self.assertIsNotNone(security.valider_texte_sfiler("*(|(mail=*))", "requete"))
        # Command injection
        self.assertIsNotNone(security.valider_texte_sfiler("test; rm -rf /", "requete"))

    def test_verifier_partage_jeton(self):
        # Étape 1 : sans code -> doit générer un code
        ok, msg = security.verifier_partage("test_mcp.txt", "test@exemple.com", 7)
        self.assertFalse(ok)
        self.assertIn("Code de confirmation :", msg)
        code = msg.split("Code de confirmation : ")[1].split("\n")[0].strip()

        # Étape 2 : tentative avec mauvais code
        ok_bad, msg_bad = security.verifier_partage(
            "test_mcp.txt", "test@exemple.com", 7, code_confirmation="WRONG1"
        )
        self.assertFalse(ok_bad)
        self.assertIn("Code de confirmation invalide", msg_bad)

        # Étape 3 : tentative avec modification des paramètres (tampering)
        ok_tamper, msg_tamper = security.verifier_partage(
            "test_mcp.txt", "hacker@evil.com", 7, code_confirmation=code
        )
        self.assertFalse(ok_tamper)
        self.assertIn("ne correspondent pas", msg_tamper)

        # Regénération d'un code valide pour tester le succès
        ok, msg = security.verifier_partage("test_mcp.txt", "test@exemple.com", 7)
        code = msg.split("Code de confirmation : ")[1].split("\n")[0].strip()

        # Étape 4 : validation avec les bons paramètres
        ok_good, msg_good = security.verifier_partage(
            "test_mcp.txt", "test@exemple.com", 7, code_confirmation=code
        )
        self.assertTrue(ok_good)
        self.assertEqual(msg_good, "CONFIRMATION_OK")

        # Étape 5 : anti-rejeu (le code ne peut pas être réutilisé)
        ok_replay, msg_replay = security.verifier_partage(
            "test_mcp.txt", "test@exemple.com", 7, code_confirmation=code
        )
        self.assertFalse(ok_replay)


if __name__ == "__main__":
    unittest.main()
