import unittest
from okiokdefi.sfiler_client import SfilerFileListParser


class TestSfilerParser(unittest.TestCase):
    def test_parser_empty_html(self):
        parser = SfilerFileListParser()
        parser.feed("<html><body><table id='inbox'></table></body></html>")
        self.assertEqual(len(parser.items), 0)

    def test_parser_sample_html(self):
        sample_html = """
        <table id="inbox">
            <tr class="inbox-row-top">
                <td><input type="checkbox" name="checkbox_0" title="rapport.pdf">
                    <input type="hidden" id="uuid_0" value="abc-123-def"></td>
                <td><img src="icon.png"></td>
                <td><a href="#">rapport.pdf</a></td>
                <td>alice@exemple.com</td>
                <td>18/11/2026 12:00:00 UTC</td>
                <td>25/11/2026 12:00:00 UTC</td>
            </tr>
            <tr class="inbox-row-bottom">
                <td><a href="#" title="/Dossier Principal" onclick="showGlobalFileList(123)">/Dossier Principal</a></td>
                <td>alice@exemple.com</td>
                <td>42.50 KB</td>
                <td>Téléchargement(s): aucune limite</td>
            </tr>
        </table>
        """
        parser = SfilerFileListParser()
        parser.feed(sample_html)
        self.assertEqual(len(parser.items), 1)
        item = parser.items[0]
        self.assertEqual(item["nom"], "rapport.pdf")
        self.assertEqual(item["uuid"], "abc-123-def")
        self.assertEqual(item["expediteur"], "alice@exemple.com")
        self.assertEqual(item["taille"], "42.50 KB")
        self.assertEqual(item["date"], "18/11/2026 12:00:00 UTC")
        self.assertEqual(item["expiration"], "25/11/2026 12:00:00 UTC")
        self.assertEqual(item["emplacement"], "/Dossier Principal")


if __name__ == "__main__":
    unittest.main()
