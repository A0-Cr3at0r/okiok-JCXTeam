import asyncio
import base64
import json
import logging
import os
import re
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

BASE_URL = os.getenv("SFILER_BASE_URL", "https://sfilerdemo2.sfiler.com/sfiler").rstrip("/")
USERNAME = os.getenv("SFILER_USERNAME", "")
PASSWORD = os.getenv("SFILER_PASSWORD", "")
DOMAIN_ID = os.getenv("SFILER_DOMAIN_ID", "1")


class SFilterSessionError(Exception):
    """Erreur d'authentification ou de session S-Filer."""


class SfilerFileListParser(HTMLParser):
    """Parseur HTML pour extraire proprement les fichiers depuis RecentFilesAjax.action."""

    def __init__(self) -> None:
        super().__init__()
        self.items: list[dict[str, Any]] = []
        self._current_item: dict[str, Any] | None = None
        self._text_buffer: list[str] = []
        self._in_top_row = False
        self._in_bottom_row = False
        self._td_index = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        self._text_buffer = []

        if tag == "tr":
            classes = (attrs_dict.get("class") or "").split()
            if "inbox-row-top" in classes:
                self._in_top_row = True
                self._in_bottom_row = False
                self._td_index = 0
                self._current_item = {
                    "nom": "",
                    "uuid": "",
                    "expediteur": "",
                    "date": "",
                    "expiration": "",
                    "taille": "",
                    "emplacement": "",
                    "telechargements": "",
                }
            elif "inbox-row-bottom" in classes:
                self._in_bottom_row = True
                self._in_top_row = False
                self._td_index = 0

        elif tag == "td" and (self._in_top_row or self._in_bottom_row):
            self._td_index += 1

        elif tag == "input" and self._in_top_row and self._current_item:
            name = attrs_dict.get("name") or ""
            if name.startswith("checkbox_"):
                self._current_item["nom"] = attrs_dict.get("title") or attrs_dict.get("aria-label") or ""
            elif (attrs_dict.get("id") or "").startswith("uuid_"):
                self._current_item["uuid"] = attrs_dict.get("value") or ""

        elif tag == "a" and self._in_bottom_row and self._current_item:
            if "showGlobalFileList" in (attrs_dict.get("onclick") or ""):
                self._current_item["emplacement"] = attrs_dict.get("title") or ""

    def handle_data(self, data: str) -> None:
        self._text_buffer.append(data)

    def handle_endtag(self, tag: str) -> None:
        text = "".join(self._text_buffer).strip()

        if tag == "td" and self._current_item:
            if self._in_top_row:
                if self._td_index == 3 and not self._current_item["nom"]:
                    self._current_item["nom"] = text
                elif self._td_index == 4:
                    self._current_item["expediteur"] = text
                elif self._td_index == 5:
                    self._current_item["date"] = text
                elif self._td_index == 6:
                    self._current_item["expiration"] = text
            elif self._in_bottom_row:
                if self._td_index == 1 and not self._current_item["emplacement"]:
                    self._current_item["emplacement"] = text
                elif self._td_index == 3:
                    self._current_item["taille"] = text
                elif self._td_index == 4:
                    self._current_item["telechargements"] = " ".join(text.split())

        elif tag == "tr":
            if self._in_bottom_row and self._current_item:
                if self._current_item.get("nom"):
                    self.items.append(self._current_item)
                self._current_item = None
                self._in_bottom_row = False
            elif self._in_top_row:
                self._in_top_row = False


def _nettoyer_cookies_session(client: httpx.AsyncClient) -> None:
    """Garantit qu'un seul cookie JSESSIONID existe pour éviter l'erreur 400 Duplicate sessions de Jetty."""

    jsessionids = [c for c in client.cookies.jar if c.name == "JSESSIONID"]
    if len(jsessionids) > 1:
        dernier = jsessionids[-1]
        for cookie in jsessionids[:-1]:
            client.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
        client.cookies.set("JSESSIONID", dernier.value, domain=dernier.domain, path=dernier.path)


def _extraire_csrf(html: str) -> str:
    """Extrait le jeton CSRF depuis le HTML de Tree.action ou Login.action."""

    motifs = [
        r'name=["\']CSRFToken["\'][^>]*value=["\']([a-zA-Z0-9]+)["\']',
        r'csrf-token=["\']([a-zA-Z0-9]+)["\']',
        r"CSRFToken=([a-zA-Z0-9]+)",
    ]
    for motif in motifs:
        match = re.search(motif, html, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


class SfilerSessionManager:
    """Gestionnaire de session HTTP persistante avec reconnexion automatique."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._csrf_token: str = ""
        self._lock = asyncio.Lock()

    async def get_session(self, force_refresh: bool = False) -> tuple[httpx.AsyncClient, str]:
        async with self._lock:
            if self._client is None or self._client.is_closed or force_refresh:
                if self._client and not self._client.is_closed:
                    await self._client.aclose()
                self._client, self._csrf_token = await self._authentifier()
            return self._client, self._csrf_token

    async def _authentifier(self) -> tuple[httpx.AsyncClient, str]:
        if not USERNAME or not PASSWORD:
            raise SFilterSessionError("Identifiants SFILER_USERNAME / SFILER_PASSWORD manquants dans .env.")

        client = httpx.AsyncClient(
            base_url=BASE_URL,
            follow_redirects=True,
            timeout=30.0,
            headers={
                "User-Agent": "Mozilla/5.0",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        try:
            await client.get("/Login.action")
            _nettoyer_cookies_session(client)

            resp_login = await client.post(
                "/Login.action",
                data={
                    "origUrl": "Tree.action",
                    "request_locale": "fr",
                    "loginForm.domain": DOMAIN_ID,
                    "loginForm.username": USERNAME,
                    "loginForm.directAccessToken": "",
                    "loginForm.password": PASSWORD,
                },
                follow_redirects=False,
            )
            _nettoyer_cookies_session(client)

            if resp_login.is_redirect and "location" in resp_login.headers:
                await client.get(resp_login.headers["location"])
                _nettoyer_cookies_session(client)

            resp_tree = await client.get("/Tree.action")
            _nettoyer_cookies_session(client)

            if "Login.action" in str(resp_tree.url):
                raise SFilterSessionError("Échec de l'authentification S-Filer : identifiants invalides.")

            csrf_token = _extraire_csrf(resp_tree.text) or _extraire_csrf(resp_login.text)
            if not csrf_token:
                raise SFilterSessionError("Impossible de récupérer le jeton CSRF après connexion.")

            client.headers["X-CSRF-Token"] = csrf_token
            return client, csrf_token
        except Exception:
            await client.aclose()
            raise

    async def fermer(self) -> None:
        async with self._lock:
            if self._client and not self._client.is_closed:
                await self._client.aclose()
                self._client = None
                self._csrf_token = ""


_SESSION_MANAGER = SfilerSessionManager()


async def _executer_avec_session(action: Callable[[httpx.AsyncClient, str], Any]) -> Any:
    """Exécute une requête avec la session persistante et réessaie une fois si la session a expiré."""

    client, csrf_token = await _SESSION_MANAGER.get_session()
    try:
        return await action(client, csrf_token)
    except (httpx.HTTPStatusError, SFilterSessionError) as ex:
        logger.warning("Session S-Filer potentiellement expirée (%s), réauthentification...", ex)
        client, csrf_token = await _SESSION_MANAGER.get_session(force_refresh=True)
        return await action(client, csrf_token)


def _chiffrer_fichier_sfiler(contenu: bytes, wrapping_public_key_b64: str) -> tuple[bytes, str, str]:
    """Chiffre le fichier en AES-128-CTR et enveloppe la clé symétrique avec RSA-OAEP SHA-256."""

    cle_der = base64.b64decode(wrapping_public_key_b64)
    try:
        pub_key = serialization.load_der_public_key(cle_der)
    except ValueError:
        cert = x509.load_der_x509_certificate(cle_der)
        pub_key = cert.public_key()

    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise TypeError("Clé publique système RSA invalide.")

    aes_key = os.urandom(16)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    contenu_chiffre = encryptor.update(contenu) + encryptor.finalize()

    wrapped_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return (
        contenu_chiffre,
        base64.b64encode(wrapped_key).decode("ascii"),
        base64.b64encode(iv).decode("ascii"),
    )


async def _obtenir_noeud_racine(
    client: httpx.AsyncClient,
    csrf_token: str,
    communaute: str = "",
    dossier: str = "",
) -> str:
    """Récupère le treeNodeId du dossier racine, de la communauté ou du dossier ciblé."""

    action_param = ""
    if communaute or dossier:
        tree_resp = await client.post("/TreeBuilder.action", data={"CSRFToken": csrf_token})
        tree_resp.raise_for_status()
        entries = tree_resp.json().get("entry", [])

        if communaute:
            for entry in entries:
                if communaute.lower() in (entry.get("nodeName") or "").lower():
                    action_id = entry.get("nodeActionId", "")
                    if action_id.startswith("tree_community"):
                        comm_id = action_id.removeprefix("tree_community")
                        action_param = f"communityId={comm_id}"
                        break
            if not action_param:
                raise ValueError(f"Communauté '{communaute}' introuvable sur S-Filer.")

        elif dossier and not dossier.isdigit():
            for entry in entries:
                if dossier.lower() in (entry.get("nodeName") or "").lower():
                    node_id = entry.get("nodeId")
                    if node_id:
                        return str(node_id)
            raise ValueError(f"Dossier '{dossier}' introuvable dans l'arborescence S-Filer.")

    resp = await client.get(
        "/FileListAjax.action",
        params={
            "search_box": "",
            "treeNodeId": "",
            "nbrRow": 25,
            "action": action_param,
            "CSRFToken": csrf_token,
        },
    )
    resp.raise_for_status()
    match = re.search(r'name=["\']treeNodeId["\'][^>]*value=["\'](\d+)["\']', resp.text)
    if not match:
        raise SFilterSessionError("Impossible de trouver treeNodeId dans FileListAjax.action.")
    return match.group(1)


async def _televerser_avec_session(
    client: httpx.AsyncClient,
    csrf_token: str,
    fichier: str,
    node_id: str = "",
) -> str:
    """Exécute le téléversement chiffré E2EE en 2 étapes sur ajaxupload (1: roaming init, 2: multipart chiffré)."""

    chemin = Path(fichier)
    contenu_clair = chemin.read_bytes()
    cible_node_id = node_id or await _obtenir_noeud_racine(client, csrf_token)

    base_headers = {
        "useEndToEndEncryption": "true",
        "Referer": f"{BASE_URL}/Tree.action",
    }

    init_resp = await client.post(
        "/ajaxupload",
        data={
            "CSRFToken": csrf_token,
            "nodeId": str(cible_node_id),
            "size": str(len(contenu_clair)),
            "uploadfile": chemin.name,
        },
        headers={**base_headers, "roaming": "true"},
    )
    init_resp.raise_for_status()
    roaming = init_resp.json().get("roamingInfos", {})

    pub_key_b64 = roaming.get("wrappingPublicKey")
    cert_id = roaming.get("systemCertificateId")
    digest_algo = roaming.get("digestAlgorithm", "SHA-1")

    if not pub_key_b64:
        key_resp = await client.post("/internal/api/v3/transfers/retrieve-system-public-key")
        key_resp.raise_for_status()
        key_info = key_resp.json()
        pub_key_b64 = key_info["systemPublicKey"]
        cert_id = key_info["systemCertificateId"]

    contenu_chiffre, wrapped_key_b64, iv_b64 = _chiffrer_fichier_sfiler(contenu_clair, pub_key_b64)

    form_data = {
        "CSRFToken": csrf_token,
        "nodeId": str(cible_node_id),
        "size": str(len(contenu_clair)),
        "systemCertificateId": str(cert_id),
        "wrappedSymmetricKey": wrapped_key_b64,
        "wrappingAlgorithm": "RSA/ECB/OAEPwithSHA-256andMGF1Padding",
        "iv": iv_b64,
        "digestAlgorithm": digest_algo,
    }
    files = {
        "uploadfile": (chemin.name, contenu_chiffre, "application/octet-stream"),
    }

    upload_resp = await client.post(
        "/ajaxupload",
        params={"CSRFToken": csrf_token, "nodeId": str(cible_node_id)},
        data=form_data,
        files=files,
        headers=base_headers,
    )
    upload_resp.raise_for_status()
    return upload_resp.text


async def rechercher_fichiers(requete: str = "", envoyeur: str = "") -> dict[str, Any]:
    """Recherche des fichiers via RecentFilesAjax.action et retourne une structure JSON propre."""
    async def _action(client: httpx.AsyncClient, csrf_token: str) -> dict[str, Any]:
        params: dict[str, Any] = {
            "search_box": requete,
            "treeNodeId": "",
            "nbrRow": 50,
            "filter": "",
            "fromRecentFiles": "",
            "fromSentFiles": "",
            "CSRFToken": csrf_token,
        }
        if envoyeur:
            params["sender"] = envoyeur

        resp = await client.get("/RecentFilesAjax.action", params=params)
        resp.raise_for_status()

        if "Login.action" in str(resp.url):
            raise SFilterSessionError("Session expirée")

        if not resp.text.strip() or "Une erreur s'est produite" in resp.text:
            tree_resp = await client.post("/TreeBuilder.action", data={"CSRFToken": csrf_token})
            tree_resp.raise_for_status()
            try:
                tree_data = tree_resp.json()
                nodes = [
                    {
                        "nom": e.get("nodeName"),
                        "id": e.get("nodeId"),
                        "type": e.get("nodeActionId"),
                    }
                    for e in tree_data.get("entry", [])
                    if not requete or requete.lower() in (e.get("nodeName") or "").lower()
                ]
                return {"resultats": nodes, "total": len(nodes), "source": "arborescence"}
            except Exception:
                return {"resultats": [], "total": 0, "source": "arborescence"}

        parser = SfilerFileListParser()
        parser.feed(resp.text)
        return {
            "resultats": parser.items,
            "total": len(parser.items),
            "filtres": {
                "requete": requete or None,
                "envoyeur": envoyeur or None,
            },
        }

    return await _executer_avec_session(_action)


async def televerser(fichier: str, dossier: str = "", communaute: str = "") -> dict[str, Any]:
    """Téléverse un fichier local chiffré vers S-Filer via ajaxupload."""

    chemin = Path(fichier)
    if not chemin.is_file():
        raise FileNotFoundError(f"Le fichier local '{fichier}' est introuvable.")

    async def _action(client: httpx.AsyncClient, csrf_token: str) -> dict[str, Any]:
        node_id = ""
        if communaute or (dossier and not dossier.isdigit()):
            node_id = await _obtenir_noeud_racine(client, csrf_token, communaute=communaute, dossier=dossier)
        elif dossier.isdigit():
            node_id = dossier

        raw_resp = await _televerser_avec_session(client, csrf_token, fichier, node_id=node_id)
        try:
            parsed = json.loads(raw_resp)
        except Exception:
            parsed = {"reponse_brute": raw_resp.strip()}

        return {
            "statut": "succes",
            "fichier": chemin.name,
            "taille_octets": chemin.stat().st_size,
            "details": parsed,
        }

    return await _executer_avec_session(_action)


async def partager(
    fichier: str,
    destinataire: str,
    expiration_jours: int = 7,
    message: str = "",
) -> dict[str, Any]:
    """Crée un transfert sécurisé anonyme et y téléverse le fichier."""

    chemin = Path(fichier)
    if not chemin.is_file():
        raise FileNotFoundError(f"Le fichier local '{fichier}' est introuvable pour le partage.")

    async def _action(client: httpx.AsyncClient, csrf_token: str) -> dict[str, Any]:
        maintenant = datetime.now(tz=UTC)
        horodatage = maintenant.strftime("%Y-%m-%d %H.%M.%S")
        share_name = f"Partage MCP {chemin.name} {horodatage}"
        date_expiration = (maintenant.date() + timedelta(days=expiration_jours)).isoformat()

        payload = {
            "defaultShareNameLanguage": "fr",
            "messageToRecipients": message or f"Partage sécurisé du fichier {chemin.name}",
            "operationType": "SEND",
            "recipients": [
                {
                    "email": destinataire,
                    "language": "fr",
                    "permissionId": 1,
                    "secretType": "NONE",
                    "secretValue": "",
                }
            ],
            "themeId": None,
            "shareExpirationDate": date_expiration,
            "shareName": share_name,
            "templateId": "",
        }

        resp = await client.post("/api/v3/http/anonymous-transfer", json=payload)
        resp.raise_for_status()
        transfer_info = resp.json()

        node_id = str(transfer_info.get("nodeId") or transfer_info.get("folderId") or "")
        if node_id:
            await _televerser_avec_session(client, csrf_token, fichier, node_id=node_id)

        tokens = transfer_info.get("tokens", [])
        tokens_masques = [
            {"email": t.get("email"), "token_partiel": t.get("displayValue")}
            for t in tokens
        ]

        return {
            "statut": "succes",
            "nom_partage": share_name,
            "destinataire": destinataire,
            "date_expiration": date_expiration,
            "expiration_jours": expiration_jours,
            "nodeId": node_id,
            "destinataires": tokens_masques,
        }

    return await _executer_avec_session(_action)


async def lister_activite(jours: int = 7) -> dict[str, Any]:
    """Liste l'activité récente sur le compte S-Filer sous forme structurée."""
    
    async def _action(client: httpx.AsyncClient, csrf_token: str) -> dict[str, Any]:
        resp = await client.get(
            "/RecentFilesAjax.action",
            params={
                "search_box": "",
                "treeNodeId": "",
                "nbrRow": 50,
                "filter": "",
                "fromRecentFiles": "true",
                "fromSentFiles": "",
                "days": jours,
                "CSRFToken": csrf_token,
            },
        )
        resp.raise_for_status()

        if "Login.action" in str(resp.url):
            raise SFilterSessionError("Session expirée")

        parser = SfilerFileListParser()
        parser.feed(resp.text)
        return {
            "activite_recents": parser.items,
            "total": len(parser.items),
            "periode_jours": jours,
        }

    return await _executer_avec_session(_action)
