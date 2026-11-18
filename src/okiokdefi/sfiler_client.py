import base64
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv("SFILER_BASE_URL", "https://sfilerdemo2.sfiler.com/sfiler").rstrip("/")
USERNAME = os.getenv("SFILER_USERNAME", "")
PASSWORD = os.getenv("SFILER_PASSWORD", "")
DOMAIN_ID = os.getenv("SFILER_DOMAIN_ID", "1")


class SFilterSessionError(Exception):
    """Erreur d'authentification ou de session S-Filer."""


def _nettoyer_cookies_session(client: httpx.AsyncClient) -> None:
    """Garantit qu'un seul cookie JSESSIONID existe pour éviter l'erreur 400 Duplicate sessions de Jetty."""
    jsessionids = [c for c in client.cookies.jar if c.name == "JSESSIONID"]
    if len(jsessionids) > 1:
        dernier = jsessionids[-1]
        for cookie in jsessionids[:-1]:
            client.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
        client.cookies.set("JSESSIONID", dernier.value, domain=dernier.domain, path=dernier.path)


def _extraire_csrf(html: str) -> str:
    """Extrait le jeton CSRF depuis le HTML de Tree.action."""
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


async def _creer_client_authentifie() -> tuple[httpx.AsyncClient, str]:
    """Initialise une session S-Filer authentifiée et retourne (client, csrf_token)."""
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
            raise SFilterSessionError("Échec de l'authentification S-Filer.")

        csrf_token = _extraire_csrf(resp_tree.text) or _extraire_csrf(resp_login.text)
        if csrf_token:
            client.headers["X-CSRF-Token"] = csrf_token

        return client, csrf_token
    except Exception:
        await client.aclose()
        raise


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


async def _obtenir_noeud_racine(client: httpx.AsyncClient, csrf_token: str, communaute: str = "") -> str:
    """Récupère le treeNodeId du dossier racine (boîte de réception ou communauté ciblée)."""
    action_param = ""
    if communaute:
        tree_resp = await client.post("/TreeBuilder.action", data={"CSRFToken": csrf_token})
        tree_resp.raise_for_status()
        for entry in tree_resp.json().get("entry", []):
            if communaute.lower() in entry.get("nodeName", "").lower():
                action_id = entry.get("nodeActionId", "")
                if action_id.startswith("tree_community"):
                    comm_id = action_id.removeprefix("tree_community")
                    action_param = f"communityId={comm_id}"
                    break

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


async def rechercher_fichiers(requete: str = "", envoyeur: str = "") -> str:
    """Recherche des fichiers via RecentFilesAjax.action et l'arborescence TreeBuilder.action."""
    client, csrf_token = await _creer_client_authentifie()
    try:
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

        if not resp.text.strip() or "Une erreur s'est produite" in resp.text:
            tree_resp = await client.post("/TreeBuilder.action", data={"CSRFToken": csrf_token})
            tree_resp.raise_for_status()
            return tree_resp.text

        return resp.text
    finally:
        await client.aclose()


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

    # Étape 1 : Initialisation roaming en application/x-www-form-urlencoded
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

    # Étape 2 : Envoi du binaire chiffré en multipart/form-data avec CSRFToken & nodeId en query string
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


async def televerser(fichier: str, node_id: str = "") -> str:
    """Téléverse un fichier local chiffré vers S-Filer via ajaxupload."""
    client, csrf_token = await _creer_client_authentifie()
    try:
        return await _televerser_avec_session(client, csrf_token, fichier, node_id=node_id)
    finally:
        await client.aclose()


async def partager(
    fichier: str,
    destinataire: str,
    expiration_jours: int = 7,
    message: str = "",
) -> str:
    """Crée un transfert anonyme / envoi rapide et y téléverse le fichier dans la même session."""
    client, csrf_token = await _creer_client_authentifie()
    try:
        maintenant = datetime.now(tz=UTC)
        horodatage = maintenant.strftime("%Y-%m-%d %H.%M.%S")
        share_name = f"Partage MCP {Path(fichier).name} {horodatage}"
        date_expiration = (maintenant.date() + timedelta(days=expiration_jours)).isoformat()

        payload = {
            "defaultShareNameLanguage": "fr",
            "messageToRecipients": message or f"Partage sécurisé du fichier {Path(fichier).name}",
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
        if node_id and Path(fichier).exists():
            await _televerser_avec_session(client, csrf_token, fichier, node_id=node_id)

        return f"Partage '{share_name}' créé pour {destinataire} (expiration : {date_expiration}). Réponse : {transfer_info}"
    finally:
        await client.aclose()


async def lister_activite(jours: int = 7) -> str:
    """Liste l'activité récente sur le compte S-Filer."""
    client, csrf_token = await _creer_client_authentifie()
    try:
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
        return resp.text
    finally:
        await client.aclose()