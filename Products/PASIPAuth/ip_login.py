import ipaddress
import logging

from plone import api
from plone.protect.interfaces import IDisableCSRFProtection
from plone.restapi.services import Service
from zExceptions import Unauthorized
from zope.interface import alsoProvides

logger = logging.getLogger(__name__)


def _get_all_client_ips(request):
    """
    Return all candidate IPs — forwarded chain first, then REMOTE_ADDR.

    Mirrors the logic in AuthIPPlugin.extractCredentials so that @ip-login
    matches the same IPs that PAS IP auth matches for content requests.
    This means the same IP config that grants content access will also
    grant a JWT token, regardless of whether the request comes through
    the Volto proxy or directly via nginx.
    """
    ips = []
    for ip in request.get("HTTP_X_FORWARDED_FOR", "").split(","):
        ip = ip.strip()
        if ip:
            ips.append(ip)
    client_addr = request.getClientAddr()
    if client_addr and client_addr not in ips:
        ips.append(client_addr)
    return ips


def _get_ip_auth_plugin(acl_users):
    """
    Walk PAS and return the first AuthIPPlugin instance found.
    Returns None if no plugin is configured.
    """
    for plugin_id in acl_users.objectIds():
        plugin = acl_users[plugin_id]
        if getattr(plugin, "meta_type", None) == "AuthIPPlugin":
            return plugin
    return None


def _match_ip(client_ip, plugin):
    """
    Check a single client IP against all networks configured in the plugin.
    Returns the matched userid string, or None if no match.

    Each line in plugin.remote_ip_addresses is expected to be:
        <network_or_ip>:<userid>
    e.g.
        10.0.0.0/24:john
        192.168.1.50:jane
    """
    for line in plugin.remote_ip_addresses.split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            network_str, userid = line.split(":", 1)
            network_str = network_str.strip()
            userid = userid.strip()
        except ValueError:
            logger.warning("AuthIPPlugin: bad config line: %r", line)
            continue

        try:
            client_addr = ipaddress.ip_address(client_ip)
            # strict=False allows host bits to be set in the network address,
            # which is a common configuration mistake. Silently corrects it.
            network = ipaddress.ip_network(network_str, strict=False)
            if client_addr in network:
                return userid
        except ValueError as e:
            logger.warning("AuthIPPlugin: could not parse network %r: %s", network_str, e)
            continue

    return None


def _issue_jwt_token(acl_users, userid):
    """
    Ask the jwt_auth PAS plugin to produce a token for the given userid.
    Raises KeyError if no JWT plugin is installed (plone.restapi requirement).
    """
    try:
        jwt_plugin = acl_users["jwt_auth"]
    except KeyError:
        raise RuntimeError(
            "No jwt_auth plugin found in acl_users. "
            "Ensure plone.restapi is properly installed."
        )
    token = jwt_plugin.create_token(userid)
    # create_token may return bytes in Python 3 — decode to str so the
    # response serializes cleanly to JSON. Without this the JSON serializer
    # throws a TypeError and Zope returns a 500 HTML error page instead.
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


class IPLoginService(Service):
    """
    GET /++api++/@ip-login

    Checks the client IP against the AuthIPPlugin configuration.
    If the IP matches a configured network, issues a JWT token for the
    associated user and returns it in the same format as @login.

    Returns 200 with token on success, 401 if no match.

    Security notes:
    - Only issues tokens for users that actually exist in Plone.
    - All logic is server-side; the client supplies nothing except its IP.
    - Checks all IPs in the X-Forwarded-For chain plus REMOTE_ADDR,
      mirroring AuthIPPlugin.extractCredentials exactly.
    """

    def reply(self):
        # Disable CSRF protection — this is a GET endpoint with no side
        # effects on Plone content, but plone.protect can still complain
        # when we write the auth cookie, so we opt out explicitly.
        alsoProvides(self.request, IDisableCSRFProtection)

        acl_users = api.portal.get_tool("acl_users")

        # --- 1. Find the plugin ---
        plugin = _get_ip_auth_plugin(acl_users)
        if plugin is None:
            logger.error("@ip-login called but no AuthIPPlugin is configured in PAS.")
            raise Unauthorized("IP authentication is not configured.")

        # --- 2. Resolve all candidate client IPs ---
        client_ips = _get_all_client_ips(self.request)
        if not client_ips:
            logger.warning("@ip-login: could not determine client IP.")
            raise Unauthorized("Could not determine client IP address.")

        logger.debug("@ip-login: checking IPs %s", client_ips)

        # --- 3. Match against configured networks ---
        # Check each IP in the chain — same order as AuthIPPlugin.extractCredentials
        userid = None
        matched_ip = None
        for ip in client_ips:
            userid = _match_ip(ip, plugin)
            if userid:
                matched_ip = ip
                break

        if userid is None:
            self.request.response.setStatus(401)
            return {"error": "No IP match"}

        # --- 4. Verify the user actually exists in Plone ---
        user = acl_users.getUserById(userid)
        if user is None:
            logger.warning(
                "@ip-login: IP %s matched userid %r but that user does not exist.",
                matched_ip,
                userid,
            )
            raise Unauthorized("Matched user does not exist.")

        # --- 5. Issue JWT token ---
        try:
            token = _issue_jwt_token(acl_users, userid)
        except RuntimeError as e:
            logger.error("@ip-login: token issuance failed: %s", e)
            self.request.response.setStatus(500)
            return {"error": str(e)}

        logger.info(
            "@ip-login: issued token for user %r from IP %s", userid, matched_ip
        )

        self.request.response.setStatus(200)
        return {
            "token": token,
        }