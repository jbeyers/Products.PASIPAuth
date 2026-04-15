import ipaddress
import logging

from plone import api
from plone.protect.interfaces import IDisableCSRFProtection
from plone.restapi.services import Service
from zExceptions import Unauthorized
from zope.interface import alsoProvides

logger = logging.getLogger(__name__)


def _get_client_ip(request, trust_xff=True):
   """
   Determine the real client IP address.

   If trust_xff is True, the leftmost IP in X-Forwarded-For is used.
   This is only safe when you control the proxy in front of Plone and
   know it sets XFF correctly. Set trust_xff=False if Plone is exposed
   directly to the internet.
   """
   if trust_xff:
      xff = request.get("HTTP_X_FORWARDED_FOR", "")
      forwarded_ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
      if forwarded_ips:
         return forwarded_ips[0]

   return request.getClientAddr()


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
   Check the client IP against all networks configured in the plugin.
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
         logger.warning(
            "AuthIPPlugin: could not parse network %r: %s", network_str, e
         )
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
   # create_token may return bytes in Python 3 - decode to str so the
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
   - XFF trust is configurable via the trust_xff property on this view
     (default True, safe only behind a trusted reverse proxy).
   """

   # Set to False if Plone is exposed directly (no trusted proxy in front).
   trust_xff = True

   def reply(self):
      # Disable CSRF protection - this is a GET endpoint with no side
      # effects on Plone content, but plone.protect can still complain
      # when we write the auth cookie, so we opt out explicitly.
      alsoProvides(self.request, IDisableCSRFProtection)

      acl_users = api.portal.get_tool("acl_users")

      # --- 1. Find the plugin ---
      plugin = _get_ip_auth_plugin(acl_users)
      if plugin is None:
         logger.error("@ip-login called but no AuthIPPlugin is configured in PAS.")
         raise Unauthorized("IP authentication is not configured.")

      # --- 2. Resolve client IP ---
      client_ip = _get_client_ip(self.request, trust_xff=self.trust_xff)
      if not client_ip:
         logger.warning("@ip-login: could not determine client IP.")
         raise Unauthorized("Could not determine client IP address.")

      logger.debug("@ip-login: checking IP %s", client_ip)

      # --- 3. Match against configured networks ---
      userid = _match_ip(client_ip, plugin)
      if userid is None:
         logger.debug("@ip-login: no match for IP %s", client_ip)
         self.request.response.setStatus(401)
         return {"error": "No IP match"}

      # --- 4. Verify the user actually exists in Plone ---
      user = api.user.get(userid=userid)
      if user is None:
         logger.warning(
            "@ip-login: IP %s matched userid %r but that user does not exist.",
            client_ip,
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

      logger.info("@ip-login: issued token for user %r from IP %s", userid, client_ip)

      self.request.response.setStatus(200)
      return {
         "token": token,
      }