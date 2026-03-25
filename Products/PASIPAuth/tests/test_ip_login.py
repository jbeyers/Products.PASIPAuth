"""
Tests for the @ip-login REST API endpoint.

Run with:
    ./bin/test -s Products.PASIPAuth
"""
import unittest
from unittest.mock import MagicMock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Helpers to build fake objects
# ---------------------------------------------------------------------------

def _make_plugin(lines):
    """Return a mock AuthIPPlugin with the given config lines."""
    plugin = MagicMock()
    plugin.meta_type = "AuthIPPlugin"
    plugin.remote_ip_addresses = "\n".join(lines)
    return plugin


def _make_request(remote_addr="10.0.0.1", xff=None):
    """Return a mock Zope request."""
    request = MagicMock()
    request.getClientAddr.return_value = remote_addr
    request.get = lambda key, default="": (
        xff if key == "HTTP_X_FORWARDED_FOR" and xff is not None else default
    )
    request.environ = {"REMOTE_ADDR": remote_addr}
    request.response = MagicMock()
    return request


# ---------------------------------------------------------------------------
# Tests for _get_client_ip
# ---------------------------------------------------------------------------

class TestGetClientIp(unittest.TestCase):

    def _call(self, request, trust_xff=True):
        from ip_login import _get_client_ip
        return _get_client_ip(request, trust_xff=trust_xff)

    def test_returns_remote_addr_when_no_xff(self):
        request = _make_request(remote_addr="1.2.3.4")
        self.assertEqual(self._call(request), "1.2.3.4")

    def test_returns_first_xff_when_trust_xff_true(self):
        request = _make_request(xff="5.6.7.8, 9.10.11.12")
        self.assertEqual(self._call(request, trust_xff=True), "5.6.7.8")

    def test_ignores_xff_when_trust_xff_false(self):
        request = _make_request(remote_addr="1.2.3.4", xff="5.6.7.8")
        self.assertEqual(self._call(request, trust_xff=False), "1.2.3.4")

    def test_handles_empty_xff(self):
        request = _make_request(remote_addr="1.2.3.4", xff="   ")
        self.assertEqual(self._call(request, trust_xff=True), "1.2.3.4")


# ---------------------------------------------------------------------------
# Tests for _match_ip
# ---------------------------------------------------------------------------

class TestMatchIp(unittest.TestCase):

    def _call(self, client_ip, lines):
        from ip_login import _match_ip
        plugin = _make_plugin(lines)
        return _match_ip(client_ip, plugin)

    def test_exact_match(self):
        result = self._call("192.168.1.50", ["192.168.1.50:jane"])
        self.assertEqual(result, "jane")

    def test_cidr_match(self):
        result = self._call("10.0.0.7", ["10.0.0.0/29:john"])
        self.assertEqual(result, "john")

    def test_cidr_no_match(self):
        result = self._call("10.0.0.8", ["10.0.0.0/29:john"])
        self.assertIsNone(result)

    def test_blank_lines_ignored(self):
        result = self._call("10.0.0.1", [" ", "", "10.0.0.0/24:admin"])
        self.assertEqual(result, "admin")

    def test_malformed_line_skipped(self):
        # No colon — should be skipped without crashing
        result = self._call("10.0.0.1", ["this is garbage", "10.0.0.0/24:admin"])
        self.assertEqual(result, "admin")

    def test_first_match_wins(self):
        lines = ["10.0.0.0/24:first", "10.0.0.0/16:second"]
        result = self._call("10.0.1.5", lines)
        # 10.0.1.5 is NOT in /24 but IS in /16
        self.assertEqual(result, "second")

    def test_host_bits_set_in_network_tolerated(self):
        # 10.0.0.1/24 has host bits set — strict=False should handle it
        result = self._call("10.0.0.5", ["10.0.0.1/24:admin"])
        self.assertEqual(result, "admin")

    def test_no_match_returns_none(self):
        result = self._call("172.16.0.1", ["10.0.0.0/8:john"])
        self.assertIsNone(result)

    def test_ipv6_match(self):
        result = self._call("::1", ["::1:localuser"])
        self.assertEqual(result, "localuser")


# ---------------------------------------------------------------------------
# Tests for the full IPLoginService.reply()
# ---------------------------------------------------------------------------

class TestIPLoginService(unittest.TestCase):

    def _make_service(self, request):
        from ip_login import IPLoginService
        service = IPLoginService(None, request)
        service.trust_xff = True
        return service

    def _make_acl_users(self, plugin=None, user_exists=True):
        acl_users = MagicMock()
        # objectIds() returns the list of plugin ids
        if plugin:
            acl_users.objectIds.return_value = ["ip_auth"]
            acl_users.__getitem__ = lambda self_, key: (
                plugin if key == "ip_auth" else MagicMock()
            )
        else:
            acl_users.objectIds.return_value = []

        user = MagicMock() if user_exists else None
        acl_users.getUserById.return_value = user
        return acl_users

    @patch("ip_login.api")
    def test_no_plugin_raises_unauthorized(self, mock_api):
        request = _make_request()
        acl_users = self._make_acl_users(plugin=None)
        mock_api.portal.get_tool.return_value = acl_users

        from zExceptions import Unauthorized
        service = self._make_service(request)
        with self.assertRaises(Unauthorized):
            service.reply()

    @patch("ip_login.api")
    def test_no_ip_match_returns_401(self, mock_api):
        request = _make_request(remote_addr="8.8.8.8")
        plugin = _make_plugin(["10.0.0.0/8:admin"])
        acl_users = self._make_acl_users(plugin=plugin)
        mock_api.portal.get_tool.return_value = acl_users

        service = self._make_service(request)
        result = service.reply()

        self.assertEqual(result["error"], "No IP match")
        request.response.setStatus.assert_called_with(401)

    @patch("ip_login.api")
    def test_matched_user_not_in_plone_raises_unauthorized(self, mock_api):
        request = _make_request(remote_addr="10.0.0.1")
        plugin = _make_plugin(["10.0.0.0/8:ghost_user"])
        acl_users = self._make_acl_users(plugin=plugin, user_exists=False)
        mock_api.portal.get_tool.return_value = acl_users

        from zExceptions import Unauthorized
        service = self._make_service(request)
        with self.assertRaises(Unauthorized):
            service.reply()

    @patch("ip_login.api")
    def test_successful_login_returns_token(self, mock_api):
        request = _make_request(remote_addr="10.0.0.1")
        plugin = _make_plugin(["10.0.0.0/8:john"])
        acl_users = self._make_acl_users(plugin=plugin, user_exists=True)

        # jwt_auth plugin
        jwt_plugin = MagicMock()
        jwt_plugin.create_token.return_value = "fake-jwt-token"

        def getitem(key):
            if key == "ip_auth":
                return plugin
            if key == "jwt_auth":
                return jwt_plugin
            raise KeyError(key)

        acl_users.__getitem__ = getitem
        mock_api.portal.get_tool.return_value = acl_users

        service = self._make_service(request)
        result = service.reply()

        self.assertEqual(result["token"], "fake-jwt-token")
        jwt_plugin.create_token.assert_called_once_with("john")
        request.response.setStatus.assert_called_with(200)

    @patch("ip_login.api")
    def test_spoofed_xff_ignored_when_trust_xff_false(self, mock_api):
        # Client sends a spoofed XFF claiming to be 10.0.0.1
        # but the real REMOTE_ADDR is 8.8.8.8
        request = _make_request(remote_addr="8.8.8.8", xff="10.0.0.1")
        plugin = _make_plugin(["10.0.0.0/8:admin"])
        acl_users = self._make_acl_users(plugin=plugin)
        mock_api.portal.get_tool.return_value = acl_users

        service = self._make_service(request)
        service.trust_xff = False  # ← critical: don't trust XFF
        result = service.reply()

        self.assertEqual(result["error"], "No IP match")


if __name__ == "__main__":
    unittest.main()
