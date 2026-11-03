"""
Tests for AuthIPPlugin's own check, which runs on every request.

Run with:
    ./bin/test -s Products.PASIPAuth
"""
import unittest
from unittest.mock import MagicMock

from Products.PASIPAuth.AuthIPPlugin import AuthIPPlugin, parse_ip_lines


def _plugin(lines):
    plugin = AuthIPPlugin('authipplugin')
    plugin.remote_ip_addresses = '\n'.join(lines)
    return plugin


def _request(remote_addr='10.0.0.1', xff=None):
    request = MagicMock()
    request.getClientAddr.return_value = remote_addr
    request.get = lambda key, default='': (
        xff if key == 'HTTP_X_FORWARDED_FOR' and xff is not None else default
    )
    return request


class TestExtractCredentials(unittest.TestCase):

    def setUp(self):
        parse_ip_lines.cache_clear()

    def test_matches_the_client_address(self):
        plugin = _plugin(['10.0.0.0/24:alice'])
        self.assertEqual(
            plugin.extractCredentials(_request('10.0.0.7')),
            {'loginid': 'alice', 'remote_address': '10.0.0.7'},
        )

    def test_no_match(self):
        plugin = _plugin(['10.0.0.0/24:alice'])
        self.assertEqual(plugin.extractCredentials(_request('10.0.1.7')), {})

    def test_reads_a_range_written_from_one_of_its_addresses(self):
        # 41.164.41.97/29 is 41.164.41.96/29, as @ip-login reads it
        plugin = _plugin(['41.164.41.97/29:KPMG'])
        self.assertEqual(
            plugin.extractCredentials(_request('41.164.41.100'))['loginid'],
            'KPMG',
        )
        self.assertEqual(
            plugin.extractCredentials(_request('41.164.41.104')), {})

    def test_matches_a_forwarded_address(self):
        plugin = _plugin(['10.0.0.0/24:alice'])
        self.assertEqual(
            plugin.extractCredentials(
                _request('127.0.0.1', xff='192.168.1.1, 10.0.0.9')),
            {'loginid': 'alice', 'remote_address': '10.0.0.9'},
        )

    def test_the_first_matching_line_wins(self):
        plugin = _plugin(['10.0.0.0/24:alice', '10.0.0.7:bob'])
        self.assertEqual(
            plugin.extractCredentials(_request('10.0.0.7'))['loginid'],
            'alice',
        )

    def test_spaces_and_windows_line_ends(self):
        plugin = _plugin([' 10.0.0.0/24 : alice \r', ''])
        self.assertEqual(
            plugin.extractCredentials(_request('10.0.0.7'))['loginid'],
            'alice',
        )

    def test_skips_bad_lines_and_logs_them_once(self):
        plugin = _plugin(['nonsense', 'not.an.ip:bob', '10.0.0.0/24:alice'])
        with self.assertLogs('Products.PASIPAuth.AuthIPPlugin', 'WARNING') as logs:
            for _ in range(3):
                self.assertEqual(
                    plugin.extractCredentials(_request('10.0.0.7'))['loginid'],
                    'alice',
                )
        self.assertEqual(len(logs.output), 2)

    def test_an_unreadable_client_address_still_checks_forwarded_ones(self):
        plugin = _plugin(['10.0.0.0/24:alice'])
        self.assertEqual(
            plugin.extractCredentials(_request('', xff='10.0.0.9'))['loginid'],
            'alice',
        )
        self.assertEqual(plugin.extractCredentials(_request('::1')), {})

    def test_empty_list(self):
        self.assertEqual(_plugin([]).extractCredentials(_request()), {})
