from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, IExtractionPlugin

from Products.PageTemplates.PageTemplateFile import PageTemplateFile
import functools
import ipaddress
import logging

logger = logging.getLogger(__name__)

manage_addIPAuthPluginForm = PageTemplateFile(
            'www/ipAuthAdd', globals(), __name__='manage_addIPAuthPluginForm' )

def manage_addIPAuthPlugin(dispatcher, id, title=None, REQUEST=None):
    """ Add a AuthIPPlugin to a Pluggable Auth Service. """

    obj = AuthIPPlugin(id, title)
    dispatcher._setObject(obj.getId(), obj)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace?manage_tabs_message=IPAuthPlugin+added.' % dispatcher.absolute_url())


@functools.lru_cache(maxsize=16)
def parse_ip_lines(text):
    """The <network>:<login id> lines, as (network, login id) pairs.

    A network written from one of its addresses rather than its first
    (41.164.41.97/29 for 41.164.41.96/29) is read as that network, as
    @ip-login reads it. Lines that can't be read are left out, with a
    warning in the log; the result is cached, so that's once per change
    to the list rather than on every request.
    """
    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        network, sep, loginid = line.partition(':')
        network, loginid = network.strip(), loginid.strip()
        if not sep or not loginid:
            logger.warning('AuthIPPlugin: bad config line: %r', line)
            continue
        try:
            networks.append(
                (ipaddress.ip_network(network, strict=False), loginid))
        except ValueError as err:
            logger.warning(
                'AuthIPPlugin: could not parse network %r: %s', network, err)
    return tuple(networks)


def _ip_address(value):
    """The address in value, or None when there isn't one."""
    try:
        return ipaddress.ip_address((value or '').strip())
    except ValueError:
        return None


class AuthIPPlugin(BasePlugin):
    """ PAS plugin for using IP Address to log in. """

    meta_type = 'AuthIPPlugin'

    security = ClassSecurityInfo()

    _properties = (
        {'id':'remote_ip_addresses', 'type':'text', 'mode':'w','label':'A list of <IP Addresses:login id>'},)

    remote_ip_addresses=''

    def __init__(self, id, title=None):
        self._id = self.id = id
        self.title = title

    #
    #   IAuthenticationPlugin implementation (PluggableAuthService interface)
    #
    security.declarePrivate('authenticateCredentials')
    def authenticateCredentials(self, credentials):
        """ See IAuthenticationPlugin.

        o We expect the credentials to be those returned by
          ILoginPasswordHostExtractionPlugin.
        """
        login = credentials.get('loginid')
        return login, login

    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        """Extract credentials for ip address"""
        networks = parse_ip_lines(self.remote_ip_addresses or '')
        if not networks:
            return {}

        candidates = [request.getClientAddr()]
        for ip in request.get('HTTP_X_FORWARDED_FOR', '').split(','):
            candidates.append(ip)
        addresses = []
        for candidate in candidates:
            address = _ip_address(candidate)
            if address is not None:
                addresses.append((candidate.strip(), address))

        # Each line in turn, as before: the first line that matches the
        # client's address or one of the forwarded ones wins.
        for network, loginid in networks:
            for remote_address, address in addresses:
                if address in network:
                    return {'loginid': loginid,
                            'remote_address': remote_address}
        return {}

classImplements(AuthIPPlugin, IAuthenticationPlugin, IExtractionPlugin)

InitializeClass(AuthIPPlugin)
