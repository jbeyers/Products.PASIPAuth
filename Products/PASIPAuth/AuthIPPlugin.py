from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, IExtractionPlugin

from Products.PageTemplates.PageTemplateFile import PageTemplateFile
import ipaddress

manage_addIPAuthPluginForm = PageTemplateFile(
            'www/ipAuthAdd', globals(), __name__='manage_addIPAuthPluginForm' )

def manage_addIPAuthPlugin(dispatcher, id, title=None, REQUEST=None):
    """ Add a AuthIPPlugin to a Pluggable Auth Service. """

    obj = AuthIPPlugin(id, title)
    dispatcher._setObject(obj.getId(), obj)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace?manage_tabs_message=IPAuthPlugin+added.' % dispatcher.absolute_url())

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

        # print('Inside extractCredentials')
        clean_rem_addresses=[]
        for s in self.remote_ip_addresses.split("\n"):
            s.strip(" ")
            if s == '':
                continue
            s = s.split(":")
            clean_rem_addresses.append(tuple(s))
        # print("Available addresses: {}".format(clean_rem_addresses))
        
        forwarded_ips=[]
        for ip_address in request.get('HTTP_X_FORWARDED_FOR', '').split(','):
            ip_address = ip_address.strip()
            if ip_address:
                forwarded_ips.append(ip_address)
        # print("Forwarded IPs: {}".format(forwarded_ips))

        clientAddr = request.getClientAddr()
        # print("Client Address: {}".format(clientAddr))
        for tup in clean_rem_addresses:
            try:
                # print("Look for {}".format(tup))
                if len(tup) <= 1:
                    print('Error in AuthIPPlugin: Invalid address: {}'.format(tup))
                    continue
                if ipaddress.IPv4Address(clientAddr) in ipaddress.IPv4Network(tup[0]):
                    # print('clientAddr in cidr')
                    return {'loginid':tup[1], 'remote_address':clientAddr,}
                # print('Not in CIDR')
                for ip_address in forwarded_ips:
                    # print("Loop forwarded_ips: {}".format(ip_address))
                    if ipaddress.IPv4Address(ip_address) in ipaddress.IPv4Network(tup[0]):
                        # print('CIDR in forwarded')
                        return {'loginid':tup[1], 'remote_address':ip_address,}
                    # print('CIDR NOT in forwarded')
            except Exception as err:
                print('Error in AuthIPPlugin: {}'.format(err))
        # print('Exit extractCredentials with no matches')
        return {}

classImplements(AuthIPPlugin, IAuthenticationPlugin, IExtractionPlugin)

InitializeClass(AuthIPPlugin)
