"""
"""

from AccessControl.Permissions import add_user_folders
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from AuthIPPlugin import AuthIPPlugin, manage_addIPAuthPlugin, manage_addIPAuthPluginForm

_initialized = False

def initialize(context):
    """Initialize IPAuthPlugin"""
    # This is sometimes called twice, protect against that.
    global _initialized
    if not _initialized:
        registerMultiPlugin(AuthIPPlugin.meta_type)

        context.registerClass( AuthIPPlugin,
                                permission=add_user_folders,
                                constructors=(manage_addIPAuthPluginForm,manage_addIPAuthPlugin),
                                icon='www/PluggableAuthService.png',
                                visibility=None,
                            )
        _initialized = True
