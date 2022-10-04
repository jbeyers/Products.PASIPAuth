"""
"""

from AccessControl.Permissions import add_user_folders
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from . import AuthIPPlugin

_initialized = False

def initialize(context):
    """Initialize IPAuthPlugin"""
    # This is sometimes called twice, protect against that.
    global _initialized
    if not _initialized:
        registerMultiPlugin(AuthIPPlugin.AuthIPPlugin.meta_type)

        context.registerClass( AuthIPPlugin.AuthIPPlugin,
                                permission=add_user_folders,
                                constructors=(AuthIPPlugin.manage_addIPAuthPluginForm,AuthIPPlugin.manage_addIPAuthPlugin),
                                icon='www/PluggableAuthService.png',
                                visibility=None,
                            )
        _initialized = True
