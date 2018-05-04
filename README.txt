Installation:
------------

Copy PASIPAuth into your Products directory. Restart Zope.

In the ZMI, go to acl_users and add an AuthIPPlugin.  Give it a name such as
"authipplugin".  Go back to acl_users and click on authipplugin.  Click on the
properties tab and add a list of client ips separated from the login id of the user, eg:
192.168.1.157:tom
192.168.1.158:dick
with no spaces and no leading http.

Go to acl_users and click on "plugins".  Click on "Authentication Plugins" and
add the authipplugin to the Active Plugins list.

Go to acl_users and click on "plugins". Click on "Extraction Plugins" and add
authipplugin to the Active Plugins list.

The plugin can now be used to log in automatically from an ip address.

Tested:
------

Tested with zope 2.9.8-final and Plone 2.5.3-final.
