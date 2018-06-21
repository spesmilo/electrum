Electron Cash - Plugins
=======================

The plugin system of Electron Cash is designed to allow the development
of new features without increasing the core code of Electron Cash.

Electron Cash is written in pure python. if you want to add a feature
that requires non-python libraries, then it must be submitted as a
plugin. If the feature you want to add requires communication with
a remote server (not an Electron Cash server), then it should be a
plugin as well. If the feature you want to add introduces new
dependencies in the code, then it should probably be a plugin.

There are two types of plugins supported by Electron Cash.  The first is the
internal plugin, currently offered under "Optional Features" in the Tools
menu of the QT client.  The second is the external plugin, which the user
has to manually install, currently managed under "Installed Plugins" in the
Tools menu of the QT client.

At this time, there is no documentation for the plugin API.  What API there
is, mostly consists of some limited hooks which provide notification on events
and a base class which provides the basic plugin integration.

**WARNING:** The plugin API will be upgraded at some point.  Plugins will
be required to specify their release plugin API version, and those that
predate it will be assumed to be version 0.   This will be used to first
deprecate, and then over time, remove the existing API as plugin
developers transition to any replacement API.  Plenty of time and warning
will be given before any removal, allowing plugin developers to upgrade.
Given the extremely limited state of the Electrum plugin API we inherited,
this may even reduce maintenance requirements
as internals a plugin developer makes use of can easily get changed
in the course of normal development.

Risks and Dangers
=================

Plugins, like Electron Cash, are written in pure Python, in the form of
PythonPackages_.  This means they can access almost all of Electron
Cash's state, and change any behaviour, perhaps even in dishonest ways
you might not even notice at first.  They might even use Python's file
system access, or other similar functionality, to damage whatever else
they can access.

If you plan to install plugins, you should ensure that they are fully vetted
by someone trustworthy, and do so at your own risk, only installing them from
official locations.

If you plan to develop a plugin, it is in your best interest to get it
reviewed by someone a plugin user knows and trusts, before releasing it,
in order to have provable safety for potential users as a feature.

.. _PythonPackages: https://docs.python.org/3/tutorial/modules.html#packages

Types of Plugin
===============

Optional features (internal plugins) are included with Electron Cash, and are
available to all users of Electron Cash to enable and disable as they wish.
They cannot be uninstalled, and no installation functionality is provided
either.

User installable plugins (external plugins) are not included with Electron
Cash.  The user must use the Plugin Manager to install these, through the
user interface.  In the QT UI, this is accessed through the Tools menu.  The
process of installation includes both warnings and required user confirmations
that they accept the risks installing them incurs.

Internal Plugin Rules
=====================

- We expect plugin developers to maintain their plugin code. However,
  once a plugin is merged in Electron Cash, we will have to maintain it
  too, because changes in the Electron Cash code often require updates in
  the plugin code. Therefore, plugins have to be easy to maintain. If
  we believe that a plugin will create too much maintenance work in
  the future, it will be rejected.

- Plugins should be compatible with Electron Cash's conventions. If your
  plugin does not fit with Electron Cash's architecture, or if we believe
  that it will create too much maintenance work, it will not be
  accepted. In particular, do not duplicate existing Electron Cash code in
  your plugin.

- We may decide to remove a plugin after it has been merged in
  Electron Cash. For this reason, a plugin must be easily removable,
  without putting at risk the user's bitcoins. If we feel that a
  plugin cannot be removed without threatening users who rely on it,
  we will not merge it.

External Plugins
================

At this time, external plugins must be developed in the same way as an
internal plugin.  It might be that this can be done by placing a symbolic link
to your plugin's Python package directory, in the ``plugins`` directory within the
clone of the Electron Cash source you are developing within.

Please be sure that you test your plugin with the same recommended version of
Python for the version of Electron Cash you intend to specify in your
plugin's minimum Electron Cash version.  Not doing so, will cause you pain
and potential users to avoid your plugin.

Packaging The Hard Way
----------------------

Once your plugin is ready for use by other users, you can package it for them
so they can take advantage of the easy methods of plugin installation available
in the QT user interface (drag and drop onto the plugin manager, or click
``Add Plugin`` and select the plugin zip archive).

An external plugin must be constructed in the form of a zip archive that is
acceptable to the Python ``zipimport`` module.  Within this archive must be two
things:

- The ``manifest.json`` file which provides plugin metadata.
- The Python package directory that contains your plugin code.

It is recommended that your Python package directory contain precompiled
Python bytecode files.  Python includes
the `compileall module <https://docs.python.org/3/library/compileall.html#command-line-use>`
within it's standard library which can do this from the command line.  This
is because ``zipimport`` does not support writing these back into the zip archive
which encapulates your packaged plugin.

The ``manifest.json`` file has required fields:

- ``display_name``: This is the name of your plugin.
- ``version``: This is the version of your plugin.  Only numeric versions of the
  form ``<integer>.<integer>`` (e.g. ``1.0``) or ``<integer>.<integer>.<integer>``
  (e.g. ``1.0.1``) are supported.
- ``project_url``: This is the official URL of your project.
- ``description``: A longer form description of how your plugin upgrades
  Electron Cash.
- ``minimum_ec_version``: This is the earliest version of Electron Cash
  which your plugin is known to work with.  This will not be ``3.2`` or lower
  as the external plugin functionality only arrived after that version.
- ``package_name``: This is the name of the Python package directory at the
  top level of the zip archive, which contains your plugin code.  It is
  necessary to formally specify this, to spare Electron Cash confusion in
  the case of advanced plugin packages which contain multiple Python
  packages, or even looking around to distinguish between the one Python
  package and other data directories.
- ``available_for``: This is a list of keywords which map to supported
  Electron Cash plugin interfaces.  Valid values to include are ``qt``,
  ``kivy`` and ``cmdline``.

If you do not include these fields in your manifest file, then the user will
see an error message when they try and install it.

Example ``manifest.json``
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: json

    {
        "display_name": "Scheduled Payments",
        "version": "1.0",
        "project_url": "https://github.com/rt121212121/electron_cash_scheduled_payments_plugin",
        "description": "This allows a user to specify recurring payments to a number of recipients.",
        "minimum_ec_version": "3.2",
        "package_name": "scheduled_payments",
        "available_for": [
            "qt"
        ]
    }

The Easy Way
------------

In the ``contrib`` directory of the Electron Cash source tree, you can find a script
named ``package_plugin.py``.  Execute this script with the command-line
``py -3 package_plugin.py``.  You must have ``PyQT5`` installed, which you will have
if you are developing against a clone of the GIT repository.

A window will be displayed with fields for all the required manifest fields, and
when they have valid values, will allow you to generate the package zip archive
automatically.  This will create a zip archive with sha256 checksum which any
user can then drag into their Electron Cash wallet's plugin manager, to
almost immediately install and run (sure they have to check a barrage of warnings
about the damage you could do to them).

Advanced Python Packaging
-------------------------

With a bit of thought a user can bundle additional supporting Python packages,
or even binary data like icons, into their plugin archive.

It is not possible to import Python extension modules (.pyd, .dll, .so, etc)
from within a ``ziparchive`` "mounted zip archive".

If you need to extract data from the archive, to make use of it, please contact
the Electron Cash developers to work out a standard way to do so, so that if
a user uninstalls your plugin, the extracted data can also be removed.  For this
initial external plugin feature release, this level of functionality is not
officially supported or recommended.
