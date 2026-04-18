certbot-dns-infomaniak
======================

Infomaniak_ DNS Authenticator plugin for certbot_

This plugin uses the Infomaniak public API to complete ``dns-01`` challenges.
After creating the challenge record, it polls the API's ``/check`` endpoint
to confirm propagation on the authoritative name servers rather than sleeping
for a fixed duration.

.. _Infomaniak: https://www.infomaniak.com/
.. _certbot: https://certbot.eff.org/

Issue a token
-------------

At your Infomaniak manager dashboard_, go to the API section and generate a
token with the following scopes:

- ``domain:read``
- ``dns:read``
- ``dns:write``

.. _dashboard: https://manager.infomaniak.com/v3/infomaniak-api

Installation
------------

.. code-block:: bash

    pip install certbot-dns-infomaniak

Usage
-----

Via environment variable
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   export INFOMANIAK_API_TOKEN=xxx
   certbot certonly \
     --authenticator dns-infomaniak \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'death.star'

If certbot requires elevated rights, the following command must be used instead:

.. code-block:: bash

   export INFOMANIAK_API_TOKEN=xxx
   sudo --preserve-env=INFOMANIAK_API_TOKEN certbot certonly \
     --authenticator dns-infomaniak \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'death.star'

Via INI file
^^^^^^^^^^^^

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).

===================================  ==========================================
``--authenticator dns-infomaniak``   select the authenticator plugin (Required)
``--dns-infomaniak-credentials``     Infomaniak Token credentials
                                     INI file. (Required)
===================================  ==========================================

An example ``credentials.ini`` file:

.. code-block:: ini

   dns_infomaniak_token = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


To start using DNS authentication for Infomaniak, pass the following arguments on certbot's command line:


.. code-block:: bash

  certbot certonly \
    --authenticator dns-infomaniak \
    --dns-infomaniak-credentials <path to file> \
    --server https://acme-v02.api.letsencrypt.org/directory \
    --agree-tos \
    --rsa-key-size 4096 \
    -d 'death.star'

Automatic renewal
-----------------

By default, certbot installs a service that periodically renews its
certificates automatically. In order to do this, the command must know the API
key, otherwise it will fail silently.

In order to enable automatic renewal for your wildcard certificates, you will
need to edit ``/lib/systemd/system/certbot.service``. In there, add the
following line in ``Service``, with <YOUR_API_TOKEN> replaced with your actual
token:

.. code-block:: bash

   Environment="INFOMANIAK_API_TOKEN=<YOUR_API_TOKEN>"

Migrating from 0.2.x
--------------------

Version ``1.0.0`` moves the plugin from Infomaniak API v1 to API v2. Users
upgrading from ``0.2.x`` must:

1. **Regenerate the API token.** v2 requires the scopes ``domain:read``,
   ``dns:read`` and ``dns:write``. The legacy "Domain" scope issued for v1
   will not work.
2. **Review ``propagation_seconds``.** The default was lowered from ``120``
   to ``10`` because the plugin now polls the API's ``/check`` endpoint to
   confirm propagation. The configured ``propagation_seconds`` only acts as
   a final safety buffer after ``/check`` confirms (or times out).

No configuration file change is required beyond the token itself.

Known issues
------------

Fast Anycast
^^^^^^^^^^^^

If the domain has Infomaniak's **Fast Anycast** option enabled, records
created via the API are accepted and stored but are never published on the
authoritative name servers. This makes the ``dns-01`` challenge fail because
Let's Encrypt cannot resolve the TXT record. Disable Fast Anycast on the
domain before using this plugin. See upstream issue `#47
<https://github.com/Infomaniak/certbot-dns-infomaniak/issues/47>`_.

Local Development
-----------------

Usage of `uv`_ to manage virtual environments and dependencies as defined in ``pyproject.toml`` is strongly recommended.

.. _uv: https://docs.astral.sh/uv/

Simply run ``uv sync`` to automatically create or update the ``.venv``. Usual activation is not required as all tools can simply be run within the project's environment through ``uv run...``, (eg. ``uv run ruff check``, ``uv run pytest``), eliminating the need for manual requirements management.

Acknowledgments
---------------

Based on certbot-dns-ispconfig plugin at https://github.com/m42e/certbot-dns-ispconfig/
