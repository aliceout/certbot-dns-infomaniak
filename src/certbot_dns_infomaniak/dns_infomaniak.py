# SPDX-FileCopyrightText: 2021-2022 Rene Luria <rene.luria@infomaniak.com>
# SPDX-FileCopyrightText: 2021-2022 Yannik Roth <info@fuechslein.ch>
# SPDX-FileCopyrightText: 2021      Romain Autran <romain.autran@2itea.ch>
# SPDX-License-Identifier: Apache-2.0
"""DNS Authenticator for Infomaniak."""
import json
import logging
import time

import idna
import requests

from certbot import errors
from certbot.plugins import dns_common
try:
    import certbot.compat.os as os
except ImportError:
    import os

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Infomaniak.

    Completes ``dns-01`` challenges using the Infomaniak public API.
    Propagation is confirmed by polling the API's own ``/check`` endpoint
    instead of sleeping for a fixed duration.
    """

    description = "Automates dns-01 challenges using Infomaniak API"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = ""
        self.credentials = None
        self._record_ids = {}

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=10
        )
        add("credentials", help="Infomaniak credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return self.description

    def _setup_credentials(self):
        token = os.getenv("INFOMANIAK_API_TOKEN")
        if token is None:
            self.credentials = self._configure_credentials(
                "credentials",
                "Infomaniak credentials INI file",
                {
                    "token": "Infomaniak API token.",
                },
            )
            if not self.credentials:
                raise errors.PluginError("INFOMANIAK API Token not defined")
            self.token = self.credentials.conf("token")
        else:
            self.token = token

    def _perform(self, domain, validation_name, validation):
        decoded_domain = idna.decode(domain)
        try:
            record_id = self._api_client().add_txt_record(
                decoded_domain, validation_name, validation,
            )
        except ValueError as err:
            raise errors.PluginError("Cannot add txt record: {err}".format(err=err))
        if record_id is not None:
            self._record_ids[(validation_name, validation)] = (decoded_domain, record_id)

    def _cleanup(self, domain, validation_name, validation):
        cached = self._record_ids.pop((validation_name, validation), None)
        if cached is None:
            logger.warning(
                "No tracked record id for %s; skipping cleanup", validation_name,
            )
            return
        cached_domain, record_id = cached
        try:
            self._api_client().del_txt_record_by_id(cached_domain, record_id)
        except ValueError as err:
            raise errors.PluginError("Cannot del txt record: {err}".format(err=err))

    def _api_client(self):
        return _APIDomain(self.token)


class _APIDomain:

    baseUrl = "https://api.infomaniak.com"

    # Polling parameters for the /check endpoint (post-create propagation).
    check_interval = 3
    check_timeout = 120

    def __init__(self, token):
        """Initialize the API client.

        :param str token: OAuth2 token to consume the Infomaniak API.
        """
        self.token = token
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": "Bearer {token}".format(token=self.token)}
        )

    def _handle_response(self, req):
        try:
            result = req.json()
        except json.decoder.JSONDecodeError as exc:
            raise errors.PluginError("no JSON in API response") from exc
        if result.get("result") == "success":
            return result.get("data")
        error = result.get("error") or {}
        if error.get("code") == "not_authorized":
            raise errors.PluginError("cannot authenticate")
        raise errors.PluginError(
            "error in API request: {} / {}".format(
                error.get("code"), error.get("description")
            )
        )

    def _get_request(self, url, payload=None):
        url = self.baseUrl + url
        logger.debug("GET %s", url)
        with self.session.get(url, params=payload) as req:
            return self._handle_response(req)

    def _post_request(self, url, payload):
        url = self.baseUrl + url
        headers = {"Content-Type": "application/json"}
        json_data = json.dumps(payload)
        logger.debug("POST %s", url)
        with self.session.post(url, data=json_data, headers=headers) as req:
            return self._handle_response(req)

    def _delete_request(self, url):
        url = self.baseUrl + url
        logger.debug("DELETE %s", url)
        with self.session.delete(url) as req:
            return self._handle_response(req)

    @staticmethod
    def _encode_zone(zone):
        """Return the ASCII / punycode form of a zone name for use in URLs."""
        return idna.encode(zone).decode("ascii")

    def _find_zone(self, domain):
        """Find the DNS zone corresponding to ``domain``.

        Iterates from the full domain up to the registrable domain, probing
        ``GET /2/zones/{zone}`` until one succeeds.
        """
        candidate = domain
        while "." in candidate:
            try:
                self._get_request(
                    "/2/zones/{zone}".format(zone=self._encode_zone(candidate)),
                )
                return candidate
            except errors.PluginError as exc:
                if "cannot authenticate" in str(exc):
                    raise
                candidate = candidate[candidate.find(".") + 1:]
        raise errors.PluginError("Domain not found")

    @staticmethod
    def _relative_source(source, zone):
        """Strip the trailing zone from ``source`` if present."""
        zone_ascii = idna.encode(zone).decode("ascii")
        suffix = "." + zone_ascii
        if source == zone_ascii:
            return "."
        if source.endswith(suffix):
            return source[: -len(suffix)]
        return source

    def _wait_for_propagation(self, zone, record_id):
        """Poll the ``/check`` endpoint until the record is live or timeout."""
        if record_id is None:
            return
        deadline = time.monotonic() + self.check_timeout
        url = "/2/zones/{zone}/records/{record_id}/check".format(
            zone=self._encode_zone(zone), record_id=record_id,
        )
        while True:
            try:
                if self._get_request(url) is True:
                    logger.debug("Record %s is propagated", record_id)
                    return
            except errors.PluginError as exc:
                logger.debug("check endpoint returned error: %s", exc)
            if time.monotonic() >= deadline:
                logger.warning(
                    "Timed out waiting for record %s to propagate; "
                    "falling back to propagation_seconds",
                    record_id,
                )
                return
            time.sleep(self.check_interval)

    @staticmethod
    def _extract_record_id(data):
        """Extract the record ID from a POST response payload."""
        if isinstance(data, dict):
            return data.get("id")
        if isinstance(data, (int, str)):
            try:
                return int(data)
            except (TypeError, ValueError):
                return None
        return None

    def add_txt_record(self, domain, source, target, ttl=300):
        """Add a TXT DNS record to a domain.

        :returns: the created record id, or ``None`` if the API response
            did not include one.
        """
        zone = self._find_zone(domain)
        relative_source = self._relative_source(source, zone)
        logger.debug("add_txt_record %s %s %s", zone, relative_source, target)
        payload = {
            "type": "TXT", "source": relative_source, "target": target, "ttl": ttl,
        }
        response = self._post_request(
            "/2/zones/{zone}/records".format(zone=self._encode_zone(zone)), payload,
        )
        record_id = self._extract_record_id(response)
        self._wait_for_propagation(zone, record_id)
        return record_id

    def del_txt_record_by_id(self, domain, record_id):
        """Delete a DNS record by id, resolving the zone from ``domain``."""
        zone = self._find_zone(domain)
        self._delete_request(
            "/2/zones/{zone}/records/{record_id}".format(
                zone=self._encode_zone(zone), record_id=record_id,
            )
        )
