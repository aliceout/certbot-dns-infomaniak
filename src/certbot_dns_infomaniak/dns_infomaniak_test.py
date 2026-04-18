# SPDX-FileCopyrightText: 2021-2022 Rene Luria <rene.luria@infomaniak.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for certbot_dns_infomaniak.dns_infomaniak."""

import io
import logging
import sys
import unittest
from unittest import mock

import requests_mock

from certbot.errors import PluginError
try:
    import certbot.compat.os as os
except ImportError:
    import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_infomaniak.dns_infomaniak import _APIDomain

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


FAKE_TOKEN = "xxxx"  # noqa: S105
FAKE_RECORD_ID = 1001234


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    """Class to test the Authenticator class"""
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        self.config = mock.MagicMock()

        os.environ["INFOMANIAK_API_TOKEN"] = FAKE_TOKEN

        from certbot_dns_infomaniak.dns_infomaniak import Authenticator
        self.auth = Authenticator(self.config, "infomaniak")

        self.mock_client = mock.MagicMock(default_propagation_seconds=15)
        self.mock_client.add_txt_record.return_value = FAKE_RECORD_ID

        self.auth._api_client = mock.MagicMock(return_value=self.mock_client)

        try:
            from certbot.display.util import notify  # noqa: F401
            notify_patch = mock.patch('certbot._internal.main.display_util.notify')
            self.mock_notify = notify_patch.start()
            self.addCleanup(notify_patch.stop)
            self.old_stdout = sys.stdout
            sys.stdout = io.StringIO()
        except ImportError:
            self.old_stdout = sys.stdout

    def tearDown(self):
        sys.stdout = self.old_stdout

    def test_perform(self):
        """perform() should delegate to add_txt_record on the client"""
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY)
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup_uses_tracked_record_id(self):
        """cleanup() should delete the record by the id tracked during perform()"""
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.perform([self.achall])
        self.mock_client.reset_mock()
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record_by_id(DOMAIN, FAKE_RECORD_ID)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup_without_tracked_id_is_noop(self):
        """cleanup() without a tracked id should log a warning and skip"""
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        self.assertEqual([], self.mock_client.mock_calls)


class APIDomainTest(unittest.TestCase):
    """Class to test the _APIDomain class against the Infomaniak API."""
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    record_id = FAKE_RECORD_ID

    def setUp(self):
        self.adapter = requests_mock.Adapter()

        self.client = _APIDomain(FAKE_TOKEN)
        self.client.baseUrl = "mock://endpoint"
        # Speed up polling in tests.
        self.client.check_interval = 0
        self.client.check_timeout = 1
        self.client.session.mount("mock", self.adapter)

    def _register_response(self, url, data=None, method=requests_mock.ANY):
        """Register a successful reply."""
        resp = {"result": "success", "data": data}
        self.adapter.register_uri(
            method,
            self.client.baseUrl + url,
            json=resp,
        )

    def _register_error(self, url, code, description, method=requests_mock.ANY):
        """Register an error reply."""
        resp = {"result": "error", "error": {"code": code, "description": description}}
        self.adapter.register_uri(
            method,
            self.client.baseUrl + url,
            json=resp,
        )

    def test_add_txt_record(self):
        """add_txt_record should POST the record and return the created id"""
        self._register_response(
            "/2/zones/{domain}".format(domain=DOMAIN), data={"name": DOMAIN},
        )
        self._register_response(
            "/2/zones/{domain}/records".format(domain=DOMAIN),
            data=self.record_id,
            method="POST",
        )
        self._register_response(
            "/2/zones/{domain}/records/{rid}/check".format(
                domain=DOMAIN, rid=self.record_id,
            ),
            data=True,
            method="GET",
        )

        record_id = self.client.add_txt_record(
            DOMAIN, self.record_name, self.record_content, self.record_ttl,
        )
        self.assertEqual(self.record_id, record_id)

    def test_add_txt_record_id_in_object(self):
        """add_txt_record should also accept a POST response shaped as an object"""
        self._register_response(
            "/2/zones/{domain}".format(domain=DOMAIN), data={"name": DOMAIN},
        )
        self._register_response(
            "/2/zones/{domain}/records".format(domain=DOMAIN),
            data={"id": self.record_id, "type": "TXT"},
            method="POST",
        )
        self._register_response(
            "/2/zones/{domain}/records/{rid}/check".format(
                domain=DOMAIN, rid=self.record_id,
            ),
            data=True,
            method="GET",
        )

        record_id = self.client.add_txt_record(
            DOMAIN, self.record_name, self.record_content, self.record_ttl,
        )
        self.assertEqual(self.record_id, record_id)

    def test_add_txt_record_polling_times_out(self):
        """add_txt_record should return normally when /check never returns true"""
        self._register_response(
            "/2/zones/{domain}".format(domain=DOMAIN), data={"name": DOMAIN},
        )
        self._register_response(
            "/2/zones/{domain}/records".format(domain=DOMAIN),
            data=self.record_id,
            method="POST",
        )
        self._register_response(
            "/2/zones/{domain}/records/{rid}/check".format(
                domain=DOMAIN, rid=self.record_id,
            ),
            data=False,
            method="GET",
        )
        self.client.check_timeout = 0

        record_id = self.client.add_txt_record(
            DOMAIN, self.record_name, self.record_content, self.record_ttl,
        )
        self.assertEqual(self.record_id, record_id)

    def test_add_txt_record_fail_to_find_zone(self):
        """add_txt_record with a non-existing domain should fail"""
        self.adapter.register_uri(
            requests_mock.ANY,
            requests_mock.ANY,
            json={
                "result": "error",
                "error": {"code": "not_found", "description": "zone not found"},
            },
        )
        with self.assertRaises(PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl,
            )

    def test_add_txt_record_fail_to_authenticate(self):
        """add_txt_record with an unauthorized token should fail"""
        self._register_error(
            "/2/zones/{domain}".format(domain=DOMAIN),
            "not_authorized",
            "Authorization required",
        )
        with self.assertRaises(PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl,
            )

    def test_del_txt_record_by_id(self):
        """del_txt_record_by_id should DELETE /2/zones/{zone}/records/{id}"""
        self._register_response(
            "/2/zones/{domain}".format(domain=DOMAIN), data={"name": DOMAIN},
        )
        self._register_response(
            "/2/zones/{domain}/records/{rid}".format(
                domain=DOMAIN, rid=self.record_id,
            ),
            data=True,
            method="DELETE",
        )

        self.client.del_txt_record_by_id(DOMAIN, self.record_id)

    def test_del_txt_record_by_id_fail_to_authenticate(self):
        """del_txt_record_by_id with an unauthorized token should fail"""
        self._register_error(
            "/2/zones/{domain}".format(domain=DOMAIN),
            "not_authorized",
            "Authorization required",
        )
        with self.assertRaises(PluginError):
            self.client.del_txt_record_by_id(DOMAIN, self.record_id)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
