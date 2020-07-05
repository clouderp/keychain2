
import logging
from base64 import b64decode

from cryptography.fernet import Fernet

from odoo.exceptions import ValidationError
from odoo.tests.common import TransactionCase
from odoo.tools.config import config

from odoo.addons.keychain2.constants import CONFIG_KEYCHAIN_KEY


_logger = logging.getLogger(__name__)


class TestKeychain(TransactionCase):

    def setUp(self):
        super(TestKeychain, self).setUp()
        self.keychain = self.env['keychain2.account']
        config[CONFIG_KEYCHAIN_KEY] = Fernet.generate_key()
        self.keychain._fields['namespace'].selection.append(
            ('testnamespace', 'Test namespace'))

    def tearDown(self):
        super(TestKeychain, self).tearDown()
        if CONFIG_KEYCHAIN_KEY in config.options:
            del config.options[CONFIG_KEYCHAIN_KEY]

    def _create_account(self):

        def _validate_credentials(self, data):
            return (
                isinstance(data, dict)
                and 3 > len(data) > 0)

        keychain_clss = self.keychain.__class__
        keychain_clss.testnamespace_validate_credentials = (
            _validate_credentials)
        return self.keychain.create(
            dict(namespace="testnamespace"))

    def test_credentials(self):
        account = self._create_account()
        credentials = (
            '{"x": 1}',
            '{"password": 12345}',
            '{"token": "djkqfljfqm"}',
            '{"&é": "\'(§è!ç"}')

        for creds in credentials:
            account.set_credentials(creds)
            assert (
                account.credentials
                != account.credentials_input)
            assert (
                account.get_credentials()
                == creds
                == account.credentials_input
                == str(
                    Fernet(config[CONFIG_KEYCHAIN_KEY]).decrypt(
                        b64decode(account.credentials)),
                    'UTF-8'))

    def test_wrong_key(self):
        account = self._create_account()
        account.set_credentials('{"password": "urieapocq"}')
        config[CONFIG_KEYCHAIN_KEY] = Fernet.generate_key()
        credentials = None
        warning = None
        try:
            credentials = account.get_credentials()
        except Warning as warn:
            warning = warn
        assert not credentials
        assert warning

    def test_no_key(self):
        account = self._create_account()
        del config.options[CONFIG_KEYCHAIN_KEY]
        warning = None
        try:
            account.set_credentials(
                '{"password": "urieapocq"}')
        except Warning as warn:
            warning = warn
        assert warning
        assert not account.credentials

    def test_invalid_keys(self):
        account = self._create_account()
        keys = ("", "not", "0000000000000000000000000000000", "$key")
        for key in keys:
            config[CONFIG_KEYCHAIN_KEY] = key
            warning = None
            credentials = None
            try:
                credentials = account.set_credentials(
                    '{"password": "urieapocq"}')
            except Warning as warn:
                warning = warn
            assert warning
            assert not credentials

    def test_not_well_formed_json(self):
        account = self._create_account()
        wrong_jsons = (
            "{'hi': 'o'}",
            '{"oq", [>}',
            '{"foo": ["bar", "baz", ]}')
        for json in wrong_jsons:
            error = None
            try:
                account.set_credentials(json)
            except ValidationError as e:
                error = e
            assert not account.credentials
            assert error

    def test_invalid_json(self):
        account = self._create_account()
        invalid_jsons = (
            '{}',
            '[]',
            '[1, 2, 3]',
            '{"a": 1, "b": 2, "c": 3}')
        for json in invalid_jsons:
            error = None
            try:
                account.set_credentials(json)
            except ValidationError as e:
                error = e
            assert not account.credentials
            assert error

    def test_set_no_credentials(self):
        account = self._create_account()
        # does nothing
        account.set_credentials(None)
        account.set_credentials('')
        assert not account.credentials

        creds = '{"x": 1}'
        account.set_credentials(creds)

        # still does nothing
        account.set_credentials(None)
        account.set_credentials('')

        assert account.credentials
