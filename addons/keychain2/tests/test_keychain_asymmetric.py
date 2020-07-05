# -*- coding: utf-8 -*-

import logging
from base64 import b64decode

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, serialization

from odoo.exceptions import ValidationError
from odoo.tests.common import TransactionCase
from odoo.tools.config import config

from odoo.addons.keychain2.constants import (
    CONFIG_KEYCHAIN_KEY,
    CONFIG_KEYCHAIN_PRIVATE_KEY,
    CONFIG_KEYCHAIN_PUBLIC_KEY)


_logger = logging.getLogger(__name__)


class TestAsymmetricKeychain(TransactionCase):
    _private_key_path = '/tmp/test_private_key.pem'
    _public_key_path = '/tmp/test_public_key.pem'

    def _create_keys(self):
        private_key = asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open(self._private_key_path, 'wb') as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()))
        with open(self._public_key_path, 'wb') as f:
            f.write(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def setUp(self):
        super(TestAsymmetricKeychain, self).setUp()
        self.keychain = self.env['keychain2.account']
        self._create_keys()
        config[CONFIG_KEYCHAIN_PRIVATE_KEY] = self._private_key_path
        config[CONFIG_KEYCHAIN_PUBLIC_KEY] = self._public_key_path
        self.keychain._fields['namespace'].selection.append(
            ('testnamespace', 'Test namespace'))

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
                account.credentials
                != creds)
            assert (
                account.get_credentials()
                == creds
                == account.credentials_input)

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

    def test_write_no_public_key(self):
        account = self._create_account()
        del config.options[CONFIG_KEYCHAIN_PUBLIC_KEY]
        warning = None
        try:
            account.set_credentials(
                '{"password": "urieapocq"}')
        except Warning as warn:
            warning = warn
        assert warning
        assert not account.credentials

    def test_write_bad_public_key(self):
        account = self._create_account()
        with open(config.options[CONFIG_KEYCHAIN_PUBLIC_KEY], 'wb') as f:
            f.write(b'NOT A KEY!!!')
        warning = None
        try:
            account.set_credentials(
                '{"password": "urieapocq"}')
        except Warning as warn:
            warning = warn
        assert warning
        assert not account.credentials

    def test_write_no_private_key(self):
        account = self._create_account()
        del config.options[CONFIG_KEYCHAIN_PRIVATE_KEY]
        account = self._create_account()
        credentials = (
            '{"x": 1}',
            '{"password": 12345}',
            '{"token": "djkqfljfqm"}',
            '{"&é": "\'(§è!ç"}')

        for creds in credentials:
            account.set_credentials(creds)
            assert account.credentials
            assert account.credentials != creds
            assert (
                account.credentials
                != account.credentials_input)
            assert (
                account.credentials
                != creds)
            error = None
            try:
                account.get_credentials()
            except Warning as err:
                error = err
            assert error

    def test_read_no_private_key(self):
        account = self._create_account()
        del config.options[CONFIG_KEYCHAIN_PRIVATE_KEY]
        account.set_credentials(
            '{"password": "urieapocq"}')
        error = None
        try:
            account.get_credentials()
        except Warning as err:
            error = err
        assert error

    def test_read_bad_private_key(self):
        account = self._create_account()
        with open(config.options[CONFIG_KEYCHAIN_PRIVATE_KEY], 'wb') as f:
            f.write(b'NOT A KEY!!!')
        account.set_credentials(
            '{"password": "urieapocq"}')
        error = None
        try:
            account.get_credentials()
        except Warning as err:
            error = err
        assert error

    def test_read_no_public_key(self):
        account = self._create_account()
        account = self._create_account()
        creds = '{"x": 1}'
        account.set_credentials(creds)
        del config.options[CONFIG_KEYCHAIN_PUBLIC_KEY]
        assert (
            account.get_credentials()
            == account.credentials_input
            == creds)

    def test_symmetric_key_also_set(self):
        config[CONFIG_KEYCHAIN_KEY] = Fernet.generate_key()
        account = self._create_account()
        creds = '{"x": 1}'
        account.set_credentials(creds)
        error = None
        try:
            Fernet(config[CONFIG_KEYCHAIN_KEY]).decrypt(
                b64decode(account.credentials))
        except InvalidToken as err:
            error = err
        assert error
        assert (
            account.credentials
            != account.credentials_input)
        assert (
            account.credentials
            != creds)
        assert (
            account.get_credentials()
            == creds
            == account.credentials_input)
        del config.options[CONFIG_KEYCHAIN_KEY]
