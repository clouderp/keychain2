# -*- coding: utf-8 -*-

import json
import logging
from base64 import b64decode, b64encode

from cryptography.fernet import (
    Fernet, InvalidToken)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (
    asymmetric, hashes, serialization)

from odoo import fields, models
from odoo.exceptions import ValidationError
from odoo.tools.config import config
from odoo.tools.translate import _

from ..constants import (
    CONFIG_KEYCHAIN_KEY,
    CONFIG_KEYCHAIN_PRIVATE_KEY,
    CONFIG_KEYCHAIN_PUBLIC_KEY)
from ..decorators import delegated


_logger = logging.getLogger(__name__)


class Keychain2Account(models.Model):
    _name = 'keychain2.account'
    _description = 'Keychain account with encrypted secrets'

    credentials = fields.Binary()
    credentials_input = fields.Text(
        help="Credentials. Leave empty if no changes",
        inverse='_inverse_set_credentials',
        store=False)
    namespace = fields.Selection(
        selection=[],
        help="Type of account",
        required=True)

    @staticmethod
    def _parse_credentials(data):
        try:
            return json.loads(data)
        except ValueError:
            raise ValidationError(
                _("Credentials should be valid JSON"))

    @classmethod
    def _decode_credentials(cls, data):
        cypher, padding = cls._get_cypher(private=True)
        args = (
            (data, padding)
            if padding
            else (data, ))
        try:
            return str(cypher.decrypt(*args), 'UTF-8')
        except InvalidToken:
            raise Warning(
                _("Password has been encrypted with a different "
                  "key. Unless you can recover the previous key, "
                  "this password is unreadable."))

    @classmethod
    def _encode_credentials(cls, data):
        cypher, padding = cls._get_cypher()
        data = (data or '').encode()
        args = (
            (data, padding)
            if padding
            else (data, ))
        return cypher.encrypt(*args)

    @classmethod
    def _get_asymmetric_cypher(cls, private_key, public_key, private=False):
        if private and not private_key:
            raise Warning(
                _('Private key is not set, unable to decode credentials'))
        elif not private and not public_key:
            raise Warning(
                _('Public key is not set, unable to encode credentials'))
        try:
            return cls._load_asymmetric_cypher(
                private_key, public_key, private)
        except (ValueError) as e:
            key = public_key
            key_type = "public"
            if private:
                key = private_key
                key_type = "private"
            raise Warning(
                'Missing or invalid %s key `%s`: %s'
                % (key_type, key, e))

    @classmethod
    def _get_cypher(cls, private=False):
        symmetric_key = config.get(CONFIG_KEYCHAIN_KEY)
        private_key = config.get(CONFIG_KEYCHAIN_PRIVATE_KEY)
        public_key = config.get(CONFIG_KEYCHAIN_PUBLIC_KEY)
        cypher = cls._get_symmetric_cypher
        args = (symmetric_key, )
        if public_key or private_key:
            if symmetric_key:
                _logger.warn(
                    "Both symmetric key and asymmetric keys are set, "
                    "defaulting to asymmetric encryption")
            cypher = cls._get_asymmetric_cypher
            args = (private_key, public_key, private)
        return cypher(*args)

    @classmethod
    def _get_symmetric_cypher(cls, key, private=False):
        try:
            return (
                Fernet(key),
                None)
        except (ValueError, TypeError) as e:
            raise Warning(
                'Missing or invalid `%s`: %s'
                % (CONFIG_KEYCHAIN_KEY, e))

    @classmethod
    def _load_asymmetric_cypher(cls, private_key, public_key, private=False):
        key = public_key
        key_type = "public"
        kwargs = {}
        if private:
            key = private_key
            key_type = "private"
            kwargs = dict(password=None)
        return (
            cls._load_key_file(
                key_type,
                key,
                **kwargs),
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))

    @classmethod
    def _load_key_file(cls, key_type, key_path, **kwargs):
        with open(key_path, "rb") as key_file:
            serializer = getattr(
                serialization,
                "load_pem_%s_key" % key_type)
            return serializer(
                key_file.read(),
                backend=default_backend(),
                **kwargs)

    def get_credentials(self):
        try:
            return self._decode_credentials(b64decode(self.credentials))
        except Warning as warn:
            raise Warning(_("%s\nKeychain: %s" % (warn, self.namespace)))

    def set_credentials(self, credentials):
        self.credentials_input = credentials
        self._inverse_set_credentials()

    def _inverse_set_credentials(self):
        for rec in self:
            if not rec.credentials_input:
                continue
            parsed = rec._parse_credentials(rec.credentials_input)
            if not rec._validate_credentials(parsed):
                raise ValidationError(_("Credentials not valid"))
            rec.credentials = b64encode(
                rec._encode_credentials(rec.credentials_input))

    @delegated
    def _validate_credentials(self, data):
        pass
