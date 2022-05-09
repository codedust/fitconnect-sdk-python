import hashlib
import json
import jsonschema
import logging
import os
import re
import requests
import semver
import uuid
from datetime import datetime
from enum import Enum
from jwcrypto import jwk, jwe

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

class _DocEnum(Enum):
    def __new__(cls, value, doc=None):
        self = object.__new__(cls)  # calling super().__new__(value) here would fail
        self._value_ = value
        if doc is not None:
            self.__doc__ = doc
        return self

class Environment(_DocEnum):
    '''The environment Enum that specifies the server environment to talk with.'''
    DEV = 1, "The development environment (used internally by the FIT-Connect team)"
    TESTING = 2, "The test environment that can be used freely"
    STAGING = 3, "The staging environment to test update before deploying to production"
    PRODUCTION = 4, "The production environment"

_ENVIRONMENT_CONFIG = {
    Environment.DEV: {
        'TOKEN_URL': 'https://auth-dev.fit-connect.fitko.dev/token',
        'SUBMISSION_API_URL': 'https://submission-api-dev.fit-connect.fitko.dev/v1',
    },
    Environment.TESTING: {
        'TOKEN_URL': 'https://auth-testing.fit-connect.fitko.dev/token',
        'SUBMISSION_API_URL': 'https://submission-api-testing.fit-connect.fitko.dev/v1',
    },
    Environment.STAGING: {},
    Environment.PRODUCTION: {}
}

PROBLEM_PREFIX = 'https://schema.fitko.de/fit-connect/submission-api/problems/'
METADATA_SCHEMA_URI = 'https://schema.fitko.de/fit-connect/metadata/'
SEMVER_REGEX = '[1-9]+\.[0-9]+\.[0-9]+'

class ProblemDetailError(Exception):
    '''exception that represents a "problem detail" according to RFC 7807, see https://datatracker.ietf.org/doc/html/rfc7807'''
    def __init__(self, problem_detail, *args):
        super().__init__(args)
        self.problem_type = problem_detail['type']
        self.title = problem_detail['title']
        self.detail = problem_detail['detail']
        self.instance = problem_detail['instance'] if 'instance' in problem_detail else None

    def __str__(self):
        if self.instance is not None:
            return f'{self.title} <{self.problem_type}:{self.instance}> ({self.detail})'
        else:
            return f'{self.title} <{self.problem_type}> ({self.detail})'

class FITConnectClient:
    '''The main class of this SDK. Initialize the SDK by initializing a
    FITConnectClient object.

    :param environment: The server environment to talk with. Use
        Environment.TESTING to access the test environment.
    :type environment: enum:`Environment`
    :param client_id: The OAuth client id of the API client registered in the
        self service portal.
    :type client_id: str
    :param client_secret: The OAuth client secret of the API client registered
        in the self service portal.
    :type client_secret: str
    :param insecure: Set to False to disable some security checks. For debugging
        purposes only!!
    :type insecure: bool, optional
    '''

    def __init__(self, environment, client_id, client_secret, insecure=False):
        '''Constructor method
        '''
        # configure environment
        allowed_environments = [Environment.DEV, Environment.TESTING]
        if environment not in allowed_environments:
            raise ValueError(f'Invalid environment given: {environment}. For now, this SDK is meant to be used for testing purposes only. Please do not use in production yet! Environment be one of {allowed_environments}.')

        self.token_url = _ENVIRONMENT_CONFIG[environment]['TOKEN_URL']
        self.submission_api_url = _ENVIRONMENT_CONFIG[environment]['SUBMISSION_API_URL']

        # set OAuth credentials
        self.client_id = client_id
        self.client_secret = client_secret

        self.ignore_metadata_hashes = insecure

    def _get_access_token(self, client_id, client_secret):
        '''Internal method to receive the OAuth access token

        :param client_id: The OAuth client id of the API client registered in the
            self service portal.
        :type client_id: str
        :param client_secret: The OAuth client secret of the API client registered
            in the self service portal.
        :type client_secret: str
        '''
        log.debug(f'POST {self.token_url}')
        r = requests.post(self.token_url, data = {'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': client_secret})
        log.debug(f'req = {r.request.body}')
        log.debug(f'status_code = {r.status_code}')
        log.debug(f'resp = {r.text}')
        if r.status_code == 404:
            raise ValueError("Invalid OAuth token url")
        if r.status_code == 401:
            raise ValueError('Missing or invalid client authentication')
        elif r.status_code != 200:
            response_json = r.json()

            if "error" in response_json:
                if response_json['error'] == 'invalid_scope':
                    raise ValueError("Invalid OAuth scope. If this client is a subscriber, did you assign a destination in the self service portal?")

            raise ValueError('Error while retrieving access token')

        access_token = r.json()["access_token"]
        return access_token

    def _refresh_access_token(self):
        '''Internal method to refresh the OAuth access token
        '''
        # TODO: only refresh if access token is expired
        self.access_token = self._get_access_token(self.client_id, self.client_secret)

    def _authorized_get(self, path):
        '''Internal method to execute authorized GET requests to Submission API

        :param path: The relative HTTP path
        :type path: str
        '''
        self._refresh_access_token()

        log.debug(f'GET {self.submission_api_url + path}')
        r = requests.get(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token})
        # TODO: error handling for http errors
        log.debug(f'status_code = {r.status_code}')
        log.debug(f'headers = {r.headers}')
        log.debug(f'resp = {r.text}')
        return r

    def _authorized_post(self, path, json=None, data=None):
        '''Internal method to execute authorized POST requests to Submission API

        :param path: The relative HTTP path
        :type path: str
        :param json: A JSON serializable Python object to send in the body of the
            request
        :type json: object, optional
        :param data: Dictionary, list of tuples, bytes, or file-like object to
            send in the body of the request.
        :type data: dict, list of tuples, bytes or file-like object, optional
        :return: Returns a Requests (python HTTP library) Response object
        :rtype: requests.Response
        '''
        self._refresh_access_token()

        log.debug(f'POST {self.submission_api_url + path}')
        r = requests.post(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token}, json=json, data=data)
        # TODO: error handling for http errors
        log.debug(f'req = {r.request.body}')
        log.debug(f'status_code = {r.status_code}')
        log.debug(f'resp = {r.text}')
        return r

    def _authorized_put(self, path, json=None, data=None, content_type=None):
        '''Internal method to execute authorized PUT requests to Submission API

        :param path: The relative HTTP path
        :type path: str
        :param json: A JSON serializable Python object to send in the body of the
            request
        :type json: object, optional
        :param data: Dictionary, list of tuples, bytes, or file-like object to
            send in the body of the request.
        :type data: dict, list of tuples, bytes or file-like object, optional
        :param content_type: The request body's content type
        :type content_type: str
        :return: Returns a Requests (python HTTP library) Response object
        :rtype: requests.Response
        '''
        self._refresh_access_token()

        log.debug(f'PUT {self.submission_api_url + path}')
        if content_type is not None:
            r = requests.put(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token, 'Content-Type': content_type}, json=json, data=data)
        else:
            r = requests.put(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token}, json=json, data=data)

        # TODO: error handling for http errors
        log.debug(f'req = {r.request.body}')
        log.debug(f'status_code = {r.status_code}')
        log.debug(f'resp = {r.text}')
        return r

    def _authorized_patch(self, path, json=None, data=None):
        '''Internal method to execute authorized PATCH requests to Submission API

        :param path: The relative HTTP path
        :type path: str
        :param json: A JSON serializable Python object to send in the body of the
            request
        :type json: object, optional
        :param data: Dictionary, list of tuples, bytes, or file-like object to
            send in the body of the request.
        :type data: dict, list of tuples, bytes or file-like object, optional
        :return: Returns a Requests (python HTTP library) Response object
        :rtype: requests.Response
        '''
        self._refresh_access_token()

        log.debug(f'PATCH {self.submission_api_url + path}')
        r = requests.patch(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token}, json=json, data=data)
        # TODO: error handling for http errors
        log.debug(f'req = {r.request.body}')
        log.debug(f'status_code = {r.status_code}')
        log.debug(f'resp = {r.text}')
        return r

    def get_destination(self, destination_id):
        '''Get destination object

        :param destination_id: Destination id (uuid) of the destination to query
        :type destination_id: str
        '''
        return self._authorized_get(f'/destinations/{destination_id}')

    def activate_destination(self, destination_id):
        '''Activate destination

        :param destination_id: Destination id (uuid) of the destination to activate
        :type destination_id: str
        '''
        return self._authorized_patch(f'/destinations/{destination_id}', json={"status": "active"})

    def convert_to_bytes(self, obj):
        '''Convert dict, str or bytes object to bytes.

        :param obj: The dict, str, or bytes object
        :type obj: dict, str, or bytes
        :return: The obj converted to bytes
        :rtype: bytes
        '''
        if isinstance(obj, dict):
            return json.dumps(obj).encode('utf-8')
        elif isinstance(obj, str):
            return obj.encode('utf-8')
        elif isinstance(obj, bytes):
            return obj
        else:
            raise TypeError(f"Cannot convert type {type(obj).__name__} to bytes")

    def encrypt(self, destination_id, data):
        '''Encrypt data for the given destination. The given data will be
        encrypted using the public key of the given destination. The public keys
        is retrieved automatically.

        :param destination_id: The destination id (uuid) of the destination for
            which the data will be encrypted
        :type destination_id: str
        :param data: The data to be encrypted
        :type data: dict, str, or bytes
        :return: A ‘raw’ JWE token (compact notation) string
        :rtype: str
        '''
        r_get_destination = self._authorized_get(f'/destinations/{destination_id}')
        encryption_kid = r_get_destination.json()['encryptionKid']

        # retrieve public key
        r_get_destination_key = self._authorized_get(f'/destinations/{destination_id}/keys/{encryption_kid}')
        pk_enc = r_get_destination_key.json()

        # verify key usage
        if "wrapKey" not in pk_enc['key_ops']:
            raise ValueError("invalid keyUsage: public key cannot be used for encryption")

        # check key length
        pk_enc['key_ops'] = ['wrapKey']
        pk_enc_jwk = jwk.JWK.from_json(json.dumps(pk_enc))

        if len(pk_enc['n'])*6 < 4096: # base64-encoding: each char represents 6 bit
            raise ValueError("invalid key length: ")

        # TODO: verify that n and e values from jwk match values from certificate
        # TODO: validate certificate chain (with v-pki trust anchor)
        # TODO: ocsp status validation / crl check
        try:
            data_bytes = self.convert_to_bytes(data)
        except TypeError as e:
            raise TypeError(f"Cannot encrypt object of type {type(data).__name__}")

        # encrypt data with public key
        data_encrypted = jwe.JWE(plaintext=data_bytes, protected={
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "zip": "DEF",
            "cty": "application/json", # TODO: fix
            "kid": pk_enc_jwk.thumbprint(),
        }, recipient=pk_enc_jwk)

        return data_encrypted.serialize(compact=True)

    def decrypt(self, private_key, data_encrypted):
        '''Decrypt data using the given private key

        :param private_key: The private key as JSON Web Key
        :type private_key: jwcrypto.jwk.JWK
        :param data_decrypted: A 'raw' JWE token (JSON Encoded or Compact
            notation) string.
        :type data: str
        :return: The decrypted data
        :rtype: bytes
        '''
        jwetoken = jwe.JWE()
        jwetoken.deserialize(data_encrypted, key=private_key)
        return jwetoken.payload

    def decrypt_json(self, private_key, data_encrypted):
        '''Decrypt and parse encrypted json data

        :param private_key: The private key as JSON Web Key
        :type private_key: jwcrypto.jwk.JWK
        :param data_encrypted: A 'raw' JWE token (JSON Encoded or Compact
            notation) string.
        :type data: str
        :return: The decrypted json object
        :rtype: dict
        '''
        data_decrypted = self.decrypt(private_key, data_encrypted)

        try:
            return json.loads(data_decrypted)
        except json.decoder.JSONDecodeError as e:
            log.error("Could not parse decrypted data as json")
            raise e

    def latest_metadata_schema(self, major=None, minor=None, patch=None):
        '''load latest metadata schema included in this SDK. If major, minor or
        patch parameters are given, the latest schema matching these criteria
        is retrieved.

        :param major: The major version of the metadata schema
        :type major: int
        :param minor: The minor version of the metadata schema
        :type minor: int
        :param patch: The patchversion of the metadata schema
        :type patch: int
        :return: The metadata schema
        :rtype: dict
        '''
        latest_version = semver.Version(major = 1)
        matching_version_found = False

        schema_dir = os.path.join(os.path.dirname(__file__), 'schema')

        for file_name in os.listdir(schema_dir):
            match = re.match('^metadata\.schema\.v(' + SEMVER_REGEX + ')\.json$', file_name)
            if match and match[1] >= latest_version and \
                (major is None or semver.Version.parse(match[1]).major == major) and \
                (minor is None or semver.Version.parse(match[1]).minor == minor) and \
                (patch is None or semver.Version.parse(match[1]).patch == patch):
                matching_version_found = True
                latest_version = semver.Version.parse(match[1])

        if not matching_version_found:
            raise ValueError("not matching matadata version found!")

        log.debug(f'Loading metadata schema v{latest_version}')

        with open(os.path.join(schema_dir, 'metadata.schema.v' + str(latest_version) + '.json')) as file:
            return json.load(file)

    def create_submission(self, destination_id, leika_key, num_attachments=0):
        '''Create a submission via the Submission API. If you just want to send
        a submission without dealing with API-specific details, just use the
        `submission` method instead.

        :param destination_id: The destination id of the destination to which
            the submission is sent
        :type destination_id: str
        :param leika_key: The LeiKa key ("Leistungsschlüssel" from
            "Leistungskatalog der öffentlichen Verwaltung") for this submission
            represented as urn. E.g. `urn:de:fim:leika:leistung:99018115001001`
        :type leika_key: str
        :param num_attachments: The number of attachments that will be
            announced. Defaults to 0
        :type num_attachments: int
        :return: The response from the API, with the additional
            `announcedAttachments` parameter
        :rtype: dict
        '''
        # TODO: verify that leika_key matches destination

        submission_request = {
            'destinationId': destination_id,
            'announcedAttachments': [str(uuid.uuid4())] * num_attachments,
            'serviceType': {
                'name': '', # TODO: auto-fill via leika key
                'identifier': leika_key
            }
        }

        r_create_submission = self._authorized_post('/submissions', json=submission_request)
        if r_create_submission.status_code != 201:
            if r_create_submission.json()['type'] == PROBLEM_PREFIX + 'destination-not-found':
                raise ValueError("Could not create submission: destination does not exist")
            if r_create_submission.json()['type'] == PROBLEM_PREFIX + 'destination-state-invalid':
                raise ValueError("Could not create submission: destination has not been actived yet or is not active any more")
            raise ValueError("Could not create submission", r_create_submission.text)

        submission = r_create_submission.json()
        submission['announcedAttachments'] = submission_request['announcedAttachments']

        log.info('Submission created (submission_id = {})'.format(submission['submissionId']))
        return submission

    def upload_attachment(self, destination_id, submission_id, attachment_id, attachment=None, attachment_encrypted=None):
        '''Upload an attachment for an existing submission via the Submission
        API. If you just want to send a submission without dealing with
        API-specific details, just use the `submission` method instead.
        Please provide either `attachment` or `attachment_encrypted`.

        :param destination_id: The destination id of the destination to which
            the attachment is sent
        :type destination_id: str
        :param submission_id: The submission id of the submission to which
            the attachment is attached
        :type submission_id: str
        :param attachment_id: The attachement id of the attachement to be
            uploaded
        :type attachment_id: str
        :param attachment: The unencrypted attachment to be encrypted and
            uploaded
        :type attachment: dict, str, or bytes, optional
        :param encrypted_attachment: The encrypted attachment to be uploaded
        :type encrypted_attachment: str, optional
        :return: The Response from the API
        :rtype: requests.Response
        '''
        if attachment_encrypted is None and attachment is not None:
            attachment_encrypted = self.encrypt(destination_id, attachment)

        if attachment_encrypted is None:
            raise ValueError("attachment_encrypted is None")

        r_upload_attachment = self._authorized_put(f'/submissions/{submission_id}/attachments/{attachment_id}', data=attachment_encrypted, content_type="application/jose")

        if r_upload_attachment.status_code != 204:
            raise ValueError("Error while uploading attachment", r_upload_attachment.json())

        log.info(f'Attachment uploaded (submission_id = {submission_id}, attachment_id = {attachment_id})')
        return r_upload_attachment

    def submit_submission(self, destination_id, submission_id, metadata=None, metadata_encrypted=None, data=None, data_encrypted=None):
        '''Submit a submission via the Submission API. If you just want to send
        a submission without dealing with API-specific details, just use the
        `submission` method instead. Please provide either `metadata` or
        `metadata_encrypted` and either `data` or `data_encrypted`.

        :param destination_id: The destination id of the destination to which
            the submission is sent
        :type destination_id: str
        :param submission_id: The submission id of the submission
        :type submission_id: str
        :param metadata: The unencrypted metadata to be encrypted and
            uploaded
        :type metadata: dict, str, or bytes, optional
        :param encrypted_metadata: The encrypted metadata to be uploaded
        :type encrypted_metadata: str, optional
        :param data: The unencrypted data to be encrypted and uploaded
        :type data: dict, str, or bytes, optional
        :param encrypted_data: The encrypted data to be uploaded
        :type encrypted_data: str, optional
        :return: The response from the API
        :rtype: dict
        '''
        if metadata_encrypted is None and metadata is not None:
            metadata_encrypted = self.encrypt(destination_id, metadata)
        if data_encrypted is None and data is not None:
            data_encrypted = self.encrypt(destination_id, data)

        r_submit_submission = self._authorized_put(f'/submissions/{submission_id}', json={
            'encryptedMetadata': metadata_encrypted,
            'encryptedData': data_encrypted
        })

        log.info(f'Submission submitted (submission_id = {submission_id})')
        return r_submit_submission.json()

    def submission(self, destination_id, leika_key, metadata=None, metadata_encrypted=None, data=None, data_encrypted=None, data_sha512=None, data_schema=None, attachments=[]):
        '''All-in-one method to create, encrypt and send a submission including
        attachments. Please provide either `metadata` or `metadata_encrypted`
        and either `data` or `data_encrypted`.

        :param destination_id: The destination id of the destination to which
            the submission is sent
        :type destination_id: str
        :param leika_key: The LeiKa key ("Leistungsschlüssel" from
            "Leistungskatalog der öffentlichen Verwaltung") for this submission
            represented as urn. E.g. `urn:de:fim:leika:leistung:99018115001001`
        :type leika_key: str
        :param metadata: The unencrypted metadata to be uploaded
        :type metadata: dict, str, or bytes, optional
        :param encrypted_metadata: The encrypted metadata to be uploaded
        :type encrypted_metadata: str, optional
        :param data: The unencrypted data to be encrypted and uploaded
        :type data: dict, str, or bytes, optional
        :param encrypted_data: The encrypted data to be uploaded
        :type encrypted_data: str, optional
        :param data_sha512: The SHA-512 hash of the unencrypted data. This
            parameter is required only if the `encrypted_data` parameter is
            used. Otherwise the hash value will be calculated automatically.
        :type data_sha512: str, optional
        :param data_schema: The schema reference of the data as URI. This
            parameter is required only if the schema URI cannot be retrieved
            from the `data` object (in JSON format) via the `$schema` attribute.
        :param attachments: The list of unencrypted attachments to be sent.
            Defaults to an empty list
        :type attachments: list, optional
        :return: The response from the API
        :rtype: dict
        '''
        submission = self.create_submission(destination_id, leika_key, len(attachments))
        submission_id = submission['submissionId']

        # create metadata if non-existent
        if metadata is None and metadata_encrypted is None:
            metadata = {
                "$schema": METADATA_SCHEMA_URI + "1.0.0/metadata.schema.json",
                "contentStructure": {
                    "attachments": [],
                }
            }

        # create metadata entry for each attachment and upload attachments
        for i, attachment in enumerate(attachments):
            attachment_id = submission['announcedAttachments'][i]

            if metadata is not None and attachment_id not in map(lambda attachment: attachment['attachmentId'], metadata['contentStructure']['attachments']):
                attachment_sha512 = hashlib.sha512(attachment).hexdigest() # TODO: support for attachments_encrypted + attachment_sha512
                attachment_metadata = {
                    "attachmentId": attachment_id,
                    "hash": {
                        "type": "sha512",
                        "content": attachment_sha512,
                    },
                    "mimeType": "application/pdf",
                    "purpose": "attachment",
                }
                metadata['contentStructure']['attachments'].append(attachment_metadata)

            r_upload_attachment = self.upload_attachment(destination_id, submission_id, attachment_id, attachment=attachment)

        # add additional metadata entries and validate metadata
        if metadata is not None:
            # add submissionDate to metadata
            if 'additionalReferenceInfo' not in metadata:
                metadata['additionalReferenceInfo'] = {
                    "submissionDate": str(datetime.now()),
                }

            if 'data' not in metadata['contentStructure']:
                metadata['contentStructure']['data'] = {}

            if 'hash' not in metadata['contentStructure']['data']:
                if data is not None:
                    try:
                        data_bytes = self.convert_to_bytes(data)
                    except TypeError as e:
                        raise TypeError(f"Invalid type of parameter `data`: {type(data).__name__}")

                    data_sha512 = hashlib.sha512(data_bytes).hexdigest()
                elif data_sha512 is None:
                    raise ValueError("Could not include data hash. Please provide `data` or `data_sha512` parameter.")

                metadata['contentStructure']['data']['hash'] = {
                    "type": "sha512",
                    "content": data_sha512,
                }

            if 'submissionSchema' not in metadata['contentStructure']['data']:
                if isinstance(data, dict) and '$schema' in data:
                    if data_schema is None:
                        data_schema = {
                            "schemaUri": data['$schema'],
                            "mimeType": "application/json",
                        }
                    else:
                        if 'schemaUri' not in data_schema or 'mimeType' not in data_schema:
                            raise ValueError("Invalid data_schema given")

                        if data['$schema'] != data_schema['schemaUri']:
                            raise ValueError(f"Submission schema mismatch: {data_schema} does not match {data['$schema']['schemaUri']} from data object")

                # if no data_schema was given and data_schema could not be retrieved
                if data_schema is None:
                    raise ValueError("Submission schema could not be determined. Please include '$schema' in json data or specify via data_schema parameter.")

                metadata['contentStructure']['data']['submissionSchema'] = data_schema

            # valdate metadata schema
            metadata_schema = self.latest_metadata_schema(major=1, minor=0) # TODO: get $schema from metadata

            try:
                jsonschema.validate(metadata, metadata_schema)
            except jsonschema.exceptions.ValidationError as e:
                log.error("Metadata does not match schema")
                raise e # TODO: raise InvalidMetadataError

        return self.submit_submission(destination_id, submission_id, metadata, metadata_encrypted, data, data_encrypted)

    def available_submissions(self):
        '''Retrieve a list of available submissions

        :return: The list of avaliable submissions as a list of dicts containing
            the destination id, submission id and case id of the available
            submission
        :rtype: list
        '''
        r_get_submissions = self._authorized_get('/submissions')
        return r_get_submissions.json()['submissions'] # TODO: pagination

    def _validate_metadata_schema(self, metadata):
        '''Validate metadata json schema

        :param metadata: the unencrypted metadata dict
        :type metadata: dict
        '''
        if '$schema' in metadata:
            schema = metadata['$schema']
            match = re.match('^' + re.escape(METADATA_SCHEMA_URI) + '('+SEMVER_REGEX+')' + re.escape('/metadata.schema.json') + '$', schema)
            if match:
                schema_version = semver.Version.parse(match[1])
                metadata_schema = self.latest_metadata_schema(major=schema_version.major, minor=schema_version.minor)
            else:
                log.error(f"Invalid $schema: '{schema}' on instance: {metadata}")
                raise ValueError("Invalid $schema:", schema)
        else:
            # if no schema is given, assume latest v1.0.x
            metadata_schema = self.latest_metadata_schema(major=1, minor=0)

        try:
            jsonschema.validate(metadata, metadata_schema)
        except jsonschema.exceptions.ValidationError as e:
            if not self.ignore_metadata_hashes:
                log.error("Metadata does not match schema")
                raise e # TODO: raise InvalidMetadataError

    def verify_metadata_data_hash(self, metadata, data_decrypted):
        '''verify hash value from metadata for data

        :param metadata: the unencrypted metadata dict
        :type metadata: dict
        :param data_decrypted: the decrypted data object as bytes
        :type metadata: bytes
        '''
        data_decrypted_hash = hashlib.sha512(data_decrypted).hexdigest()
        if 'data' not in metadata['contentStructure']:
            raise ValueError("Data missing in metadata['contentStructure']")

        if not self.ignore_metadata_hashes and data_decrypted_hash != metadata['contentStructure']['data']['hash']['content']:
            raise ValueError("Invalid attachment hash!")

    def verify_metadata_attachment_hash(self, metadata, attachment_id, attachment_decrypted):
        '''verify hash value from metadata for the given attachement

        :param metadata: the unencrypted metadata dict
        :type metadata: dict
        :param attachment_decrypted: the decrypted attachment object as bytes
        :type metadata: bytes
        :param attachment_id: the attachment id
        :type attachment_id: str
        '''
        attachment_decrypted_hash = hashlib.sha512(attachment_decrypted).hexdigest()
        metadata_attachments_filtered = list(filter(lambda a: a['attachmentId'] == attachment_id, metadata['contentStructure']['attachments']))
        if len(metadata_attachments_filtered) != 1:
            raise ValueError("Invalid attachments in metadata")

        if not self.ignore_metadata_hashes and attachment_decrypted_hash != metadata_attachments_filtered[0]['hash']['content']:
            raise ValueError("Invalid attachment hash!")

    def _get_submission(self, submission_id):
        '''download submission (without attachments)

        :param submission_id: The submission id of the submission
        :type submission_id: str

        :return: The submission as dict
        :rtype: dict
        '''
        r_get_submission = self._authorized_get(f'/submissions/{submission_id}')

        if r_get_submission.status_code != 200:
            r_get_submission_json = r_get_submission.json()
            if r_get_submission_json['type'] == PROBLEM_PREFIX + 'submission-not-found':
                raise ValueError("Submission not found")

            raise ValueError("Error fetching submission")

        log.info(f'Submission retrieved (submission_id = {submission_id})')
        return r_get_submission.json() # TODO: validate schema

    def retrieve_submission(self, submission_id, private_key):
        '''All-in-one method to retrieve a submission including attachments

        :param submission_id: The submission id of the submission
        :type submission_id: str
        :param private_key: The private key of the corresponding destination as
            JSON Web Key
        :type private_key: jwcrypto.jwk.JWK
        :return: The submission as dict
        :rtype: dict
        '''
        private_key = jwk.JWK.from_json(json.dumps(private_key))

        # download submission
        submission = self._get_submission(submission_id)

        # decrypt and validate metadata
        submission['metadata'] = self.decrypt_json(private_key, submission['encryptedMetadata']) # TODO: error handling
        self._validate_metadata_schema(submission['metadata'])

        # decrypt and validata data
        data_decrypted = self.decrypt(private_key, submission['encryptedData']) # TODO: error handling
        self.verify_metadata_data_hash(submission['metadata'], data_decrypted)

        try:
            submission['data_json'] = json.loads(data_decrypted)
        except json.decoder.JSONDecodeError as e:
            raise e # TODO: decode xml

        # handle attachments
        attachment_ids = submission['attachments']
        attachments = {}
        for attachment_id in attachment_ids:
            r_get_attachment = self._authorized_get(f'/submissions/{submission_id}/attachments/{attachment_id}')
            log.info(f'Attachment retrieved (submission_id = {submission_id}, attachment_id = {attachment_id})')

            attachments[attachment_id] = self.decrypt(private_key, r_get_attachment.text) # TODO: error handling

            # verify hash values from metadata for attachment
            self.verify_metadata_attachment_hash(submission['metadata'], attachment_id, attachments[attachment_id])

        submission['attachments'] = attachments

        # TODO: retrieve security event log
        # case_id = submission['caseId']
        # r_get_eventlog = self._authorized_get(f'/cases/{case_id}/events')

        return submission
