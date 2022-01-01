import json
import requests
import uuid
from enum import Enum
from jwcrypto import jwk, jwe
from strictyaml import load, Map, Str, Int, Seq, YAMLError
from strictyaml import Enum as YAMLEnum

class Environment(Enum):
    DEV = 1
    TESTING = 2
    STAGING = 3
    PRODUCTION = 4

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

class FITConnectClient:
    def __init__(self, config_file=None, config_yaml=None, debug=False):
        self._parse_config(config_file, config_yaml)
        self.debug = debug

    def _parse_config(self, config_file=None, config_yaml=None):
        if (config_yaml is None) == (config_file is None):
           raise TypeError('You must specify exactly one of config_file, config.')

        # read config file
        if config_file is not None:
            with open(config_file) as file:
                config_yaml = file.read()

        if config_yaml is None:
           raise TypeError('You must specify exactly one of config_file, config.')

        config_schema = Map({
            "environment": YAMLEnum([e.name for e in Environment]), # change to native Enum when strictyaml supports it: https://github.com/crdoconnor/strictyaml/issues/73
            "client_id": Str(),
            "client_secret": Str(),
        })

        # parse yaml config
        if config_file is not None:
            config = load(config_yaml, config_schema, label=config_file).data
        else:
            config = load(config_yaml, config_schema).data

        self.client_id = config['client_id']
        self.client_secret = config['client_secret']

        # configure environment
        environment = Environment[config['environment']]
        if environment not in [Environment.DEV, Environment.TESTING]:
            raise ValueError("For now, this SDK is meant to be used for testing purposes only. Please do not use in production yet!")

        self.token_url = _ENVIRONMENT_CONFIG[environment]['TOKEN_URL']
        self.submission_api_url = _ENVIRONMENT_CONFIG[environment]['SUBMISSION_API_URL']

    def _get_access_token(self, client_id, client_secret):
        if self.debug: print('GET', self.token_url)
        r = requests.post(self.token_url, data = {'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': client_secret})
        if self.debug:
            print('<', r.request.body)
            print('>', r.text)
            print('>', r.status_code)
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
        # TODO: only refresh if access token is expired
        if self.client_id is not None and self.client_secret is not None:
            self.access_token = self._get_access_token(self.client_id, self.client_secret)


    # authorized get to submission api
    def _authorized_get(self, path):
        self._refresh_access_token()

        if self.debug: print('GET', self.submission_api_url + path)
        r = requests.get(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token})
        # TODO: error handling for http errors
        if self.debug:
            print('>', r.text)
        return r

    # authorized post to submission api
    def _authorized_post(self, path, json=None, data=None):
        self._refresh_access_token()

        if self.debug: print('POST', self.submission_api_url + path)
        r = requests.post(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token}, json=json, data=data)
        # TODO: error handling for http errors
        if self.debug:
            print('<', r.request.body)
            print('>', r.text)
        return r

    # authorized put to submission api
    def _authorized_put(self, path, json=None, data=None, content_type=None):
        self._refresh_access_token()

        if self.debug: print('PUT', self.submission_api_url + path)
        if content_type is not None:
            r = requests.put(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token, 'Content-Type': content_type}, json=json, data=data)
        else:
            r = requests.put(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token}, json=json, data=data)

        # TODO: error handling for http errors
        if self.debug:
            print('<', r.request.body)
            print('>', r.text)
        return r

    # authorized patch to submission api
    def _authorized_patch(self, path, json=None, data=None):
        self._refresh_access_token()

        if self.debug: print('PATCH', self.submission_api_url + path)
        r = requests.patch(self.submission_api_url + path, headers = {'Authorization': 'Bearer ' + self.access_token}, json=json, data=data)
        # TODO: error handling for http errors
        if self.debug:
            print('<', r.request.body)
            print('>', r.text)
        return r

    def get_destination(self, destination_id):
        return self._authorized_get(f'/destinations/{destination_id}')

    def activate_destination(self, destination_id):
        return self._authorized_patch(f'/destinations/{destination_id}', json={"status": "active"})

    def encrypt(self, destination_id, data):
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

        # encrypt data with public key
        data_encrypted = jwe.JWE(plaintext=data, protected={
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "zip": "DEF",
            "cty": "application/json", # TODO: fix
            "kid": pk_enc_jwk.thumbprint(),
        }, recipient=pk_enc_jwk)

        return data_encrypted.serialize(compact=True)

    def decrypt(self, private_key, data_encrypted):
        jwetoken = jwe.JWE()
        jwetoken.deserialize(data_encrypted, key=private_key)
        return jwetoken.payload

    def create_submission(self, destination_id, leika_key, num_attachments=0):
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
            if r_create_submission.json()['type'] == PROBLEM_PREFIX + 'destination-state-invalid':
                raise ValueError("Destination has not been actived yet or is not active any more")
            raise ValueError("Could not create submission")

        submission = r_create_submission.json()
        submission['announcedAttachments'] = submission_request['announcedAttachments']

        if self.debug: print('Submission created:', submission['submissionId'])

        return submission

    def upload_attachment(self, destination_id, submission_id, attachment_id, encryptedAttachment=None, attachment=None):
        #print(encryptedAttachment, attachment)
        if encryptedAttachment is None and attachment is not None:
            encryptedAttachment = self.encrypt(destination_id, attachment)

        if encryptedAttachment is None:
            raise ValueError("encryptedAttachment is None")

        r_upload_attachment = self._authorized_put(f'/submissions/{submission_id}/attachments/{attachment_id}', data=encryptedAttachment, content_type="application/jose")

        if r_upload_attachment.status_code != 204:
            raise ValueError("Error while uploading attachment", r_upload_attachment.json())

        if self.debug: print('Submission submitted')
        return r_upload_attachment

    def submit_submission(self, destination_id, submission_id, encryptedMetadata=None, encryptedData=None, metadata=None, data=None):
        #print(encryptedMetadata, encryptedData, metadata, data)
        if encryptedMetadata is None and metadata is not None:
            encryptedMetadata = self.encrypt(destination_id, metadata)
        if encryptedData is None and data is not None:
            encryptedData = self.encrypt(destination_id, data)

        r_submit_submission = self._authorized_put(f'/submissions/{submission_id}', json={
            'encryptedMetadata': encryptedMetadata,
            'encryptedData': encryptedData
        })
        if self.debug: print('Submission submitted')
        return r_submit_submission.json()

    def submission(self, destination_id, leika_key, encryptedMetadata=None, encryptedData=None, metadata=None, data=None, attachments=[]):
        submission = self.create_submission(destination_id, leika_key, len(attachments))
        submission_id = submission['submissionId']

        for i, attachment in enumerate(attachments):
            attachment_id = submission['announcedAttachments'][i]
            r_upload_attachment = self.upload_attachment(destination_id, submission_id, attachment_id, attachment=attachment)

        return self.submit_submission(destination_id, submission_id, encryptedMetadata, encryptedData, metadata, data)

    def available_submissions(self):
        r_get_submissions = self._authorized_get('/submissions')
        return r_get_submissions.json()['submissions'] # TODO: pagination

    def retrieve_submission(self, submission_id, private_key):
        private_key = jwk.JWK.from_json(json.dumps(private_key))

        r_get_submission = self._authorized_get(f'/submissions/{submission_id}')

        if r_get_submission.status_code != 200:
            r_get_submission_json = r_get_submission.json()
            if r_get_submission_json['type'] == PROBLEM_PREFIX + 'submission-not-found':
                raise ValueError("Submission not found")

            raise ValueError("Error fetching submission")

        submission = r_get_submission.json() # TODO: validate schema

        metadata_decrypted = self.decrypt(private_key, submission['encryptedMetadata'])
        if metadata_decrypted is not None:
            submission['metadata'] = json.loads(metadata_decrypted)

        data_decrypted = self.decrypt(private_key, submission['encryptedData'])
        if data_decrypted is not None:
            try:
                submission['data_json'] = json.loads(data_decrypted)
            except json.decoder.JSONDecodeError as e:
                raise e # TODO: decode xml

        attachment_ids = submission['attachments']
        attachments = {}
        for attachment_id in attachment_ids:
            r_get_attachment = self._authorized_get(f'/submissions/{submission_id}/attachments/{attachment_id}')

            data_decrypted = self.decrypt(private_key, r_get_attachment.text)
            if data_decrypted is not None:
                attachments[attachment_id] = data_decrypted

        submission['attachments'] = attachments
        # TODO: verify hash values for data and attachments from metadata schema

        # TODO: retrieve security event log
        # case_id = submission['caseId']
        # r_get_eventlog = self._authorized_get(f'/cases/{case_id}/events')

        return submission
