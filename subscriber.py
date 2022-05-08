from fitconnect import FITConnectClient, Environment
from jwcrypto.jwe import InvalidJWEData
from os import path
from strictyaml import load, Map, Str, Int, Seq, YAMLError
from strictyaml import Enum as YAMLEnum
import json
import jsonschema
import logging

# configure logging
logging.basicConfig()
#logging.getLogger('fitconnect').level = logging.INFO

def read_config(config_file):
    config_schema = Map({
        "destination_id": Str(),
        "private_key_decryption_file": Str(),
        "sdk": Map({
            "environment": YAMLEnum([e.name for e in Environment]), # change to native Enum when strictyaml supports it: https://github.com/crdoconnor/strictyaml/issues/73
            "client_id": Str(),
            "client_secret": Str(),
        }),
    })

    # parse yaml config
    with open(config_file) as file:
        config = load(file.read(), config_schema, label=config_file).data

    # load private key for decryption
    with open(path.join(path.dirname(config_file), config['private_key_decryption_file'])) as private_key_file:
        config['private_key_decryption'] = json.load(private_key_file)

    return config

# read config_file
config = read_config('conf/subscriber.yaml')

# initialize SDK
fitc = FITConnectClient(Environment[config['sdk']['environment']], config['sdk']['client_id'], config['sdk']['client_secret'])

# activate destination
fitc.activate_destination(config['destination_id'])

# get a list of available submissions
submissions = fitc.available_submissions()

for submission in submissions:
    submission_id = submission['submissionId']
    try:
        print(f"\n== Retrieving submission {submission_id} ==")
        submission = fitc.retrieve_submission(submission_id, config['private_key_decryption'])

        if submission['metadata']:
            print("=== Metadaten ===")
            print(json.dumps(submission['metadata'], indent=2, ensure_ascii=False).encode('utf-8').decode())

        if submission['data_json']:
            print("\n=== Fachdaten ===")
            print(json.dumps(submission['data_json'], indent=2, ensure_ascii=False).encode('utf-8').decode())

        for attachment_id, attachment in submission['attachments'].items():
            print(f"\n=== Anhang ({attachment_id}) ===")
            if attachment.startswith(b'%PDF'):
                with open(f'./subscriber-data/{submission_id}--{attachment_id}-data.pdf', 'wb') as f:
                    f.write(attachment)
                    print("File written (Type: pdf)")
    except InvalidJWEData as e:
        print(f"Could not decrypt submission {submission_id}")
    except jsonschema.exceptions.ValidationError as e:
        print(f"Invalid schema in submission {submission_id}:", e)
    except json.decoder.JSONDecodeError as e:
        print(f"Unparsable json in submission {submission_id}")
    except ValueError as e:
        print("ValueError", e)
