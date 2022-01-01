from fitconnect import FITConnectClient, Environment
from strictyaml import load
import json
import logging

# configure logging
logging.basicConfig()
#logging.getLogger('fitconnect').level = logging.INFO

# load private key for decryption
private_key_decryption = None
with open('conf/privateKey_decryption.json') as private_key_file:
    private_key_decryption = json.load(private_key_file)

# read config
with open('conf/subscriber.yaml') as file:
    config = load(file.read())

# initialize SDK
fitc = FITConnectClient(config_yaml=config['sdk'].as_yaml())

# activate destination
fitc.activate_destination(config.data['destination_id'])

# get a list of available submissions
submissions = fitc.available_submissions()

for submission in submissions:
    submission = fitc.retrieve_submission(submission['submissionId'], private_key_decryption)

    if submission['metadata']:
        print("=== Metadaten ===")
        print(json.dumps(submission['metadata'], indent=2, ensure_ascii=False).encode('utf-8').decode())

    if submission['data_json']:
        print("\n=== Fachdaten ===")
        print(json.dumps(submission['data_json'], indent=2, ensure_ascii=False).encode('utf-8').decode())

    for attachment_id, attachment in submission['attachments'].items():
        print(f"\n=== Anhang ({attachment_id}) ===")
        if attachment.startswith(b'%PDF'):
            submission_id = submission['submissionId']
            with open(f'./subscriber-data/{submission_id}--{attachment_id}-data.pdf', 'wb') as f:
                f.write(attachment)
                print("File written (Type: pdf)")
