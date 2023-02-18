from datetime import datetime
from fitconnect import FITConnectClient, Environment
from read_config import read_config_sender
from strictyaml import load, Map, Str, Int, Seq, YAMLError
from strictyaml import Enum as YAMLEnum
import argparse
import logging

# parse command line arguments
parser = argparse.ArgumentParser(
                    prog = 'sender',
                    description = 'This script uses a sender client to send a submission to a given destination')

parser.add_argument('-c', '--config', help='Path to config file', default='conf/sender.yaml')
parser.add_argument('-a', '--attachment', help='The path to an attachment that is included in the submission', default='./test.pdf')

args = parser.parse_args()

# configure logging. Uncomment to enable logging. Python's default logging level
# is WARN.
logging.basicConfig()
logging.getLogger('fitconnect').level = logging.INFO

# read config_file
config = read_config_sender(args.config)

# initialize SDK
fitc = FITConnectClient(Environment[config['sdk']['environment']], config['sdk']['client_id'], config['sdk']['client_secret'])

with open(args.attachment, 'rb') as f:
    file_content = f.read()

status = fitc.submission(config['destination_id'], config['leika_key'], data={"$schema": "urn:example:schema:submission", "now": str(datetime.now())}, attachments=[file_content])
print(status)

# == mid-level api ==
# create submission
# submission_id = fitc.create_submission(destination_id, leika_key)

# submit submission
# status = fitc.submit_submission(destination_id, submission_id, 'ey', 'eyey')
