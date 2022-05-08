from datetime import datetime
from fitconnect import FITConnectClient, Environment
from read_config import read_config_sender
from strictyaml import load, Map, Str, Int, Seq, YAMLError
from strictyaml import Enum as YAMLEnum
import logging

# configure logging. Uncomment to enable logging. Python's default logging level
# is WARN.
logging.basicConfig()
logging.getLogger('fitconnect').level = logging.INFO

# read config_file
config = read_config_sender('conf/sender.yaml')

# initialize SDK
fitc = FITConnectClient(Environment[config['sdk']['environment']], config['sdk']['client_id'], config['sdk']['client_secret'])

with open('./test.pdf', 'rb') as f:
    file_content = f.read()

status = fitc.submission(config['destination_id'], config['leika_key'], data={"$schema": "urn:example:schema:submission", "now": str(datetime.now())}, attachments=[file_content])
print(status)

# == mid-level api ==
# create submission
# submission_id = fitc.create_submission(destination_id, leika_key)

# submit submission
# status = fitc.submit_submission(destination_id, submission_id, 'ey', 'eyey')
