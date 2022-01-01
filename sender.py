from datetime import datetime
from fitconnect import FITConnectClient, Environment
from strictyaml import load
import logging

# configure logging
logging.basicConfig()
logging.getLogger('fitconnect').level = logging.INFO

# read config
with open('conf/sender.yaml') as file:
    config = load(file.read())

# initialize SDK
fitc = FITConnectClient(config_yaml=config['sdk'].as_yaml())

with open('./test.pdf', 'rb') as f:
    file_content = f.read()

    status = fitc.submission(config.data['destination_id'], config.data['leika_key'], metadata='{"metadata": "' + str(datetime.now()) + '"}', data='{}', attachments=[file_content])
    print(status)

# == mid-level api ==
# create submission
# submission_id = fitc.create_submission(destination_id, leika_key)

# submit submission
# status = fitc.submit_submission(destination_id, submission_id, 'ey', 'eyey')
