from datetime import datetime
from fitconnect import FITConnectClient, Environment
from strictyaml import load, Map, Str, Int, Seq, YAMLError
from strictyaml import Enum as YAMLEnum
import logging

# configure logging
logging.basicConfig()
logging.getLogger('fitconnect').level = logging.INFO

def read_config(config_file):
    config_schema = Map({
        "destination_id": Str(),
        "leika_key": Str(),
        "sdk": Map({
            "environment": YAMLEnum([e.name for e in Environment]), # change to native Enum when strictyaml supports it: https://github.com/crdoconnor/strictyaml/issues/73
            "client_id": Str(),
            "client_secret": Str(),
        }),
    })

    # parse yaml config
    with open(config_file) as file:
        config = load(file.read(), config_schema, label=config_file).data
    return config

# read config_file
config = read_config('conf/sender.yaml')

# initialize SDK
fitc = FITConnectClient(Environment[config['sdk']['environment']], config['sdk']['client_id'], config['sdk']['client_secret'])

with open('./test.pdf', 'rb') as f:
    file_content = f.read()

    status = fitc.submission(config['destination_id'], config['leika_key'], metadata='{"metadata": "' + str(datetime.now()) + '"}', data='{}', attachments=[file_content])
    print(status)

# == mid-level api ==
# create submission
# submission_id = fitc.create_submission(destination_id, leika_key)

# submit submission
# status = fitc.submit_submission(destination_id, submission_id, 'ey', 'eyey')
