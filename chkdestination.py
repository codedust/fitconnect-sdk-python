from read_config import read_config_destination
from fitconnect import FITConnectClient, Environment
import json
import logging
import sys

'''The script chkdestination.py uses sender clients to verify the existence and status of a
specified destination. The destination ID is expected as the first command line parameter.
'''

if len(sys.argv) != 2:
    raise ValueError('Please provide a DestinationId as first argument.')

destination = sys.argv[1]

# configure logging. Uncomment to enable logging. Python's default logging level
# is WARN.
logging.basicConfig()
logging.getLogger('fitconnect').level = logging.INFO

# read config_file
config = read_config_destination('conf/destination.yaml')

# Run through all environments read from the configuration file
clients = config.keys()
for client in clients:
    #Initialize SDK for specific Environment
    fitc = FITConnectClient(Environment[config[client]['environment']], config[client]['client_id'], config[client]['client_secret'])

    # collect response
    response = fitc.get_destination(destination)

    # get status TRUE or FALSE
    status = response.ok
    # convert response content into a JSON
    jsonValue = json.loads(response.content.decode())
    if status == True:
        print(f"Environment {client}: Destination {jsonValue['destinationId']} is {jsonValue['status']}")        
    elif status == False:
        print (f"Environment {client}: {jsonValue['detail']}")
