from fitconnect import Environment
from os import path
from strictyaml import load, Map, Str, Int, Seq, YAMLError
from strictyaml import Enum as YAMLEnum
import json

def read_config_sender(config_file):
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

def read_config_subscriber(config_file):
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
