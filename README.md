# FIT-Connect Python SDK

| :zap: Warning! For now, this SDK is meant to be used for testing purposes only. Please do not use in production yet! |
|----------------------------------------------------------------------------------------------------------------------|

Python wrapper for [FIT-Connect](https://docs.fitko.de/fit-connect/) APIs.

## Usage
```python
from fitconnect import FITConnectClient, Environment

# initialize SDK
fitc = FITConnectClient(Environment.TESTING, client_id, client_secret)

# send submission
status = fitc.submission(destination_id, leika_key, data, attachments=[])
print(status)

# receive submissions
submissions = fitc.available_submissions()
for submission in submissions:
    submission = fitc.retrieve_submission(submission['submissionId'], private_key_decryption)
```

See [sender.py](./sender.py) and [subscriber.py](./subscriber.py) for details.

## How to run examples
1. Create an account for the [test environment](https://docs.fitko.de/fit-connect/docs/getting-started/account).
2. Copy `conf/sender.yaml.example` to `conf/sender.yaml` and set credentials.
3. Run sender example:

```bash
poetry install
poetry run python sender.py
```

Running the subscriber example is done analogously.

## Features
- [x] encrypt and send submissions
- [x] receive and decrypt submissions
- [x] logging via python's [default logging module](https://docs.python.org/3/library/logging.html)
- [x] check metadata schema
- [x] check submission integrity via metadata hash values
- [ ] solid testing
- [ ] comprehensive documentation
- [ ] validate certificate chains
- [ ] check certificates via OSCP
- [ ] read event log
- [ ] write event log (read receipt)
- [ ] get destination id via Routing API
- [ ] additional examples and integrations

## Contributing
Documentation and tests can always be improved.
Your support in this direction is much appreciated!
Also, code contributions, bug reports and feature requests are always welcome.
Before submitting any larger code changes or adding new features, please first get in touch to avoid wasting your time with duplicate work.

## License
Licensed under the [EUPL](./LICENSE.txt).
