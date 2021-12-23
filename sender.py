from fitconnect import FITConnectClient, Environment
from datetime import datetime

client_id = ''
client_secret = ''
destination_id = ''
leika_key = 'urn:de:fim:leika:leistung:99001004000000'

# initialize SDK
fitc = FITConnectClient(Environment.TESTING, client_id, client_secret, debug=True)

with open('./test.pdf', 'rb') as f:
    file_content = f.read()
    status = fitc.submission(destination_id, leika_key, metadata='{"metadata": "' + str(datetime.now()) + '"}', data='{}', attachments=[file_content])
    print(status)

# == mid-level api ==
# create submission
# submission_id = fitc.create_submission(destination_id, leika_key)

# submit submission
# status = fitc.submit_submission(destination_id, submission_id, 'ey', 'eyey')
