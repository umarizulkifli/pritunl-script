import  sys, json, requests, time, uuid, hmac, hashlib, base64
BASE_URL = 'https://localhost:9700'
API_TOKEN = 'LIKUuWpU4BBU3ax52CxXB9iwezRcLG1m'
API_SECRET = 'AtzpTcEeFdVqRRDiMIrqrsinFv20NrWu'

def auth_request(method, path, headers=None, data=None):
    auth_timestamp = str(int(time.time()))
    auth_nonce = uuid.uuid4().hex
    auth_string = '&'.join([API_TOKEN, auth_timestamp, auth_nonce,
        method.upper(), path] + ([data] if data else []))
    auth_signature = base64.b64encode(hmac.new(
        API_SECRET, auth_string, hashlib.sha256).digest())
    auth_headers = {
        'Auth-Token': API_TOKEN,
        'Auth-Timestamp': auth_timestamp,
        'Auth-Nonce': auth_nonce,
        'Auth-Signature': auth_signature,
    }
    if headers:
        auth_headers.update(headers)
    return getattr(requests, method.lower())(
        BASE_URL + path,
        verify=False,
        headers=auth_headers,
        data=data,
)

response = auth_request('GET','/user/54c079837fa0572d1ed6946d',)
email=sys.argv[1]
assert(response.status_code == 200)
type = 'client'
data = response.json()

for value in data:
	if value['type'] == type and value['email'] == email:
		response = auth_request('DELETE','/user/54c079837fa0572d1ed6946d/'+ value['id'],)
		resp = response.json()
