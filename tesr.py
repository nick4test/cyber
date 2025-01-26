import requests

url = "http://127.0.0.1:8000/access_key"

payload = {}
headers = {
  'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InN1YiI6Im5pY2tAbmljay5jb20iLCJBZG1pbiI6Im5vIiwiZHRfdHlwZSI6WyJzdHJpbmciXX0sImV4cCI6MTczNzkxMzI0MH0.kJ4wwBE6sN-SfqSU8ph7FA_ivLGZRuihFgq6FuNeivo'
}
response = requests.request("POST", url, headers=headers, data=payload)

print(response.headers)
