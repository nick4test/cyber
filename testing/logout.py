import requests

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InN1YiI6InRlc3QxQHRlc3QuY29tIiwiaVNBZG1pbiI6InllcyIsImR0X3R5cGUiOlsic3RyaW5nIl19LCJleHAiOjE3MzY0NjM4ODZ9.l8obXfVeVMMLpcrsmDEHb2GhuRjHc5bOo6uJZ6ToLeg'
}

response = requests.post('http://127.0.0.1:8000/logout', headers=headers, data='')

print(response.text)