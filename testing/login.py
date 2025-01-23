import base64
key= b'uhihdfsihfdgkdsfdssdfdsjhfdgkjhkfd*&^*&%%&%'
encryption_key = base64.urlsafe_b64encode(key).decode('utf-8')
print(encryption_key)