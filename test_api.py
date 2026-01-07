import requests

url = "http://127.0.0.1:5000/predict"
data = {"body": "Hello, this is a test email"}
response = requests.post(url, json=data)
print(response.json())
