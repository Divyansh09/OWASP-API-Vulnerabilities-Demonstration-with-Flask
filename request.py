import requests

base = "http://127.0.0.1:5000/"

data = {
    'username': "abcdeff",
    'password': "efgh"
}

response = requests.get(base + 'api/admin-action')
print(response.json())
