import requests
import json

# Test the download endpoint directly
file_id = 5  # This file exists according to our debug script

# Assuming the app is running on localhost:5000
url = f"http://localhost:5000/vault/download/{file_id}"

try:
    # You'll need to be logged in for this to work
    # For now, let's just see what response we get
    response = requests.get(url)
    print(f"Status Code: {response.status_code}")
    print(f"Headers: {dict(response.headers)}")
    
    if response.status_code == 200:
        print(f"Content Length: {len(response.content)}")
        print("Download would work!")
    else:
        print(f"Response Text: {response.text}")
        
except Exception as e:
    print(f"Error: {e}")

print("\nNote: This test requires you to be logged in to work properly.")
print("If you see a 401/403 error, that's normal - it means authentication is working.")
