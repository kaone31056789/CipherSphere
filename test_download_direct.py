#!/usr/bin/env python3
"""
Test script to simulate a download request
"""
import requests
import os

def test_download():
    """Test the download functionality"""
    
    # Check if there are any temp files
    temp_dir = os.path.join(os.path.dirname(__file__), 'ciphersphere', 'uploads', 'temp')
    if os.path.exists(temp_dir):
        files = os.listdir(temp_dir)
        if files:
            temp_file = files[0]
            print(f"Testing download of: {temp_file}")
            
            # Simulate the download request
            download_url = "http://127.0.0.1:5000/download_decrypted_temp"
            data = {
                'temp_filename': temp_file,
                'filename': temp_file.replace('decrypted_', '')
            }
            
            try:
                response = requests.post(download_url, data=data, allow_redirects=False)
                print(f"Response status: {response.status_code}")
                print(f"Response headers: {dict(response.headers)}")
                if response.status_code != 200:
                    print(f"Response text: {response.text}")
                else:
                    print("Download successful!")
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}")
        else:
            print("No temp files found to test download")
    else:
        print("Temp directory not found")

if __name__ == "__main__":
    test_download()
