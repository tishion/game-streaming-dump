#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
This module is the used to load and run Frida script to the target applications.
Sheen Tian @ 2019-11-21-10:14:58
'''

import sys
import time
import frida

# The Javascript file name
SOURCE_FILE_NAME = "xcloud-intercept.js"
TARGET_APP = "com.microsoft.xcloud"
FILE = open('xcloud-' + time.strftime('%Y%m%d-%H%M%S.h264'), 'wb')
STOPPED = False

# Print message from target process
def on_message(message, data):
	if STOPPED:
		return

	if (message['type'] == 'send'):
		#print('es data:' + ''.join(' {:02x}'.format(x) for x in data))
		print(len(data), 'bytes written')
		FILE.write(data)
	else:
		for k, v in message.items():
			print(k, v)

# The main work funtion.
def main():
	try: 
		# Connect to the remote device
		remote_device = frida.get_remote_device()

		# Create session
		session = remote_device.attach(TARGET_APP)

		# Read the script content
		with open(SOURCE_FILE_NAME) as f:
			source = f.read()

		STOPPED = False

		# Create the script object
		script = session.create_script(source)

		# Bind the message callback
		script.on('message', on_message)
		# Load the script
		script.load()

		# Wait for the user action to quit
		input("Press Enter to exit...\n")
		
		# Swap the stop flag
		STOPPED = True

		# Close the file
		FILE.close()

		# Detach the session
		session.detach()

	except Exception as e:
		print('Failed:', e)
	
# Get into main
main()