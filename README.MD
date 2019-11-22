# Game-Streaming Dump
This project contains the tool for dumping the video stream data of cloud game clients e.g. Microsoft xCloud Project and Google Stadia(currently not supported).


# How to use
This tool is built on top of the hooking framework [Frida](https://frida.re/), so it depends the frida environment. The environment can be setup as follows:

1. Install (Python 3.7)[https://www.python.org/downloads/] and PIP

2. Install Frida Python Package
    > `pip install frida`

3. Download the corresponding (frida-server-{ver}-{platform}-{arc})[https://github.com/frida/frida/releases] from Github release. For example, if you need to install the frida server to an Android device which has ARM64 cpu, you need to choose **frida-server-12.7.22-android-arm64.xz**

4. Push the **frida-server** binary file to your Android device: 
    > `adb push frida-server /data/`

5. Run the **frida-server** in the Android with adb shell
    1. `> adb.exe shell`                #Enter the android shell      
    2. `$ su`                           # Switch to root user       
    3. `# chmod +x /data/frida-server`  # Add execute privilege   
    4. `# ./data/frida-server`          # Launch the frida-server   

6. Forward the TCP port on your device 
    1. `adb.exe forward tcp:27042 tcp:27042`
    1. `adb.exe forward tcp:27043 tcp:27043`

7. Launch the target App on the Android device
8. Run the **xcloud.py** module
9. Start playing the game and the video stream data will be captured to the file in the same folder of **xcloud*.py*
