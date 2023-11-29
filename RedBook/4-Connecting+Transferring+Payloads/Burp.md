# Burp
Burp allows us to intercept and edit web requests. This makes it useful for fuzzing and payloads.

## Proxy
Make sure Intercept is on

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/37508407-50a7-4406-b265-9e49928742d6)


Right click or click Action button to send to Repeater or Intruder

Other options

`Change request method` Change post-get
`Copy to file` useful for programs like sqlmap -r
`Copy as curl commmand(bash)`

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/90317dc3-13a0-4b82-ae69-a5b782ee7fd0)

## Repeater
Repeater will keep the request after submitting allowing for constant refinement of the payload.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/23e0d64e-3877-4eec-85c4-cd1f2ccdffbe)


## Intruder

Useful for fuzzing.
Positions are the variable that will be changed. Payloads are the list that will be used. Processing allows user to define rules to manipulate the words in the list. Payload encoding option on the bottom is automatically selected.

Length and status useful to determine which payloads succeded.
