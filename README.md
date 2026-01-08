# Elevated CMD
[CMLuaUtil]::ShellExec("cmd.exe")

# Elevated PowerShell
[CMLuaUtil]::ShellExec("powershell.exe", "-NoExit -Command whoami /priv")

# Programm mit Argumenten
[CMLuaUtil]::ShellExec("notepad.exe", "C:\Windows\System32\drivers\etc\hosts")

# Registry Wert setzen (HKLM)
[CMLuaUtil]::SetRegValue("SOFTWARE\Test", "MyValue", "MyData")

# Registry Wert loeschen
[CMLuaUtil]::DeleteRegValue("SOFTWARE\Test", "MyValue")
