# HookTaskmgr
Hides Process From Task Manager Using WinAPI Hooking (NtQuerySystemInformation)
## How
- Hook the API function NtQuerySystemInformation() with our own function that hides a process
from task manager
- Hooked function gets called instead
- The DLL is injected into Taskmgr.exe so there is a virtual memory space available to execute our hooked code
