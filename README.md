# ring3-kit
Hides Process From Task Manager Using NT Hooking (NtQuerySystemInformation). A simple Ring-3 (user mode) rootkit. 
## How
- Hook the API function NtQuerySystemInformation() with our own function that hides a process
from task manager
- Hooked function gets called instead
- The DLL is injected into Taskmgr.exe so there is a virtual memory space available to execute our hooked code

## Disclaimer
The developer, Josh Schiavone is not responsible or liable for the misuse of this simple rootkit. Do not deploy this rootkit in association with legitmate malware programs on machines that you have no authorized access to. May God bless you all. 
