import json

data = json.load(open('report.json'))

apistats=data["behavior"]["apistats"]
processes=data["behavior"]["processes"]

categories = ["system", "file", "browser", "com", "crypto", "process","synchronisation", "registry", "misc", "services", "windows",
"device", "network", "threading", "hooking", "__notification__","resource","ole","ui","exception"]

APIFunctions = ["NtOpenSection", "NtWaitForSingleObject", "GetAsyncKeyState",
"NtDeleteValueKey", "WSARecv", "getaddrinfo",
"InternetGetConnectedState", "NtCreateEvent",
"GetFileVersionInfoSizeW", "GetAdaptersAddresses",
"NtMakeTemporaryObject", "NtRenameKey", "HttpSendRequestA",
"GetLocalTime", "NetUserGetLocalGroups", "FindFirstFileExW",
"CryptRetrieveObjectByUrlW", "NtReadVirtualMemory",
"HttpAddRequestHeadersA", "RegOpenKeyExW", "NtDelayExecution",
"InternetCrackUrlA", "SetErrorMode", "ShellExecuteExW",
"RegOpenKeyExA", "HttpSendRequestW", "HttpAddRequestHeadersW",
"GetCursorPos", "JsEval", "GetUserNameW", "WinHttpSetTimeouts",
"WaitForDebugEvent", "FindWindowExA", "GetUserNameA",
"NtCreateFile", "TransmitFile", "GetSystemTimeAsFileTime",
"WinHttpOpen", "NtLoadDriver", "GetDiskFreeSpaceA",
"NtCreateProcess", "NtDeleteKey", "WinHttpQueryHeaders",
"InternetSetOptionA", "CryptGenKey", "recvfrom", "CryptEncrypt",
"sendto", "NtSuspendThread", "NtQueryInformationFile",
"RegCreateKeyExW", "GetSystemTime", "DeviceIoControl",
"WSASendTo", "FindFirstChangeNotificationW", "NtQueryKey",
"OpenServiceA", "WriteProcessMemory", "WSARecvFrom",
"NtSetContextThread", "HttpEndRequestW", "RegQueryValueExA",
"RemoveDirectoryW", "EnumWindows", "OpenServiceW", "NtSetValueKey","LookupPrivilegeValueW", "NtQueryValueKey", "RegCreateKeyExA",
"RemoveDirectoryA", "HttpEndRequestA", "RegQueryValueExW",
"WSASocketW", "NetUserGetInfo", "SetWindowsHookExW",
"ExitWindowsEx", "WSASend", "WinHttpGetProxyForUrl",
"StartServiceA", "NtDeviceIoControlFile", "NtReadFile",
"CryptCreateHash", "FindWindowExW", "NtWriteFile",
"LdrGetDllHandle", "WinHttpSendRequest", "RtlDecompressBuffer",
"NtQuerySystemInformation", "NtEnumerateValueKey",
"CreateDirectoryExW", "CreateThread", "NtLoadKey",
"SetupDiGetClassDevsA", "SetUnhandledExceptionFilter",
"NtQuerySystemTime", "GetVolumeNameForVolumeMountPointW",
"DnsQuery_A", "CryptDecrypt", "recv", "SetupDiGetClassDevsW",
"NtProtectVirtualMemory", "SHGetFolderPathW", "RegDeleteValueW",
"GetDiskFreeSpaceExA", "socket", "RegSetValueExW", "WriteConsoleA",
"LdrGetProcedureAddress", "NtOpenThread", "CopyFileA", "CopyFileW",
"RegSetValueExA", "GetDiskFreeSpaceExW", "NtEnumerateKey",
"NtOpenDirectoryObject", "LdrLoadDll", "NtWriteVirtualMemory",
"URLDownloadToFileW", "WriteConsoleW", "CreateToolhelp32Snapshot",
"SendNotifyMessageA", "RegCloseKey", "NtOpenEvent",
"NtSetInformationFile", "HttpSendRequestExW", "NtCreateKey",
"WinHttpConnect", "MoveFileWithProgressW", "ioctlsocket",
"WSAStartup", "NtTerminateThread", "DbgUiWaitStateChange",
"NtTerminateProcess", "send", "shutdown", "SendNotifyMessageW",
"COleScript_ParseScriptText", "HttpSendRequestExA", "select",
"NtQueryFullAttributesFile", "CreateRemoteThread","GetSystemMetrics", "NtQueueApcThread", "WSASocketA",
"CreateServiceA", "WinHttpSetOption", "InternetCloseHandle",
"DeleteFileA", "NtLoadKey2", "CryptExportKey",
"CryptImportPublicKeyInfo", "NtAllocateVirtualMemory",
"ReadProcessMemory", "CreateDirectoryW", "DeleteFileW",
"VirtualProtectEx", "CreateServiceW", "listen", "NtCreateThread",
"GetComputerNameW", "NtResumeThread", "CryptAcquireContextA",
"setsockopt", "InternetReadFile", "CoCreateInstance","RegEnumKeyExW", "FindNextFileW", "ObtainUserAgentString",
"CryptAcquireContextW", "DnsQuery_W", "NtCreateNamedPipeFile",
"GetComputerNameA", "NtReplaceKey", "RegEnumKeyExA", "closesocket",
"NtGetContextThread", "RtlCreateUserThread", "RegEnumValueW",
"NtCreateSection", "StartServiceW",
"WinHttpGetIEProxyConfigForCurrentUser", "SetWindowsHookExA",
"NtOpenMutant", "InternetOpenA", "NtDeleteFile", "NSPStartup",
"IsDebuggerPresent", "RegEnumValueA", "WinHttpReceiveResponse",
"InternetOpenW", "CreateProcessInternalW", "connect",
"RegDeleteKeyA", "NtDuplicateObject", "RegNotifyChangeKeyValue",
"NtQueryMultipleValueKey", "HttpOpenRequestA", "OpenSCManagerW",
"GetSystemInfo", "NtCreateProcessEx", "accept", "FindWindowW",
"ControlService", "NtClose", "RegDeleteKeyW", "CryptHashData",
"NtOpenProcess", "FindWindowA", "HttpOpenRequestW",
"NtFreeVirtualMemory", "Process32NextW", "GetLastInputInfo",
"InternetConnectW", "UnhookWindowsHookEx", "InternetWriteFile",
"GetDiskFreeSpaceW", "NtSaveKeyEx", "RegEnumKeyW",
"InternetConnectA", "NtSaveKey", "SetWindowLongA", "CDocument_write",
"WSAConnect", "RegDeleteValueA", "CopyFileExW", "NtMapViewOfSection",
"SetupDiGetDeviceRegistryPropertyW", "Process32FirstW",
"DeleteService", "LsaOpenPolicy", "NtOpenFile", "RegQueryInfoKeyW",
"NtUnmapViewOfSection", "NtQueryDirectoryFile",
"NetGetJoinInformation", "FindFirstFileExA", "gethostbyname",
"DecodeImage", "NtQueryAttributesFile", "RegQueryInfoKeyA","NtCreateMutant", "GetAddrInfoW", "InternetOpenUrlA", "WSAAccept",
"bind", "NtOpenKey", "InternetCrackUrlW", "DnsQuery_UTF8",
"CoInternetSetFeatureEnabled", "NtResumeProcess", "OpenSCManagerA",
"GetFileVersionInfoW", "CryptDecodeObjectEx", "InternetOpenUrlW",
"OpenSCManagerA", "WinHttpOpenRequest",
"SetupDiGetDeviceRegistryPropertyA"]

numberOfRunningProcess=len(processes)
totalCategory = 0
categoriesFreq = dict.fromkeys(categories,0)
categoriesPercentage = dict.fromkeys(categories,0)
APIFreq = dict.fromkeys(APIFunctions,0)

for x in processes:
	if len(x["calls"])!=0:
		for call in  x["calls"]:
			categoriesFreq[call["category"]] = categoriesFreq[call["category"]] + 1
			totalCategory = totalCategory + 1

for k,v in apistats.items():
	for func,count in v.items():
		try:
			APIFreq[func] = APIFreq[func] + count
		except KeyError:
			continue

for k,v in categoriesFreq.items():
	categoriesPercentage[k]=(v/totalCategory)*100

print(numberOfRunningProcess)
print(categoriesFreq)
print(totalCategory)
print(categoriesPercentage)