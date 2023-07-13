#include <shlwapi.h>

static inline const HANDLE
	SK_GetCurrentThread(void) noexcept
{
	static const HANDLE
		_caller((HANDLE)-2);
	return _caller;
};

static inline const HANDLE
	SK_GetCurrentProcess(void) noexcept
{
	static const HANDLE
		_host((HANDLE)-1);
	return _host;
};

bool SK_Display_ForceDPIAwarenessUsingAppCompat(bool set)
{
	DWORD dwProcessSize = MAX_PATH;
	wchar_t wszProcessName[MAX_PATH + 2] = {};

	HANDLE hProc =
		SK_GetCurrentProcess();

	QueryFullProcessImageName(
		hProc, 0,
		wszProcessName, &dwProcessSize);

	const wchar_t* wszKey =
		LR"(Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers)";
	DWORD dwDisposition = 0x00;
	HKEY hKey = nullptr;

	const LSTATUS status =
		RegCreateKeyExW(HKEY_CURRENT_USER,
			wszKey, 0,
			nullptr, 0x0,
			KEY_READ | KEY_WRITE,
			nullptr,
			&hKey,
			&dwDisposition);

	if (status == ERROR_SUCCESS &&
		hKey != nullptr) {
		wchar_t wszOrigKeyVal[2048] = {};
		DWORD len = sizeof(wszOrigKeyVal) / 2;

		RegGetValueW(
			hKey, nullptr, wszProcessName, RRF_RT_REG_SZ,
			nullptr, wszOrigKeyVal, &len);

		wchar_t* pwszHIGHDPIAWARE =
			StrStrIW(wszOrigKeyVal, L"HIGHDPIAWARE");
		wchar_t* pwszNextToken = pwszHIGHDPIAWARE + 13;

		if ((!set) && pwszHIGHDPIAWARE != nullptr) {
			*pwszHIGHDPIAWARE = L'\0';

			std::wstring combined = wszOrigKeyVal;
			combined += L" ";
			combined += pwszNextToken;

			wcsncpy_s(wszOrigKeyVal, len,
				combined.c_str(), _TRUNCATE);

			StrTrimW(wszOrigKeyVal, L" ");

			if (wszOrigKeyVal[0] != L'\0') {
				RegSetValueExW(
					hKey, wszProcessName,
					0, REG_SZ,
					(BYTE*)wszOrigKeyVal,
					(DWORD)((wcslen(wszOrigKeyVal) + 1) * sizeof(wchar_t)));
			} else {
				RegDeleteValueW(hKey, wszProcessName);
				RegCloseKey(hKey);
				return true;
			}
		}

		else if (set && pwszHIGHDPIAWARE == nullptr) {
			StrCatW(wszOrigKeyVal, L" HIGHDPIAWARE");
			StrTrimW(wszOrigKeyVal, L" ");

			RegSetValueExW(
				hKey, wszProcessName,
				0, REG_SZ,
				(BYTE*)wszOrigKeyVal,
				(DWORD)((wcslen(wszOrigKeyVal) + 1) * sizeof(wchar_t)));
		}

		RegFlushKey(hKey);
		RegCloseKey(hKey);
	} else {
		logger::error("Failed to get AppCompatFlags registry");
		return false;
	}
	return true;
}

bool Load()
{
	if (SK_Display_ForceDPIAwarenessUsingAppCompat(true)) {
		logger::info("Disabled DPI awareness");
	}
	return true;
}