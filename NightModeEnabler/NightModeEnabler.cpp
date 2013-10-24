#include "stdafx.h"
#include "regext.h"

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwEnable = 0;

	RegistryGetDWORD(HKEY_CURRENT_USER, L"Software\\ultrashot\\NightMode", L"Enable", &dwEnable);
	RegistrySetDWORD(HKEY_CURRENT_USER, L"Software\\ultrashot\\NightMode", L"Enable", dwEnable ? 0 : 1);

	// forcing backlight driver to update backlight.
	DWORD AcBrightness = 1;
	DWORD BattBrightness = 1;
	RegistryGetDWORD(HKEY_CURRENT_USER, L"ControlPanel\\BackLight", L"ACBrightness", &AcBrightness);
	RegistrySetDWORD(HKEY_CURRENT_USER, L"ControlPanel\\BackLight", L"ACBrightness", AcBrightness - 1);
	RegistrySetDWORD(HKEY_CURRENT_USER, L"ControlPanel\\BackLight", L"ACBrightness", AcBrightness);

	RegistryGetDWORD(HKEY_CURRENT_USER, L"ControlPanel\\BackLight", L"Brightness", &BattBrightness);
	RegistrySetDWORD(HKEY_CURRENT_USER, L"ControlPanel\\BackLight", L"Brightness", BattBrightness - 1);
	RegistrySetDWORD(HKEY_CURRENT_USER, L"ControlPanel\\BackLight", L"Brightness", BattBrightness);

	return 0;
}

