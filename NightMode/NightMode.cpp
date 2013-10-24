#include "stdafx.h"
#include "regext.h"
#include "service.h"
#include "NightMode.h"

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    return TRUE;
}

HANDLE FindDevHandle(const TCHAR *devname)
{
	DWORD devhnd=0;
	HKEY hActive;
	LONG rc= RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Drivers\\Active"), 0, 0, &hActive);
	if (rc) {
		//error("RegOpenKeyEx");
		return NULL;
	}
	int i=0;
	while (true) {
		TCHAR keyname[16];
		DWORD keylen=15;
		rc=RegEnumKeyEx(hActive, i++, keyname, &keylen, NULL, NULL, NULL, NULL);
		if (rc==ERROR_NO_MORE_ITEMS)
			break;
		else if (rc) {
			//error("RegEnumKeyEx");
			continue;
		}
		TCHAR regdev[16];
		regdev[0] = L'\0';
		RegistryGetString(hActive, keyname, _T("Name"), regdev, 16);

		if (_tcscmp(regdev, devname) == 0)
		{
			RegistryGetDWORD(hActive, keyname, _T("Hnd"), &devhnd);
			break;
		}
	}
	RegCloseKey(hActive);
	return (HANDLE)devhnd;
}

ULONG BLI_MessageLoop( LPVOID pParam )
{
	HANDLE device = FindDevHandle(L"BKL1:");
	DeactivateDevice(device);
	ActivateDeviceEx(L"Drivers\\BuiltIn\\FrontLight", NULL, 0, NULL);
	MSG msg;
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}

DWORD BLI_Init(DWORD dwData)
{
	CloseHandle(CreateThread(0, 0, BLI_MessageLoop, 0, 0, 0));
	return 1;
}

DWORD BLI_Deinit(DWORD dwData)
{
	return 1;
}

int i2c_write(int device_id, int address, unsigned char *buf, int buf_size)
{
	HANDLE device=CreateFileW(L"BLI1:",0xC0000000,0,0,3,0,0);

	I2C i2c;
	i2c.device_id=device_id;
	i2c.address=address;
	i2c.smth1=1;
	i2c.inBufLength=buf_size;
	i2c.inBuf=buf;
	for (int x=0;x<3;x++)
	{
		if (DeviceIoControl(device,I2CMgr_WriteMultiBytes_Ioctl,&i2c,sizeof(I2C),NULL,NULL,NULL,NULL))
			goto away;
		DeviceIoControl(device,0x80100014,&i2c,sizeof(I2C),NULL,NULL,NULL,NULL);
		Sleep(0xA);
	}
	CloseHandle(device);
	return -1;
away:
	CloseHandle(device);
	return S_OK;
}

int i2c_writewbyte(int device_id, int address, unsigned short data)
{
	HANDLE device=CreateFileW(L"BLI1:",0xC0000000,0,0,3,0,0);

	I2C2 i2c;
	i2c.device_id=device_id;
	i2c.address=address;
	i2c.data=data;
	for (int x=0;x<3;x++)
	{
		if (DeviceIoControl(device,I2CMgr_WriteByte_Ioctl,&i2c,sizeof(I2C2),NULL,NULL,NULL,NULL))
		{
			CloseHandle(device);
			return S_OK;
		}
		DeviceIoControl(device,0x80100014,&i2c,sizeof(I2C2),NULL,NULL,NULL,NULL);
		Sleep(0xA);
	}
	CloseHandle(device);
	return -1;
}

int i2c_read(int device_id, int address, unsigned char *outBuf, int outBufLength)
{
	HANDLE device=CreateFileW(L"BLI1:",0xC0000000,0,0,3,0,0);

	I2C i2c;
	i2c.device_id=device_id;
	i2c.address=address;
	i2c.smth1=1;
	i2c.inBufLength=outBufLength;
	i2c.inBuf=outBuf;
	for (int x=0;x<3;x++)
	{
		if (DeviceIoControl(device,I2CMgr_ReadMultiBytes_Ioctl,&i2c,sizeof(I2C),outBuf,outBufLength,NULL,NULL))
		{
			CloseHandle(device);
			return S_OK;
		}
		DeviceIoControl(device,0x80100014,&i2c,sizeof(I2C),NULL,NULL,NULL,NULL);
		Sleep(0xA);
	}
	CloseHandle(device);
	return -1;
};


int lightsensor_enable(unsigned short mode)
{
	unsigned char buf[2] = {0, mode};
	return i2c_write(MICROP_KLT, MICROP_KLT_ID_LIGHT_SENSOR_ENABLE_KOVS, buf, 2);
}

int lightsensor_read()
{
	unsigned char buf[2]={0,0};
	int res=i2c_read(MICROP_KLT, MICROP_KLT_ID_LIGHT_SENSOR_KOVS, buf, sizeof(buf));
	if (res!=S_OK)
		return -1;

	int r2 = buf[1] | ((buf[0] & 3) << 8);
	return r2;
}

DWORD GetLightSensorValue(DWORD dwAmbientLevel)
{
	DWORD dwResult = dwAmbientLevel;
	DWORD dwLightDetect = 0;
	RegistryGetDWORD(HKEY_CURRENT_USER, L"ControlPanel\\BackLight", L"LightDetectOn", &dwLightDetect);
	if (dwLightDetect == 0)
	{
		lightsensor_enable(1);
	}
	dwResult = lightsensor_read();
	if (dwLightDetect == 0)
	{
		lightsensor_enable(0);
	}
	return dwResult;
}

BOOL BLI_IOControl(DWORD hOpenContext,
				   DWORD dwCode,
				   PBYTE pInBuf,
				   DWORD nInBufSize,
				   PBYTE pOutBuf,
				   DWORD nOutBufSize,
				   PDWORD pBytesReturned)
{
	switch (dwCode) 
	{
	case IOCTL_SERVICE_START:
		return TRUE;
	case IOCTL_SERVICE_STOP:
		return TRUE;
	case IOCTL_SERVICE_STARTED:
		return TRUE;
	case IOCTL_SERVICE_INSTALL: 
		{
			// Registering our service in the OS
			HKEY hKey;
			DWORD dwValue;

			if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Services\\NightMode", 0, 
				NULL, 0, 0, NULL, &hKey, &dwValue)) 
				return FALSE;

			// DLL name
			WCHAR dllname[] = L"NightMode.dll";
			RegSetValueExW(hKey, L"Dll", 0, REG_SZ, 
				(const BYTE *)dllname, wcslen(dllname) << 1);

			// Setting prefix used to control our service
			RegSetValueExW(hKey, L"Prefix", 0, REG_SZ, (const BYTE *)L"BLI",6);

			// Flags, Index, Context
			dwValue = 0;
			RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, (const BYTE *) &dwValue, 4);
			RegSetValueExW(hKey, L"Context", 0, REG_DWORD, (const BYTE *) &dwValue, 4);

			// Should system keep service alive after initialization?
			dwValue = 1;
			RegSetValueExW(hKey, L"Index", 0, REG_DWORD, (const BYTE *) &dwValue, 4);
			RegSetValueExW(hKey, L"Keep", 0, REG_DWORD, (const BYTE *) &dwValue, 4);

			// Setting load order
			dwValue = 9999;
			RegSetValueExW(hKey, L"Order", 0, REG_DWORD, (const BYTE *) &dwValue, 4);

			RegCloseKey(hKey);
			return TRUE;
		}
	case IOCTL_SERVICE_UNINSTALL: 
		{
			// Uninstalling service from the OS
			HKEY rk;
			if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Services", 0, NULL, &rk)) 
				return FALSE;

			RegDeleteKeyW(rk, L"NightMode");
			RegCloseKey(rk);

			return TRUE;
		}

	case IOCTL_SERVICE_QUERY_CAN_DEINIT:
		{
			memset(pOutBuf, 1, nOutBufSize);
			return TRUE;
		}
	case IOCTL_SERVICE_CONTROL:
		{
			if (nInBufSize != 4)
				return FALSE;

			return TRUE;
		}
	default:
		{
			HANDLE device = CreateFileW(L"I2C1:", 0xC0000000, 0, 0, 3, 0, 0);
			BOOL res = TRUE;
			if (device)
			{
				if (dwCode == I2CMgr_WriteMultiBytes_Ioctl)
				{
					I2C *i2c = (I2C*)pInBuf;
					if (i2c && i2c->device_id == MICROP_KLT && i2c->address == MICROP_KLT_ID_LCD_BRIGHTNESS_KOVS)
					{
						DWORD dwEnable = 0;
						RegistryGetDWORD(HKEY_CURRENT_USER, L"Software\\ultrashot\\NightMode", L"Enable", &dwEnable);
						if (dwEnable)
						{
							if (i2c->inBuf[1] != 0)
							{
								DWORD dwLevel = 0;
								RegistryGetDWORD(HKEY_CURRENT_USER, L"Software\\ultrashot\\NightMode", L"Level", &dwLevel);
								
								DWORD dwAmbientLightLevel = 10;
								RegistryGetDWORD(HKEY_CURRENT_USER, L"Software\\ultrashot\\NightMode", L"AmbientLightLevel", &dwAmbientLightLevel);
								
								if (GetLightSensorValue(dwAmbientLightLevel) < dwAmbientLightLevel)
								{
									i2c->inBuf[1] = (char)dwLevel;
								}
							}
						}
					}
				}
				res = DeviceIoControl(device, dwCode, pInBuf, nInBufSize, pOutBuf, nOutBufSize, pBytesReturned, NULL);

				CloseHandle(device);
			}
			return res;
		}
	}
	return FALSE;
}


DWORD BLI_Open(DWORD hDeviceContext,
			   DWORD AccessCode,
			   DWORD ShareMode)
{
	return hDeviceContext;
}

DWORD BLI_Read(DWORD dwData,
			   LPVOID pBuf,
			   DWORD dwLen)
{
	return 0;
}

DWORD BLI_Seek(DWORD dwData,
			   long pos,
			   DWORD type)
{
	return (DWORD)-1;
}

DWORD BLI_Write(DWORD dwData,
				LPCVOID pInBuf,
				DWORD dwInLen)
{
	return 0;
}

DWORD BLI_Close(DWORD dwData)
{
	return 1;
}
