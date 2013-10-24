#pragma once
#ifndef NIGHTMODE_H
#define NIGHTMODE_H

#define		MICROP_KLT	0xCC
#define		MICROP_KSC	0xCE

// MICROP_KLT (leds):
#define MICROP_KLT_ID_KEYPAD_LED_BRIGHTNESS_KOVS	0x14
#define MICROP_KLT_ID_LCD_BRIGHTNESS_KOVS			0x12
#define MICROP_KLT_ID_COLORLED_SETPATTERN_KOVS		0x41
#define MICROP_KLT_ID_COLORLED_SETSTATUS_KOVS		0x11
#define MICROP_KLT_ID_LIGHT_SENSOR_KOVS				0x30
#define MICROP_KLT_ID_LIGHT_SENSOR_ENABLE_KOVS		0xF7


#define I2CMgr_WriteMultiBytes_Ioctl			0x80100024
#define I2CMgr_WriteByte_Ioctl					0x8010000C
#define I2CMgr_ReadMultiBytes_Ioctl				0x80100028

#pragma pack(1)

typedef struct
{
	unsigned char device_id;
	unsigned char smth1;
	unsigned short address;
	unsigned int inBufLength;
	unsigned char *inBuf;
}I2C;

typedef struct
{
	unsigned char device_id;
	unsigned char address;
	unsigned short data;
}I2C2;
#pragma pack()

#endif