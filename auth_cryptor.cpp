#include "stdafx.h"
#include "auth_cryptor.h"


class Cryption
{
	class CryptCounter
	{
		unsigned int m_Counter = 0;
	public:
		BYTE Key2()
		{
			return (BYTE)(m_Counter >> 8);
		}

		BYTE Key1()
		{
			return (BYTE)(m_Counter & 0xFF);
		}

		void Increment()
		{
			m_Counter++;
		}
	};

	CryptCounter _decryptCounter;
	CryptCounter _encryptCounter;
	BYTE* _cryptKey1;
	BYTE* _cryptKey2;

public:
	Cryption()
	{
		_cryptKey1 = new BYTE[0x100];
		_cryptKey2 = new BYTE[0x100];
		BYTE i_key1 = 0x9D;
		BYTE i_key2 = 0x62;
		for (int i = 0; i < 0x100; i++)
		{
			_cryptKey1[i] = i_key1;
			_cryptKey2[i] = i_key2;
			i_key1 = (BYTE)((0x0F + (BYTE)(i_key1 * 0xFA)) * i_key1 + 0x13);
			i_key2 = (BYTE)((0x79 - (BYTE)(i_key2 * 0x5C)) * i_key2 + 0x6D);
		}
	}

	void Encrypt(BYTE* buffer, int length)
	{
		for (int i = 0; i < length; i++)
		{
			*(buffer + i) ^= (BYTE)0xAB;
			*(buffer + i) = (BYTE)(*(buffer + i) >> 4 | *(buffer + i) << 4);
			*(buffer + i) ^= (BYTE)(_cryptKey1[_encryptCounter::Key1] ^ _cryptKey2[_encryptCounter::Key2]);
			_encryptCounter.Increment();
		}
	}

	void Decrypt(BYTE* buffer, int length)
	{
		for (int i = 0; i < length; i++)
		{
			buffer[i] ^= (BYTE)0xAB;
			buffer[i] = (BYTE)(buffer[i] >> 4 | buffer[i] << 4);
			buffer[i] ^= (BYTE)(_cryptKey2[_decryptCounter.Key2] ^ _cryptKey1[_decryptCounter.Key1]);
			_decryptCounter.Increment();
		}

	}

};
