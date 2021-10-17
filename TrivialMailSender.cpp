#include "TrivialMailSender.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct IUnknown; // Workaround Windows header problem.
#define SECURITY_WIN32
#include <WS2tcpip.h> // Must come first. https://stackoverflow.com/questions/1372480/c-redefinition-header-files-winsock2-h
#include <Windns.h>
#include <Windows.h>
#include <security.h>
#include <schannel.h>



#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment (lib, "Ws2_32.lib")

#define PRINTF_SERVER_COMMUNICATION 0

static const size_t IoBufferSize = 65536;
static const size_t DomainNameSizeMax = 512;
static const size_t ReceiveBufferSize = 1024;
static const size_t SendMessageBufferSize = 8096;

// ##################################################################################################################
// ################ General helper functions ########################################################################
// ##################################################################################################################
static inline void FormatDateTime(char* OutStr, size_t OutCapacity, time_t DateTime)
{
	tm Loc;
	if (gmtime_s(&Loc, &DateTime))
	{
		*OutStr = '\0';
		return;
	}

	static const char Weeks[][4] = { "Sun", "Mon", "Tue", "Wen", "Thu", "Fri", "Sat" };
	static const char Months[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	 
	snprintf(OutStr, OutCapacity, "%s, %d %s %d %02d:%02d:%02d +0000", Weeks[Loc.tm_wday],
		Loc.tm_mday, Months[Loc.tm_mon], 1900 + Loc.tm_year, Loc.tm_hour, Loc.tm_min, Loc.tm_sec);
}
static inline void GetGUID(char* OutStr, size_t OutCapacity)
{
	GUID Guid;
	if (UuidCreate(&Guid) != S_OK)
		Guid = {};
	snprintf(OutStr, OutCapacity, "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", // https://stackoverflow.com/a/18114061
		Guid.Data1, Guid.Data2, Guid.Data3, 
		Guid.Data4[0], Guid.Data4[1], Guid.Data4[2], Guid.Data4[3],
		Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7]);
}
static inline void FindEmailAddress(char const* EmailAddress, size_t EmailAddressLength, size_t* OutBegin, size_t* OutLength)
{
	size_t Begin = 0;
	size_t Length = EmailAddressLength;

	// If there are any brackets like <> then they contain the email address...
	char const* const Bra = reinterpret_cast<char const*>(memchr(EmailAddress + Begin, '<', Length));
	char const* const Ket = reinterpret_cast<char const*>(memchr(EmailAddress + Begin, '>', Length));
	if (Bra && Ket && Bra < Ket)
	{
		Begin = Bra + 1 - EmailAddress;
		Length = Ket - (Bra + 1);
	}
	else
	{
		// Othrwise maybe thre are brackets like (). In that case, the email address is in front.
		char const* const Bra2 = reinterpret_cast<char const*>(memchr(EmailAddress + Begin, '(', Length));
		char const* const Ket2 = reinterpret_cast<char const*>(memchr(EmailAddress + Begin, ')', Length));
		if (Bra2 && Ket2 && Bra2 < Ket2)
		{
			Begin = 0;
			Length = Bra2 - EmailAddress;
		}
	}

	// Trim unnecessary whitespace...
	while (Length && isspace(EmailAddress[Begin]))
		++Begin;
	while (Length && isspace(EmailAddress[Begin + Length - 1]))
		--Length;

	// Return...
	*OutBegin = Begin;
	*OutLength = Length;
}
static inline void FindServerAddress(char const* EmailAddress, size_t EmailAddressLength, size_t* OutBegin, size_t* OutLength)
{
	FindEmailAddress(EmailAddress, EmailAddressLength, OutBegin, OutLength);
	char const* At = reinterpret_cast<char const*>(memchr(EmailAddress + *OutBegin, '@', *OutLength));
	if (At)
	{
		const size_t End = *OutBegin + *OutLength;
		*OutBegin = At + 1 - EmailAddress;
		*OutLength = End - *OutBegin;
	}
}
static inline size_t EncodeBase64GetSize(size_t InLength)
{
	return 4 * ((InLength + 2) / 3);
}
static inline void EncodeBase64(char* OutStr, void const* InPtr, size_t InLength)
{
	static const alignas(64) char Table[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };
	char* OutIter = OutStr;
	unsigned char const* InPtr2 = reinterpret_cast<unsigned char const*>(InPtr);

	// Process bulk input...
	const size_t FastInputLength = (InLength / 3) * 3;
	size_t InputIndex = 0, OutputIndex = 0;
	while (InputIndex < FastInputLength)
	{
        const uint32_t Byte0 = InPtr2[InputIndex++];
        const uint32_t Byte1 = InPtr2[InputIndex++];
        const uint32_t Byte2 = InPtr2[InputIndex++];
		const uint32_t Combined = (Byte0 << 16) + (Byte1 << 8) + Byte2;
        *(OutIter++) = Table[(Combined >> 18) & 0x3F];
        *(OutIter++) = Table[(Combined >> 12) & 0x3F];
        *(OutIter++) = Table[(Combined >> 6) & 0x3F];
        *(OutIter++) = Table[(Combined >> 0) & 0x3F];
    }

	// Process rest...
	switch (InLength - FastInputLength)
	{
		case 2:
			{
				const uint32_t Byte0 = InPtr2[InputIndex++];
				const uint32_t Byte1 = InPtr2[InputIndex++];
				const uint32_t Combined = (Byte0 << 16) + (Byte1 << 8);
				*(OutIter++) = Table[(Combined >> 18) & 0x3F];
				*(OutIter++) = Table[(Combined >> 12) & 0x3F];
				*(OutIter++) = Table[(Combined >> 6) & 0x3F];
				*(OutIter++) = '=';
			}
			break;
		case 1:
			{
				const uint32_t Combined = static_cast<uint32_t>(InPtr2[InputIndex++]) << 16;
				*(OutIter++) = Table[(Combined >> 18) & 0x3F];
				*(OutIter++) = Table[(Combined >> 12) & 0x3F];
				*(OutIter++) = '=';
				*(OutIter++) = '=';
			}
			break;
	}
}

// ##################################################################################################################
// ################ Security helper functions #######################################################################
// ##################################################################################################################
// These functions are very closely resembling the example code from http://www.coastrd.com/c-schannel-smtp
// and the still available versions of that i.e. in the TortoiseGit source code.

static inline SECURITY_STATUS CreateCredentials(SecurityFunctionTableW* SftPtr, CredHandle* CredentialsStructPtr)
{
	// Build Schannel credential structure. Currently, this sample only specifies the protocol to be used
	// (and optionally the certificate, of course). Real applications may wish to specify other parameters as well.
	SCHANNEL_CRED SchannelCred = {};
	SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
	SchannelCred.grbitEnabledProtocols = 0; // SP_PROT_TLS1; // SP_PROT_PCT1; SP_PROT_SSL2; SP_PROT_SSL3; 0=default
	
	//DWORD cSupportedAlgs = 0;
	//ALG_ID rgbSupportedAlgs[16];
	//rgbSupportedAlgs[cSupportedAlgs++] = CALG_DH_EPHEM; CALG_RSA_KEYX;
	//if (cSupportedAlgs)
	//{
	//	SchannelCred.cSupportedAlgs = cSupportedAlgs;
	//	SchannelCred.palgSupportedAlgs = rgbSupportedAlgs;
	//}

	SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;

	// The "SCH_CRED_MANUAL_CRED_VALIDATION" flag is specified because this sample verifies the server certificate manually.
	// Applications that expect to run with WinNT, Win9x, or WinME should specify this flag and also manually verify the server
	// certificate. Applications running with newer versions of Windows can remove this flag, in which case the
	// "InitializeSecurityContext" function will validate the server certificate automatically.
	SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;

	// Create an SSPI credential...
	TimeStamp Expiry;
	const SECURITY_STATUS Status = SftPtr->AcquireCredentialsHandle(nullptr, // Name of principal
		const_cast<wchar_t*>(UNISP_NAME), // Name of package
		SECPKG_CRED_OUTBOUND, // Flags indicating use
		nullptr, // Pointer to login ID
		&SchannelCred, // Package specific data
		nullptr, // Pointer to GetKey() func
		nullptr, // Value to pass to GetKey()
		CredentialsStructPtr, // (out) Cred Handle
		&Expiry); // (out) Lifetime (optional)
	return Status;
}

static inline SECURITY_STATUS ClientHandshakeLoop(SOCKET Socket, SecurityFunctionTableW* SftPtr, CredHandle* CredentialsStructPtr, CtxtHandle* ContextStructPtr, bool DoInitialRead, SecBuffer* ExtraDataPtr)
{
	static constexpr DWORD SSPIFlags = 
		ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	// Allocate data buffer...
	char* IoBuffer = reinterpret_cast<char*>(malloc(IoBufferSize));
	if (!IoBuffer)
		return SEC_E_INSUFFICIENT_MEMORY;
	DWORD IoBufferCount = 0;
	bool DoRead = DoInitialRead;

	// Loop until the handshake is finished or an error occurs...
	SECURITY_STATUS Result = SEC_I_CONTINUE_NEEDED;

	while (Result == SEC_I_CONTINUE_NEEDED || Result == SEC_E_INCOMPLETE_MESSAGE || Result == SEC_I_INCOMPLETE_CREDENTIALS)
	{
		if (0 == IoBufferCount || Result == SEC_E_INCOMPLETE_MESSAGE) // Read data from server.
		{
			if (DoRead)
			{
				const int DataCount = recv(Socket, IoBuffer + IoBufferCount, IoBufferSize - IoBufferCount, 0);
				if (DataCount == SOCKET_ERROR)
				{
					Result = SEC_E_INTERNAL_ERROR;
					break;
				}
				else if (DataCount == 0)
				{
					// printf("**** Server unexpectedly disconnected\n");
					Result = SEC_E_INTERNAL_ERROR;
					break;
				}
				// printf("%d bytes of handshake data received\n", cbData);
				IoBufferCount += DataCount;
			}
			else
				DoRead = true;
		}

		// Set up the input buffers. Buffer 0 is used to pass in data received from the server. Schannel will consume some or all
		// of this. Leftover data (if any) will be placed in buffer 1 and given a buffer type of "SECBUFFER_EXTRA".
		SecBuffer InBuffers[2];
		InBuffers[0].pvBuffer = IoBuffer;
		InBuffers[0].cbBuffer = IoBufferCount;
		InBuffers[0].BufferType = SECBUFFER_TOKEN;
		InBuffers[1].pvBuffer = nullptr;
		InBuffers[1].cbBuffer = 0;
		InBuffers[1].BufferType = SECBUFFER_EMPTY;
		
		SecBufferDesc InBuffer;
		InBuffer.cBuffers = 2;
		InBuffer.pBuffers = InBuffers;
		InBuffer.ulVersion = SECBUFFER_VERSION;

		// Set up the output buffers. These are initialized to nullptr so as to make it less likely we'll attempt to free random garbage later.
		SecBuffer OutBuffers[1];
		OutBuffers[0].pvBuffer = nullptr;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer = 0;

		SecBufferDesc OutBuffer;
		OutBuffer.cBuffers = 1;
		OutBuffer.pBuffers = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;

		// Call "InitializeSecurityContext"...
		DWORD SSPIOutFlags;
		TimeStamp Expiry;
		Result = SftPtr->InitializeSecurityContext(CredentialsStructPtr, ContextStructPtr, nullptr, SSPIFlags, 0, SECURITY_NATIVE_DREP, &InBuffer, 0, nullptr, &OutBuffer, &SSPIOutFlags, &Expiry);

		// If "InitializeSecurityContext" was successful (or if the error was one of the special extended ones),
		// SocketSend the contends of the output buffer to the server.
		if (Result == SEC_E_OK || Result == SEC_I_CONTINUE_NEEDED || FAILED(Result) && (SSPIOutFlags & ISC_RET_EXTENDED_ERROR))
		{
			if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != nullptr)
			{
				const int cbData = send(Socket, reinterpret_cast<char const*>(OutBuffers[0].pvBuffer), OutBuffers[0].cbBuffer, 0);
				if (cbData == SOCKET_ERROR || cbData == 0)
				{
					// printf("**** Error %d SocketSending data to server (2)\n",  WSAGetLastError());
					SftPtr->FreeContextBuffer(OutBuffers[0].pvBuffer);
					SftPtr->DeleteSecurityContext(ContextStructPtr);
					free(IoBuffer);
					return SEC_E_INTERNAL_ERROR;
				}
				// printf("%d bytes of handshake data sent\n", cbData);

				// Free output buffer.
				SftPtr->FreeContextBuffer(OutBuffers[0].pvBuffer);
				OutBuffers[0].pvBuffer = nullptr;
			}
		}

		// If "InitializeSecurityContext" returned "SEC_E_INCOMPLETE_MESSAGE", then we need to read more data from the server and try again.
		if (Result == SEC_E_INCOMPLETE_MESSAGE)
			continue;

		// If "InitializeSecurityContext" returned "SEC_E_OK", then the handshake completed successfully.
		if (Result == SEC_E_OK)
		{
			// If the "extra" buffer contains data, this is encrypted application protocol layer stuff. It needs to be saved.
			// The application layer will later decrypt it with "DecryptMessage". 
			
			//printf("Handshake was successful\n");

			if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
			{
				ExtraDataPtr->pvBuffer = LocalAlloc(LMEM_FIXED, InBuffers[1].cbBuffer);
				if (ExtraDataPtr->pvBuffer == nullptr)
				{
					free(IoBuffer);
					return SEC_E_INSUFFICIENT_MEMORY;
				}

				memmove(ExtraDataPtr->pvBuffer, IoBuffer + (IoBufferCount - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer);

				ExtraDataPtr->cbBuffer = InBuffers[1].cbBuffer;
				ExtraDataPtr->BufferType = SECBUFFER_TOKEN;

				// printf("%d bytes of app data was bundled with handshake data\n", ExtraDataPtr->cbBuffer);
			}
			else
			{
				ExtraDataPtr->pvBuffer = nullptr;
				ExtraDataPtr->cbBuffer = 0;
				ExtraDataPtr->BufferType = SECBUFFER_EMPTY;
			}
			break; // Quit.
		}

		// Check for fatal error...
		if (FAILED(Result))
		{
			// printf("**** Error 0x%x returned by InitializeSecurityContext (2)\n", scRet);
			break;
		}

		// If "InitializeSecurityContext" returned "SEC_I_INCOMPLETE_CREDENTIALS", then the server just requested client authentication.
		if (Result == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			// Busted. The server has requested client authentication and the credential we supplied didn't contain a client certificate.
			// This function will read the list of trusted certificate authorities ("issuers") that was received from the server
			// and attempt to find a usable client certificate that was issued by one of these. If this function is successful,
			// then we will connect using the new certificate. Otherwise, we will attempt to connect anonymously (using our current credentials).
			//GetNewClientCredentials(CredentialsStructPtr, ContextStructPtr);

			// Go around again....
			DoRead = FALSE;
			Result = SEC_I_CONTINUE_NEEDED;
			continue;
		}

		// Copy any leftover data from the "extra" buffer, and go around again...
		if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
		{
			memmove(IoBuffer, IoBuffer + (IoBufferCount - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer);
			IoBufferCount = InBuffers[1].cbBuffer;
		}
		else
			IoBufferCount = 0;
	}

	// Delete the security context in the case of a fatal error...
	if (FAILED(Result))
		SftPtr->DeleteSecurityContext(ContextStructPtr);
	
	free(IoBuffer);
	return Result;
}

static inline SECURITY_STATUS PerformClientHandshake(SOCKET Socket, SecurityFunctionTableW* SftPtr, CredHandle* CredentialsStructPtr, CtxtHandle* ContextStructPtr, char const* ServerName, SecBuffer* ExtraDataPtr)
{
	static constexpr DWORD SSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
	
	// Convert to UTF-16...
    wchar_t Utf16ServerName[DomainNameSizeMax];
	if (!MultiByteToWideChar(CP_UTF8, 0, ServerName, -1, Utf16ServerName, DomainNameSizeMax))
		return GetLastError();

	// Initiate a "ClientHello" message and generate a token...
	SecBuffer OutBuffers[1];
	OutBuffers[0].pvBuffer = nullptr;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;
	
	SecBufferDesc OutBuffer;
	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	DWORD SSPIOutFlags;
	TimeStamp Expiry;
	const SECURITY_STATUS Result = SftPtr->InitializeSecurityContext(CredentialsStructPtr, nullptr, Utf16ServerName, SSPIFlags, 0, SECURITY_NATIVE_DREP, nullptr, 0, ContextStructPtr, &OutBuffer, &SSPIOutFlags, &Expiry);

	if (Result != SEC_I_CONTINUE_NEEDED)
	{
		// printf("**** Error %d returned by InitializeSecurityContext (1)\n", scRet);
		return Result;
	}

	// SocketSend response to server if there is one...
	if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != nullptr)
	{
		const int DataCount = send(Socket, reinterpret_cast<char const*>(OutBuffers[0].pvBuffer), OutBuffers[0].cbBuffer, 0);
		if (DataCount == SOCKET_ERROR || DataCount == 0)
		{
			// printf("**** Error %d SocketSending data to server (1)\n", WSAGetLastError());
			SftPtr->FreeContextBuffer(OutBuffers[0].pvBuffer);
			SftPtr->DeleteSecurityContext(ContextStructPtr);
			return SEC_E_INTERNAL_ERROR;
		}
		// printf("%d bytes of handshake data sent\n", cbData);

		SftPtr->FreeContextBuffer(OutBuffers[0].pvBuffer); // Free output buffer.
		OutBuffers[0].pvBuffer = nullptr;
	}

	return ClientHandshakeLoop(Socket, SftPtr, CredentialsStructPtr, ContextStructPtr, true, ExtraDataPtr);
}

static inline DWORD VerifyServerCertificate(CERT_CONTEXT const* ServerCertPtr, char const* ServerName, DWORD dwCertFlags)
{
	if (ServerCertPtr == nullptr || ServerName == nullptr)
		return (DWORD)SEC_E_WRONG_PRINCIPAL;
	
	// Convert to UTF-16...
    wchar_t Utf16ServerName[DomainNameSizeMax];
	if (!MultiByteToWideChar(CP_UTF8, 0, ServerName, -1, Utf16ServerName, DomainNameSizeMax))
		return GetLastError();

	// Build certificate chain...
	static char const* const Usages[] = { szOID_PKIX_KP_SERVER_AUTH, szOID_SERVER_GATED_CRYPTO, szOID_SGC_NETSCAPE };
	CERT_CHAIN_PARA ChainPara = {};
	ChainPara.cbSize = sizeof(ChainPara);
	ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
	ChainPara.RequestedUsage.Usage.cUsageIdentifier = sizeof(Usages) / sizeof(char const*);
	ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = const_cast<char**>(Usages);
	
	CERT_CHAIN_CONTEXT const* ChainContextPtr = nullptr;
	if (!CertGetCertificateChain(nullptr, ServerCertPtr, nullptr, ServerCertPtr->hCertStore, &ChainPara, 0, nullptr, &ChainContextPtr))
		return GetLastError();

	// Validate certificate chain...
	HTTPSPolicyCallbackData PolicyHttps = {};
	PolicyHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
	PolicyHttps.dwAuthType = AUTHTYPE_SERVER;
	PolicyHttps.fdwChecks = dwCertFlags;
	PolicyHttps.pwszServerName = Utf16ServerName;
	
	CERT_CHAIN_POLICY_PARA PolicyPara = {};
	PolicyPara.cbSize = sizeof(PolicyPara);
	PolicyPara.pvExtraPolicyPara = &PolicyHttps;
	
	CERT_CHAIN_POLICY_STATUS PolicyStatus = {};
	PolicyStatus.cbSize = sizeof(PolicyStatus);

	if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, ChainContextPtr, &PolicyPara, &PolicyStatus))
	{
		const DWORD Status = GetLastError();
		CertFreeCertificateChain(ChainContextPtr);
		return Status;
	}

	if (PolicyStatus.dwError)
	{
		CertFreeCertificateChain(ChainContextPtr);
		return PolicyStatus.dwError;
	}
	
	CertFreeCertificateChain(ChainContextPtr);
	return SEC_E_OK;
}

static inline DWORD EncryptSocketSend(SOCKET Socket, SecurityFunctionTableW* SftPtr, CtxtHandle* ContextStructPtr, BYTE* IoBuffer, SecPkgContext_StreamSizes Sizes)
{
	// http://msdn.microsoft.com/en-us/library/aa375378(VS.85).aspx
	// The encrypted message is encrypted in place, overwriting the original contents of its buffer.

	BYTE* const MessagePtr = IoBuffer + Sizes.cbHeader; // Offset by "header size"
	const DWORD MessageLength = static_cast<DWORD>(strlen(reinterpret_cast<char*>(MessagePtr)));

	// Encrypt the HTTP request...
	SecBuffer Buffers[4];
	Buffers[0].pvBuffer = IoBuffer; // Pointer to buffer 1
	Buffers[0].cbBuffer = Sizes.cbHeader; // length of header
	Buffers[0].BufferType = SECBUFFER_STREAM_HEADER; // Type of the buffer
	Buffers[1].pvBuffer = MessagePtr; // Pointer to buffer 2
	Buffers[1].cbBuffer = MessageLength; // length of the message
	Buffers[1].BufferType = SECBUFFER_DATA; // Type of the buffer
	Buffers[2].pvBuffer = MessagePtr + MessageLength; // Pointer to buffer 3
	Buffers[2].cbBuffer = Sizes.cbTrailer; // length of the trailor
	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER; // Type of the buffer
	Buffers[3].pvBuffer = SECBUFFER_EMPTY; // Pointer to buffer 4
	Buffers[3].cbBuffer = SECBUFFER_EMPTY; // length of buffer 4
	Buffers[3].BufferType = SECBUFFER_EMPTY; // Type of the buffer 4
	
	SecBufferDesc Message;
	Message.ulVersion = SECBUFFER_VERSION; // Version number
	Message.cBuffers = 4; // Number of buffers - must contain four SecBuffer structures.
	Message.pBuffers = Buffers; // Pointer to array of buffers

	const SECURITY_STATUS Result = SftPtr->EncryptMessage(ContextStructPtr, 0, &Message, 0); // must contain four SecBuffer structures.
	if (FAILED(Result))
	{
		// printf("**** Error 0x%x returned by EncryptMessage\n", scRet);
		return Result;
	}

	// SocketSend the encrypted data to the server...
	return send(Socket, reinterpret_cast<char const*>(IoBuffer), Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, 0);
}

static inline SECURITY_STATUS ReadDecrypt(SOCKET Socket, SecurityFunctionTableW* SftPtr, CredHandle* CredentialsStructPtr, CtxtHandle* ContextStructPtr, BYTE* IoBuffer, DWORD IoBufferLength)
{
	// Calls "recv" for blocking socket read. (http://msdn.microsoft.com/en-us/library/ms740121(VS.85).aspx)
	// The encrypted message is decrypted in place, overwriting the original contents of its buffer. (http://msdn.microsoft.com/en-us/library/aa375211(VS.85).aspx)

	// Read data from server until done.
	DWORD IoBufferCount = 0;
	SECURITY_STATUS Result = 0;
	do // Read some data.
	{
		if (IoBufferCount == 0 || Result == SEC_E_INCOMPLETE_MESSAGE) // get the data
		{
			const int DataCount = recv(Socket, reinterpret_cast<char*>(IoBuffer) + IoBufferCount, IoBufferLength - IoBufferCount, 0);
			if (DataCount == SOCKET_ERROR)
			{
				// printf("**** Error %d reading data from server\n", WSAGetLastError());
				Result = SEC_E_INTERNAL_ERROR;
				break;
			}
			else if (DataCount == 0) // Server disconnected.
			{
				if (IoBufferCount)
				{
					// printf("**** Server unexpectedly disconnected\n");
					Result = SEC_E_INTERNAL_ERROR;
					return Result;
				}
				else
					break; // All Done
			}
			else // Success.
			{
				// printf("%d bytes of (encrypted) application data received\n", cbData);
				IoBufferCount += DataCount;
			}
		}

		// Decrypt the received data...
		SecBuffer Buffers[4];
		Buffers[0].pvBuffer = IoBuffer;
		Buffers[0].cbBuffer = IoBufferCount;
		Buffers[0].BufferType = SECBUFFER_DATA;  // Initial Type of the buffer 1
		Buffers[1].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 2
		Buffers[2].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 3
		Buffers[3].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 4
		
		SecBufferDesc Message;
		Message.ulVersion = SECBUFFER_VERSION;    // Version number
		Message.cBuffers = 4;                    // Number of buffers - must contain four SecBuffer structures.
		Message.pBuffers = Buffers;              // Pointer to array of buffers

		Result = SftPtr->DecryptMessage(ContextStructPtr, &Message, 0, nullptr);
		if (Result == SEC_I_CONTEXT_EXPIRED)
			break; // Server signalled end of session
		//if (scRet == SEC_E_INCOMPLETE_MESSAGE - Input buffer has partial encrypted record, read more
		if (Result != SEC_E_OK && Result != SEC_I_RENEGOTIATE && Result != SEC_I_CONTEXT_EXPIRED)
			return Result;

		// Locate data and (optional) extra buffers...
		SecBuffer* DataBufferPtr = nullptr;
		SecBuffer* ExtraBufferPtr = nullptr;
		for (int i = 1; i < 4; ++i)
		{
			if (DataBufferPtr == nullptr && Buffers[i].BufferType == SECBUFFER_DATA)
				DataBufferPtr = &Buffers[i];
			if (ExtraBufferPtr == nullptr && Buffers[i].BufferType == SECBUFFER_EXTRA)
				ExtraBufferPtr = &Buffers[i];
		}

		// Display the decrypted data...
		if (DataBufferPtr)
		{
			const DWORD length = DataBufferPtr->cbBuffer;
			if (length) // check if last two chars are CRLF.
			{
				BYTE* const buff = static_cast<BYTE*>(DataBufferPtr->pvBuffer);
				if (buff[length - 2] == 13 && buff[length - 1] == 10) // Found CRLF.
				{
					buff[length] = 0;
					break;
				}
			}
		}

		// Move any "extra" data to the input buffer...
		if (ExtraBufferPtr)
		{
			memmove(IoBuffer, ExtraBufferPtr->pvBuffer, ExtraBufferPtr->cbBuffer);
			IoBufferCount = ExtraBufferPtr->cbBuffer;
		}
		else
			IoBufferCount = 0;

		// The server wants to perform another handshake sequence...
		if (Result == SEC_I_RENEGOTIATE)
		{
			// printf("Server requested renegotiate!\n");
			SecBuffer ExtraBuffer;
			Result = ClientHandshakeLoop(Socket, SftPtr, CredentialsStructPtr, ContextStructPtr, false, &ExtraBuffer);
			if (Result != SEC_E_OK)
				return Result;

			if (ExtraBuffer.pvBuffer) // Move any "extra" data to the input buffer...
			{
				memmove(IoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
				IoBufferCount = ExtraBuffer.cbBuffer;
			}
		}
	} while(true); // Loop till CRLF is found at the end of the data.

	return SEC_E_OK;
}

static inline LONG SecurityDisconnectFromServer(SOCKET Socket, SecurityFunctionTableW* SftPtr, CredHandle* CredentialsStructPtr, CtxtHandle* ContextStructPtr)
{
	DWORD Type = SCHANNEL_SHUTDOWN; // Notify schannel that we are about to close the connection.
	
	SecBuffer OutBuffers[1];
	OutBuffers[0].pvBuffer = &Type;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = sizeof(Type);
	
	SecBufferDesc OutBuffer;
	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	const SECURITY_STATUS Status = SftPtr->ApplyControlToken(ContextStructPtr, &OutBuffer);
	if (FAILED(Status))
	{
		// printf("**** Error 0x%x returned by ApplyControlToken\n", Status);
		SftPtr->DeleteSecurityContext(ContextStructPtr); // Free the security context.
		return Status;
	}

	// Build an SSL close notify message.
	static constexpr DWORD SSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	OutBuffers[0].pvBuffer = nullptr;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;
	
	DWORD SSPIOutFlags;
	TimeStamp Expiry;
	const SECURITY_STATUS Status2 = SftPtr->InitializeSecurityContext(CredentialsStructPtr, ContextStructPtr, nullptr, SSPIFlags, 0, SECURITY_NATIVE_DREP, nullptr, 0, ContextStructPtr, &OutBuffer, &SSPIOutFlags, &Expiry);
	if (FAILED(Status2))
	{
		// printf("**** Error 0x%x returned by InitializeSecurityContext\n", Status);
		SftPtr->DeleteSecurityContext(ContextStructPtr); // Free the security context.
		return Status2;
	}

	BYTE* const MessagePtr = static_cast<BYTE*>(OutBuffers[0].pvBuffer);
	const DWORD MessageLength = OutBuffers[0].cbBuffer;

	// SocketSend the close notify message to the server.
	if (MessagePtr != nullptr && MessageLength != 0)
	{
		const int cbData = send(Socket, reinterpret_cast<char const*>(MessagePtr), MessageLength, 0);
		if (cbData == SOCKET_ERROR || cbData == 0)
		{
			const SECURITY_STATUS Result = WSAGetLastError();
			SftPtr->DeleteSecurityContext(ContextStructPtr); // Free the security context.
			return Result;
		}
		// printf("SocketSending Close Notify\n");
		// printf("%d bytes of handshake data sent\n", cbData);
		SftPtr->FreeContextBuffer(MessagePtr); // Free output buffer.
	}

	return Status2;
}

// ##################################################################################################################
// ################ Generic socket functions ########################################################################
// ##################################################################################################################
struct Socket
{
	SOCKET SocketHandle = INVALID_SOCKET;
	bool IsEncrypted = false;

	// The next couple variables are used only with encrypted sockets...
	DWORD IoBufferLength = 0;
	BYTE* IoBuffer = nullptr;
	SecurityFunctionTableW* SftPtr = nullptr;
	CtxtHandle ContextStruct = {};
	CredHandle CredentialsStruct = {};
	SecPkgContext_StreamSizes Sizes = {};
};
static inline bool SocketOpen(Socket* This, char* OutErrMsg, size_t ErrMsgCapacity, char const* ServerName, unsigned short Port)
{
    // Initialize Winsock...
	WSADATA WsaDataObj;
    if (const int Result = WSAStartup(MAKEWORD(2, 2), &WsaDataObj))
	{
        snprintf(OutErrMsg, ErrMsgCapacity, "\"WSAStartup\" failed with error code: %i", Result);
        return false;
    }
	
	// Resolve server address...
	char PortStr[16];
	snprintf(PortStr, sizeof(PortStr), "%i", (int)Port);
	addrinfo* ResultAddress;
	addrinfo Hints = {};
	Hints.ai_family = AF_UNSPEC;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_protocol = IPPROTO_TCP;
    if (const int Result = getaddrinfo(ServerName, PortStr, &Hints, &ResultAddress))
	{
        snprintf(OutErrMsg, ErrMsgCapacity, "\"getaddrinfo\" failed with error code: %i", Result);
        WSACleanup();
        return false;
    }

    // Attempt to connect to an address until one succeeds...
    for (addrinfo* Iter = ResultAddress; Iter; Iter = Iter->ai_next)
	{
        // Create a SOCKET for connecting to server...
        This->SocketHandle = socket(Iter->ai_family, Iter->ai_socktype, Iter->ai_protocol);
        if (This->SocketHandle == INVALID_SOCKET)
		{
            printf("socket failed with error: %ld\n", WSAGetLastError());
			freeaddrinfo(ResultAddress);
            WSACleanup();
			return false;
        }

        // Try connecting to server...
        const int Result = connect(This->SocketHandle, Iter->ai_addr, (int)Iter->ai_addrlen);
        if (Result != SOCKET_ERROR)
		{
			freeaddrinfo(ResultAddress);
			return true;
		}
		closesocket(This->SocketHandle);
        This->SocketHandle = INVALID_SOCKET;
    }
    freeaddrinfo(ResultAddress);
    WSACleanup();
	snprintf(OutErrMsg, ErrMsgCapacity, "Unable to connect to any of the addresses found by \"getaddrinfo\".");
	return false;
}
static inline bool SocketStartSecurity(Socket* This, char* OutErrMsg, size_t ErrMsgCapacity, char const* ServerName)
{
	This->SftPtr = InitSecurityInterfaceW();
	if (const SECURITY_STATUS Status = CreateCredentials(This->SftPtr, &This->CredentialsStruct))
	{
		snprintf(OutErrMsg, ErrMsgCapacity, "%s failed with error code: %i.", "CreateCredentials", Status);
		return false;
	}
	This->IsEncrypted = true;
	SecBuffer ExtraData;
	if (const SECURITY_STATUS Status = PerformClientHandshake(This->SocketHandle, This->SftPtr, &This->CredentialsStruct, &This->ContextStruct, ServerName, &ExtraData))
	{
		snprintf(OutErrMsg, ErrMsgCapacity, "%s failed with error code: %i.", "PerformClientHandshake", Status);
		return false;
	}

	// Authenticate server's credentials and get server's certificate...
	CERT_CONTEXT* RemoteCertContextPtr = nullptr;
	if (const SECURITY_STATUS Status = This->SftPtr->QueryContextAttributes(&This->ContextStruct, SECPKG_ATTR_REMOTE_CERT_CONTEXT, static_cast<PVOID>(&RemoteCertContextPtr)))
	{
		snprintf(OutErrMsg, ErrMsgCapacity, "%s failed with error code: %i.", "QueryContextAttributes", Status);
		return false;
	}
	if (const SECURITY_STATUS Status = VerifyServerCertificate(RemoteCertContextPtr, ServerName, 0))
	{
		snprintf(OutErrMsg, ErrMsgCapacity, "%s failed with error code: %i.", "VerifyServerCertificate", Status);
		CertFreeCertificateContext(RemoteCertContextPtr);
		return false;
	}

	// Create a buffer...
	CertFreeCertificateContext(RemoteCertContextPtr);
	if (const SECURITY_STATUS Status = This->SftPtr->QueryContextAttributes(&This->ContextStruct, SECPKG_ATTR_STREAM_SIZES, &This->Sizes))
	{
		snprintf(OutErrMsg, ErrMsgCapacity, "%s failed with error code: %i.", "QueryContextAttributes", Status);
		return false;
	}
	This->IoBufferLength = This->Sizes.cbHeader + This->Sizes.cbMaximumMessage + This->Sizes.cbTrailer;
	This->IoBuffer = static_cast<PBYTE>(LocalAlloc(LMEM_FIXED, This->IoBufferLength));
	if (!This->IoBuffer)
	{
		snprintf(OutErrMsg, ErrMsgCapacity, "Could not allocate memory.");
		return false;
	}
	SecureZeroMemory(This->IoBuffer, This->IoBufferLength);
	return true;
}
static inline bool SocketSend(Socket* This, char* OutErrMsg, size_t ErrMsgCapacity, char const* ToSend, size_t ToSendSize)
{
	if (This->IsEncrypted)
	{
		size_t SentSize = 0;
		while (ToSendSize > SentSize)
		{
			const size_t ThisTimeSize = min(ToSendSize - SentSize, This->Sizes.cbMaximumMessage);
			SecureZeroMemory(This->IoBuffer + This->Sizes.cbHeader, This->Sizes.cbMaximumMessage);
			memcpy(This->IoBuffer + This->Sizes.cbHeader, ToSend + SentSize, ThisTimeSize);
			DWORD cbData = EncryptSocketSend(This->SocketHandle, This->SftPtr, &This->ContextStruct, This->IoBuffer, This->Sizes);
			if (cbData == SOCKET_ERROR || cbData == 0)
			{
				snprintf(OutErrMsg, ErrMsgCapacity, "A socket error occurred.");
				return false;
			}
			SentSize += ThisTimeSize;
		}
	}
	else if (send(This->SocketHandle, ToSend, static_cast<int>(ToSendSize), 0) != ToSendSize)
	{
		snprintf(OutErrMsg, ErrMsgCapacity, "\"SocketSend\" data failed.");
		return false;
	}
#if PRINTF_SERVER_COMMUNICATION
	printf("Sent: %.*s", static_cast<int>(ToSendSize), ToSend);
#endif

	return true;
}
static inline bool SocketSend(Socket* This, char* OutErrMsg, size_t ErrMsgCapacity, char const* ToSend)
{
	return SocketSend(This, OutErrMsg, ErrMsgCapacity, ToSend, strlen(ToSend));
}
static inline bool SocketReceive(Socket* This, char* OutErrMsg, size_t ErrMsgCapacity, char* ReceiveBuffer, size_t ReceiveBufferSize)
{
	if (This->IsEncrypted)
	{
		// TODO This is terrible as theire is no way to figure out how large the received data is.
		const SECURITY_STATUS Status = ReadDecrypt(This->SocketHandle, This->SftPtr, &This->CredentialsStruct, &This->ContextStruct, This->IoBuffer, This->IoBufferLength);
		if (Status != SEC_E_OK)
		{
			snprintf(OutErrMsg, ErrMsgCapacity, "Receiving encrypted data from the socket failed.");
			return false;
		}
		SecureZeroMemory(ReceiveBuffer, ReceiveBufferSize);
		memcpy(ReceiveBuffer, This->IoBuffer + This->Sizes.cbHeader, ReceiveBufferSize - 1);
	}
	else
	{
		const size_t ReceivedCount = recv(This->SocketHandle, ReceiveBuffer, static_cast<int>(ReceiveBufferSize - 1), 0);
		if (ReceivedCount >= ReceiveBufferSize)
		{
			snprintf(OutErrMsg, ErrMsgCapacity, "Receiving data from the socket failed.");
			return false;
		}
		ReceiveBuffer[ReceivedCount] = '\0';
	}
#if PRINTF_SERVER_COMMUNICATION
	printf("Received: %s", ReceiveBuffer);
#endif
	return true;
}
static inline bool SocketGetResponse(Socket* This, char* OutErrMsg, size_t ErrMsgCapacity, char const* ExpectedCode)
{
	const size_t ExpectedCodeLength = strlen(ExpectedCode);
	char ReceiveBuffer[ReceiveBufferSize];
	if (!SocketReceive(This, OutErrMsg, ErrMsgCapacity, ReceiveBuffer, ReceiveBufferSize))
		return false;
	if (memcmp(ReceiveBuffer, ExpectedCode, ExpectedCodeLength) != 0)
	{
		snprintf(OutErrMsg, ErrMsgCapacity, "Received invalid response: %s", ReceiveBuffer);
		return false;
	}
	return true;
}
static inline void SocketClose(Socket* This)
{
	if (This->IsEncrypted)
	{
		if (This->SftPtr)
		{
			SecurityDisconnectFromServer(This->SocketHandle, This->SftPtr, &This->CredentialsStruct, &This->ContextStruct);
			This->SftPtr->DeleteSecurityContext(&This->ContextStruct);
			This->SftPtr->FreeCredentialsHandle(&This->CredentialsStruct);
		}
		if (This->IoBuffer)
		{
			SecureZeroMemory(This->IoBuffer, This->IoBufferLength);
			LocalFree(This->IoBuffer);
		}
	}
	if (This->SocketHandle != INVALID_SOCKET)
	{
		shutdown(This->SocketHandle, SD_BOTH);
		closesocket(This->SocketHandle);
	}
    WSACleanup();
}

// ##################################################################################################################
// ################ Public interface implementation #################################################################
// ##################################################################################################################

size_t TMS_SendEmails(
	char* OutErrMsg,
	size_t ErrMsgCapacity,
	char const* SmtpHostServer,
	unsigned short SmtpHostServerPort,
	TMS_SecurityLevel SecurityLevelVar,
	char const* AuthentificationUserName,
	char const* AuthentificationPassword,
	TMS_Mail const* Mails,
	size_t MailCount)
{
	// Open socket...
	Socket SocketHandle = {};
	if (!SocketOpen(&SocketHandle, OutErrMsg, ErrMsgCapacity, SmtpHostServer, SmtpHostServerPort))
		return 0;

	// Negotiate security...
	bool Encrypt = false;
	if (SecurityLevelVar <= WantTls)
	{
		if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "220"))
			return 0;
		if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, "STARTTLS\r\n"))
			return 0;
		if (SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "220"))
			Encrypt = true;
		else if (SecurityLevelVar == WantTls)
		{
			snprintf(OutErrMsg, ErrMsgCapacity, "Insufficient security by server.");
			return 0;
		}
	}
	else if (SecurityLevelVar == Ssl)
		Encrypt = true;

	// Start security...
	if (Encrypt)
		if (!SocketStartSecurity(&SocketHandle, OutErrMsg, ErrMsgCapacity, SmtpHostServer))
			return SocketClose(&SocketHandle), 0;
	if (SecurityLevelVar <= Ssl)
		if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "220"))
			return SocketClose(&SocketHandle), 0;
	
	// Get host name...
	char HostName[DomainNameSizeMax] = {};
	gethostname(HostName, DomainNameSizeMax - 7);
	if (strchr(HostName, '.') == nullptr) // Make sure "helo" hostname can be interpreted as a FQDN.
		strcat(HostName, ".local");

	// Send welcome message...
	char ServerMessage[SendMessageBufferSize];
	sprintf_s(ServerMessage, "EHLO %s\r\n", HostName);
	if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
		return SocketClose(&SocketHandle), 0;
	if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "250"))
		return SocketClose(&SocketHandle), 0;

	// Authentificate...
	if (AuthentificationUserName && *AuthentificationUserName != '\0')
	{
		if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, "auth login\r\n"))
			return SocketClose(&SocketHandle), 0;
		if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "334"))
			return SocketClose(&SocketHandle), 0;

		// Send user name...
		const size_t AuthentificationUserNameLength = strlen(AuthentificationUserName);
		size_t Base64Size = EncodeBase64GetSize(AuthentificationUserNameLength);
		if (Base64Size > sizeof(ServerMessage) - sizeof("\r\n"))
		{
			snprintf(OutErrMsg, ErrMsgCapacity, "Authentification user name too long to send.");
			return SocketClose(&SocketHandle), 0;
		}
		EncodeBase64(ServerMessage, AuthentificationUserName, AuthentificationUserNameLength);
		strcpy(ServerMessage + Base64Size, "\r\n");
		if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
			return SocketClose(&SocketHandle), 0;
		if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "334"))
			return SocketClose(&SocketHandle), 0;

		// Send password...
		if (AuthentificationPassword && AuthentificationPassword != '\0')
		{
			const size_t AuthentificationPasswordLength = strlen(AuthentificationPassword);
			Base64Size = EncodeBase64GetSize(AuthentificationPasswordLength);
			if (Base64Size > sizeof(ServerMessage) - sizeof("\r\n"))
			{
				snprintf(OutErrMsg, ErrMsgCapacity, "Authentification password too long to send.");
				return SocketClose(&SocketHandle), 0;
			}
			EncodeBase64(ServerMessage, AuthentificationPassword, AuthentificationPasswordLength);
			strcpy(ServerMessage + Base64Size, "\r\n");
			if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
				return SocketClose(&SocketHandle), 0;
			SecureZeroMemory(ServerMessage, AuthentificationPasswordLength);
		}
		else if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, "\r\n"))
				return SocketClose(&SocketHandle), 0;

		// Finish authentification...
		if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "235"))
			return SocketClose(&SocketHandle), 0;
	}
	
	for (size_t i = 0; i < MailCount; ++i)
	{
		TMS_Mail const* MailPtr = Mails + i;

		// Prepare part boundary...
		char PartBoundary[64] = "NextPart_";
		GetGUID(PartBoundary + 9, sizeof(PartBoundary) - 9);
		char MIMEContentType[128];
		if (MailPtr->AttachmentCount == 0)
			strcpy(MIMEContentType, "text/plain\r\nContent-Transfer-Encoding: 8bit");
		else
			snprintf(MIMEContentType, sizeof(MIMEContentType), "multipart/mixed; boundary=%s", PartBoundary);

		// Send head...
		{
			// Send "From"...
			size_t AddressFromBegin, AddressFromLength;
			FindEmailAddress(MailPtr->AddressFrom, strlen(MailPtr->AddressFrom), &AddressFromBegin, &AddressFromLength);
			if (static_cast<size_t>(snprintf(ServerMessage, sizeof(ServerMessage),
				"MAIL From: <%.*s>\r\n", (int)AddressFromLength, MailPtr->AddressFrom + AddressFromBegin) >= sizeof(ServerMessage)))
			{
				snprintf(OutErrMsg, ErrMsgCapacity, "Source address too long to store in message buffer.");
				return SocketClose(&SocketHandle), i;
			}
			if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
				return SocketClose(&SocketHandle), i;
			if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "250"))
				return SocketClose(&SocketHandle), i;

			// Send receivers...
			if (MailPtr->AddressTo && *MailPtr->AddressTo != '\0')
			{
				char const* CurrentAddress = MailPtr->AddressTo;
				char const* SepCharPtr;
				do
				{
					SepCharPtr = strchr(CurrentAddress, ';');
					const size_t SepLength = SepCharPtr == nullptr ? strlen(CurrentAddress) : (SepCharPtr - CurrentAddress);
					size_t CurrentAddressBegin, CurrentAddressLength;
					FindEmailAddress(CurrentAddress, SepLength, &CurrentAddressBegin, &CurrentAddressLength);
					if (static_cast<size_t>(snprintf(ServerMessage, sizeof(ServerMessage),
						"RCPT TO: <%.*s>\r\n", (int)CurrentAddressLength, CurrentAddress + CurrentAddressBegin) >= sizeof(ServerMessage)))
					{
						snprintf(OutErrMsg, ErrMsgCapacity, "Target address too long to store in message buffer.");
						return SocketClose(&SocketHandle), i;
					}
					if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
						return SocketClose(&SocketHandle), i;
					if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "250"))
						return SocketClose(&SocketHandle), i;
					CurrentAddress += SepLength + 1;
				} while(SepCharPtr);
			}

			// Send data begin...
			if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, "DATA\r\n"))
				return SocketClose(&SocketHandle), i;
			if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "354"))
				return SocketClose(&SocketHandle), i;
		}

		// Send header...
		{
			// Prepare "Sender", "To and "CC"...
			char const* EndOfFirstAddressToEntry = strchr(MailPtr->AddressTo, ';');
			if (!EndOfFirstAddressToEntry)
				EndOfFirstAddressToEntry = MailPtr->AddressTo + strlen(MailPtr->AddressTo);

			char const* Sender = MailPtr->MessageField_Sender;
			if (!Sender)
				Sender = MailPtr->AddressFrom;

			char const* To = MailPtr->MessageField_To;
			size_t ToLength = To ? strlen(To) : 0;
			if (!To)
			{
				To = MailPtr->AddressTo;
				ToLength = EndOfFirstAddressToEntry - MailPtr->AddressTo;
			}

			char const* Cc = MailPtr->MessageField_CC;
			if (!Cc)
				Cc = *EndOfFirstAddressToEntry ? EndOfFirstAddressToEntry + 1 : "";

			// Build string...
			char Date[64], MessageID[64];
			FormatDateTime(Date, sizeof(Date), MailPtr->DateTime ? MailPtr->DateTime : time(0));
			GetGUID(MessageID, sizeof(MessageID));
			if (static_cast<size_t>(snprintf(ServerMessage, sizeof(ServerMessage),
				"Date: %s\r\n"
				"From: %s\r\n"
				"CC: %s\r\n"
				"Sender: %s\r\n"
				"To: %.*s\r\n"
				"Subject: %s\r\n"
				"Message-ID: <%s>\r\n"
				"X-Mailer: %s\r\n"
				"MIME-Version: 1.0\r\n"
				"Content-Type: %s\r\n\r\n",
				Date, MailPtr->AddressFrom, Cc, Sender, (int)ToLength, To, MailPtr->Subject,
				MessageID, MailPtr->XMailer ? MailPtr->XMailer : "Unknown", MIMEContentType) >= sizeof(ServerMessage)))
			{
				snprintf(OutErrMsg, ErrMsgCapacity, "Target address, source address, xmailer and subject too long to store in message buffer.");
				return SocketClose(&SocketHandle), i;
			}
			if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
				return SocketClose(&SocketHandle), i;
		}
		if (MailPtr->AttachmentCount)
		{
			snprintf(ServerMessage, sizeof(ServerMessage),
				"This is a multi-part message in MIME format.\r\n"
				"--%s\r\n"
				"Content-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n\r\n", PartBoundary);
			if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
				return SocketClose(&SocketHandle), i;
		}

		// Send body...
		{
			const size_t MessageBodyLength = MailPtr->MessageBody ? strlen(MailPtr->MessageBody) : 0;
			char const* MessageBodyIter = MailPtr->MessageBody;
			char const* MessageBodyEndIter = MailPtr->MessageBody + MessageBodyLength;
			while (MessageBodyIter != MessageBodyEndIter)
			{
				char* ServerMessageIter = ServerMessage;
				char* ServerMessageEndIter = ServerMessage + sizeof(ServerMessage) - 4; 
				while (ServerMessageIter < ServerMessageEndIter && MessageBodyIter < MessageBodyEndIter)
				{
					const char Char = *(MessageBodyIter++);
					*(ServerMessageIter++) = Char;
					if (Char == '\n') // Escape dots between newlines.
						if (strncmp(MessageBodyIter, ".\n", 2) == 0 || strncmp(MessageBodyIter, ".\r\n", 3) == 0)
							*(ServerMessageIter++) = '.';
				}
				if (MessageBodyIter == MessageBodyEndIter) // Add a newline at the end of the message body.
				{
					*(ServerMessageIter++) = '\r';
					*(ServerMessageIter++) = '\n';
				}
				if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage, ServerMessageIter - ServerMessage))
					return SocketClose(&SocketHandle), i;
			}
		}

		// Send attachments...
		for (size_t i = 0; i < MailPtr->AttachmentCount; ++i)
		{
			const TMS_Attachment AttachmentObj = MailPtr->Attachments[i];

			// Send description...
			if (static_cast<size_t>(snprintf(ServerMessage, sizeof(ServerMessage),
				"--%s\r\n"
				"Content-Type: application/octet-stream; file=\"%s\"\r\n"
				"Content-Transfer-Encoding: base64\r\n"
				"Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", PartBoundary, AttachmentObj.Filename, AttachmentObj.Filename)) >= sizeof(ServerMessage))
			{
				snprintf(OutErrMsg, ErrMsgCapacity, "Attachment file name too long to store in message buffer.");
				return SocketClose(&SocketHandle), i;
			}
			if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
				return SocketClose(&SocketHandle), i;

			// Send content...
			size_t InOffset = 0;
			do
			{
				static const size_t Capacity = (((sizeof(ServerMessage) * 3) / 4 - 8) / 3) * 3; // Must be divisible by 3.
				const size_t ProcessCount = min(AttachmentObj.ContentSize - InOffset, Capacity);
				size_t ServerMessageLength = EncodeBase64GetSize(ProcessCount);
				EncodeBase64(ServerMessage, reinterpret_cast<char const*>(AttachmentObj.Content) + InOffset, ProcessCount);
				strcpy(ServerMessage + ServerMessageLength, "\r\n");
				ServerMessageLength += 2;
				InOffset += ProcessCount;
				if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage, ServerMessageLength))
					return SocketClose(&SocketHandle), i;
			} while (InOffset < AttachmentObj.ContentSize);
		}

		// End email...
		if (MailPtr->AttachmentCount)
		{
			snprintf(ServerMessage, sizeof(ServerMessage), "--%s--\r\n", PartBoundary);
			if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ServerMessage))
				return SocketClose(&SocketHandle), i;
		}
		if (!SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, ".\r\n"))
			return SocketClose(&SocketHandle), i;
		if (!SocketGetResponse(&SocketHandle, OutErrMsg, ErrMsgCapacity, "250"))
			return SocketClose(&SocketHandle), i;
	}
	SocketSend(&SocketHandle, OutErrMsg, ErrMsgCapacity, "QUIT\r\n");
	SocketClose(&SocketHandle);
	return MailCount;
}

size_t TMS_SendEmailsDirectlyToTheReceivers(char* OutErrMsg, size_t ErrMsgCapacity, TMS_Mail const* Mails, size_t MailCount)
{
	for (size_t i = 0; i < MailCount; ++i)
	{
		TMS_Mail const* MailPtr = Mails + i;

		// Send out emails...
		bool Result = true;
		size_t ErrMsgSize = 0;
		char const* CurrentEmailAddress = MailPtr->AddressTo;
		char const* SepCharPtr;
		do
		{
			SepCharPtr = strchr(CurrentEmailAddress, ';');
			const size_t SepLength = SepCharPtr == nullptr ? strlen(CurrentEmailAddress) : (SepCharPtr - CurrentEmailAddress);

			// Get target address...
			size_t ServerAddressBegin, ServerAddressLength;
			FindServerAddress(CurrentEmailAddress, SepLength, &ServerAddressBegin, &ServerAddressLength);
			if (!ServerAddressLength)
				continue;
			char ServerAddress[DomainNameSizeMax];
			memcpy(ServerAddress, CurrentEmailAddress + ServerAddressBegin, ServerAddressLength);
			ServerAddress[ServerAddressBegin + ServerAddressLength] = '\0';

			// Get DNS record...
			DNS_RECORD* DnsRecord;
			const DNS_STATUS Status = DnsQuery_UTF8(ServerAddress, DNS_TYPE_MX, DNS_QUERY_STANDARD, nullptr, &DnsRecord, nullptr);
			if (Status)
			{
				const ptrdiff_t MsgLength = snprintf(OutErrMsg + ErrMsgSize, ErrMsgCapacity - ErrMsgSize, "DNS query failed with status code %d.\n", Status);
				if (MsgLength > 0)
					ErrMsgSize += MsgLength;
				Result = false;
				continue;
			}

			// Send to target server(s)...
			DNS_RECORD* NextDnsRecord = DnsRecord;
			while (NextDnsRecord)
			{
				char ServerName[DomainNameSizeMax];
				if (WideCharToMultiByte(CP_UTF8, 0, NextDnsRecord->Data.MX.pNameExchange, -1, ServerName, DomainNameSizeMax, nullptr, nullptr))
					if (NextDnsRecord->wType == DNS_TYPE_MX)
					{
						if (TMS_SendEmails(OutErrMsg + ErrMsgSize, ErrMsgCapacity - ErrMsgSize, ServerName, 25, TMS_SecurityLevel::WantTls, nullptr, nullptr, MailPtr, 1))
							goto SentMail;
						if (ErrMsgCapacity > ErrMsgSize) // Add the size of the new message to the output message size.
							ErrMsgSize += strlen(OutErrMsg + ErrMsgSize);
						if (ErrMsgSize + 2 <= ErrMsgCapacity) // Place new line between messages.
						{
							OutErrMsg[ErrMsgSize++] = '\n';
							OutErrMsg[ErrMsgSize] = '\0';
						}
					}
				NextDnsRecord = NextDnsRecord->pNext;
			}
			Result = false; // If we exit the loop directly all attempts to send the email have failed.
			SentMail:;
			CurrentEmailAddress += SepLength + 1;
		} while(SepCharPtr);
		if (!Result)
			return i;
	}
	return MailCount;
}