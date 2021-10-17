// This is C/C++ code with an extremely simple C interface that can send emails from Windows using a secured
// connection and the SMTP protocol. It can optionally also send attached files. All string parameters use UTF-8.
// Only standard operating system components are used that are available since Windows NT/ME times so this
// is very portable and lightweight if you only support the Windows platform.
// 
// Figuring out how to send emails though the SMTP protocol and especially the Windows securty API was not easy.
// This would not have been possible without the great example implementation from
// http://www.coastrd.com/c-schannel-smtp which unfortunately seems to no longer be available these days. Luckily
// other projects built upon that code so they were a massive help including TortoiseGit's version
// https://github.com/TortoiseGit/TortoiseGit/blob/master/src/Utils/HwSMTP.cpp and the following translation to
// Delphi https://github.com/tothpaul/Delphi/blob/master/TLSClient/TLSclient.dpr.
//
// For general information about SMTP emails see for example these resources:
//  - https://www.ietf.org/rfc/rfc2821.txt
//  - https://www.ietf.org/rfc/rfc2822.txt
//  - https://www.atmail.com/blog/smtp-101-manual-smtp-sessions.
//  - https://en.wikipedia.org/wiki/MIME
//
// Compared to TortoiseGit/original example code the structure of the code has been drastically simplified
// and many bugs and idiosyncracies were resolved in the process. This implementation also completely avoids
// the MFC/AFX/ATL dependency. Now only the Windows standard header functions are needed. Many string allocations
// and conversions between UTF-16 and UTF-8 are avoided too.
// The code is "essentially C" meaning that it is not actually compilable as C code right now
// but it would be trivial to do that with minor adjustments. The header should be usable from pure C code.

#pragma once

#include <stddef.h>
#include <stdint.h>



enum TMS_SecurityLevel
{
	None,
	WantTls,
	Ssl
};

struct TMS_Attachment
{
	char const* Filename;
	void const* Content;
	size_t ContentSize;
};

struct TMS_Mail
{
	// The source email address. Optionally a name may be included by using the "Name <EmailAddress>"
	// or "EmailAddress (Name)" format optionally including separating whitespaces.
	char const* AddressFrom;
	// The target email addresses separated by ;. Optionally a name may be included by using the "Name <EmailAddress>"
	// or "EmailAddress (Name)" format optionally including separating whitespaces.
	char const* AddressTo;
	char const* Subject;
	char const* MessageBody;
	struct TMS_Attachment* Attachments;
	size_t AttachmentCount;

	// The date and time the email is sent. This can be 0 to automatically fill in the current date/time.
	// This is the same format as "time_t" which is POSIX time (the number of seconds without leap seconds since 00:00, Jan 1 1970 UTC).
	uint64_t DateTime;
	// The email program name used to send this email.
	// This can be "nullptr" in which case "Unknown" will be used as the program name.
	char const* XMailer;
	// This is ONLY for the email message itself and independent of "AddressFrom".
	// This can be set to "nullptr" to automatically use the same as "AddressFrom".
	char const* MessageField_Sender;
	// This is ONLY for the email message itself and independent of "AddressFrom".
	// This can be set to "nullptr" to automatically use the same as the first entry of "AddressTo".
	char const* MessageField_To;
	// This is ONLY for the email message itself and independent of "AddressFrom".
	// This can be set to "nullptr" to automatically use the same as the entries after the first of "AddressTo".
	// Note that you can set this to an empty string to hide all further recipients after the first and thus implementing BCC semantics.
	char const* MessageField_CC;
};

// This function sends an email to a single SMTP server potentially after authentification.
// This returns how many emails have been sent sequentially from the "Mails" array until all emails were
// sent or an error occurred. "OutErrMsg" is not touched if no error occurs. If no emails are specified,
// the connection is opened still to check if the server responds correctly.
size_t TMS_SendEmails(
	char* OutErrMsg,
	size_t ErrMsgCapacity,
	char const* SmtpHostServer,
	unsigned short SmtpHostServerPort,
	TMS_SecurityLevel SecurityLevelVar,
	char const* AuthentificationUserName, // Can be empty or "nullptr" to login without authentification.
	char const* AuthentificationPassword,
	TMS_Mail const* Mails,
	size_t MailCount);

// This function sends emails directly to the receiving SMTP servers. Please note that this is problematic
// because many servers will block unauthenficated accesses especially from dynamic IP ranges to prevent
// spam email.
// This returns how many emails have been sent sequentially from the "Mails" array until all emails were
// sent or an error occurred. "OutErrMsg" is not touched if no error occurs.
// All error messages that occur ith the receivers of a single failing mail will be concatenated.
size_t TMS_SendEmailsDirectlyToTheReceivers(char* OutErrMsg, size_t ErrMsgCapacity, struct TMS_Mail const* Mails, size_t MailCount);
