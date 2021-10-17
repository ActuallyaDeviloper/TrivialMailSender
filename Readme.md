# TrivialMailSender

This is C/C++ code with an extremely simple C interface that can send emails from Windows using a secured
connection and the SMTP protocol. It can optionally also send attached files. All string parameters use UTF-8.
Only standard operating system components are used that are available since Windows NT/ME times so this
is very portable and lightweight if you only support the Windows platform.
 
Figuring out how to send emails though the SMTP protocol and especially the Windows securty API was not easy.
This would not have been possible without the great example implementation from
http://www.coastrd.com/c-schannel-smtp which unfortunately seems to no longer be available these days. Luckily
other projects built upon that code so they were a massive help including TortoiseGit's version
https://github.com/TortoiseGit/TortoiseGit/blob/master/src/Utils/HwSMTP.cpp and the following translation to
Delphi https://github.com/tothpaul/Delphi/blob/master/TLSClient/TLSclient.dpr.

For general information about SMTP emails see for example these resources:
 - https://www.ietf.org/rfc/rfc2821.txt
 - https://www.ietf.org/rfc/rfc2822.txt
 - https://www.atmail.com/blog/smtp-101-manual-smtp-sessions.
 - https://en.wikipedia.org/wiki/MIME

Compared to TortoiseGit/original example code the structure of the code has been drastically simplified
and many bugs and idiosyncracies were resolved in the process. This implementation also completely avoids
the MFC/AFX/ATL dependency. Now only the Windows standard header functions are needed. Many string allocations
and conversions between UTF-16 and UTF-8 are avoided too.
The code is "essentially C" meaning that it is not actually compilable as C code right now
but it would be trivial to do that with minor adjustments. The header should be usable from pure C code.