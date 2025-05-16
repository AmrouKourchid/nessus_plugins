#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173444);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/20");

  script_cve_id(
    "CVE-2014-1745",
    "CVE-2022-43551",
    "CVE-2022-43552",
    "CVE-2023-0049",
    "CVE-2023-0051",
    "CVE-2023-0054",
    "CVE-2023-0288",
    "CVE-2023-0433",
    "CVE-2023-0512",
    "CVE-2023-23514",
    "CVE-2023-23523",
    "CVE-2023-23525",
    "CVE-2023-23526",
    "CVE-2023-23527",
    "CVE-2023-23532",
    "CVE-2023-23533",
    "CVE-2023-23534",
    "CVE-2023-23535",
    "CVE-2023-23536",
    "CVE-2023-23537",
    "CVE-2023-23538",
    "CVE-2023-23542",
    "CVE-2023-23543",
    "CVE-2023-27928",
    "CVE-2023-27929",
    "CVE-2023-27931",
    "CVE-2023-27932",
    "CVE-2023-27933",
    "CVE-2023-27934",
    "CVE-2023-27935",
    "CVE-2023-27936",
    "CVE-2023-27937",
    "CVE-2023-27939",
    "CVE-2023-27941",
    "CVE-2023-27942",
    "CVE-2023-27943",
    "CVE-2023-27944",
    "CVE-2023-27946",
    "CVE-2023-27947",
    "CVE-2023-27948",
    "CVE-2023-27949",
    "CVE-2023-27950",
    "CVE-2023-27951",
    "CVE-2023-27952",
    "CVE-2023-27953",
    "CVE-2023-27954",
    "CVE-2023-27955",
    "CVE-2023-27956",
    "CVE-2023-27957",
    "CVE-2023-27958",
    "CVE-2023-27961",
    "CVE-2023-27962",
    "CVE-2023-27963",
    "CVE-2023-27966",
    "CVE-2023-27968",
    "CVE-2023-27969",
    "CVE-2023-28178",
    "CVE-2023-28179",
    "CVE-2023-28180",
    "CVE-2023-28181",
    "CVE-2023-28182",
    "CVE-2023-28187",
    "CVE-2023-28188",
    "CVE-2023-28189",
    "CVE-2023-28190",
    "CVE-2023-28192",
    "CVE-2023-28195",
    "CVE-2023-28197",
    "CVE-2023-28198",
    "CVE-2023-28199",
    "CVE-2023-28200",
    "CVE-2023-28201",
    "CVE-2023-28209",
    "CVE-2023-28210",
    "CVE-2023-28211",
    "CVE-2023-28212",
    "CVE-2023-28213",
    "CVE-2023-28214",
    "CVE-2023-28215",
    "CVE-2023-32356",
    "CVE-2023-32358",
    "CVE-2023-32362",
    "CVE-2023-32366",
    "CVE-2023-32370",
    "CVE-2023-32378",
    "CVE-2023-32426",
    "CVE-2023-32435",
    "CVE-2023-32436",
    "CVE-2023-40383",
    "CVE-2023-40398",
    "CVE-2023-40433",
    "CVE-2023-41075",
    "CVE-2023-42830",
    "CVE-2023-42862",
    "CVE-2023-42865"
  );
  script_xref(name:"APPLE-SA", value:"HT213670");
  script_xref(name:"IAVA", value:"2023-A-0162-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/14");
  script_xref(name:"IAVA", value:"2024-A-0455-S");

  script_name(english:"macOS 13.x < 13.3 Multiple Vulnerabilities (HT213670)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.3. It is, therefore, affected by
multiple vulnerabilities:

  - Use-after-free vulnerability in the SVG implementation in Blink, as used in Google Chrome before
    35.0.1916.114, allows remote attackers to cause a denial of service or possibly have unspecified other
    impact via vectors that trigger removal of an SVGFontFaceElement object, related to
    core/svg/SVGFontFaceElement.cpp. (CVE-2014-1745)

  - A vulnerability exists in curl <7.87.0 HSTS check that could be bypassed to trick it to keep using HTTP.
    Using its HSTS support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP
    step even when HTTP is provided in the URL. However, the HSTS mechanism could be bypassed if the host name
    in the given URL first uses IDN characters that get replaced to ASCII counterparts as part of the IDN
    conversion. Like using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full
    stop (U+002E) `.`. Then in a subsequent request, it does not detect the HSTS state and makes a clear text
    transfer. Because it would store the info IDN encoded but look for it IDN decoded. (CVE-2022-43551)

  - A use after free vulnerability exists in curl <7.87.0. Curl can be asked to *tunnel* virtually all
    protocols it supports through an HTTP proxy. HTTP proxies can (and often do) deny such tunnel operations.
    When getting denied to tunnel the specific protocols SMB or TELNET, curl would use a heap-allocated struct
    after it had been freed, in its transfer shutdown code path. (CVE-2022-43552)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143. (CVE-2023-0049)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1144. (CVE-2023-0051)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1145. (CVE-2023-0054)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1189. (CVE-2023-0288)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1225. (CVE-2023-0433)

  - Divide By Zero in GitHub repository vim/vim prior to 9.0.1247. (CVE-2023-0512)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13.3, macOS Monterey 12.6.4, iOS 16.3.1 and iPadOS 16.3.1, macOS Ventura 13.2.1, macOS Big Sur 11.7.5. An
    app may be able to execute arbitrary code with kernel privileges. (CVE-2023-23514)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Ventura 13.3, iOS
    16.4 and iPadOS 16.4. Photos belonging to the Hidden Photos Album could be viewed without authentication
    through Visual Lookup. (CVE-2023-23523)

  - This issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, iOS 16.4 and
    iPadOS 16.4, macOS Big Sur 11.7.5. An app may be able to gain root privileges. (CVE-2023-23525)

  - This was addressed with additional checks by Gatekeeper on files downloaded from an iCloud shared-by-me
    folder. This issue is fixed in macOS Ventura 13.3, iOS 16.4 and iPadOS 16.4. A file from an iCloud shared-
    by-me folder may be able to bypass Gatekeeper. (CVE-2023-23526)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, iOS 16.4 and
    iPadOS 16.4, macOS Big Sur 11.7.5, macOS Monterey 12.6.4, tvOS 16.4, watchOS 9.4. A user may gain access
    to protected parts of the file system. (CVE-2023-23527)

  - This issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, iOS 16.4 and
    iPadOS 16.4, iOS 15.7.6 and iPadOS 15.7.6. An app may be able to break out of its sandbox.
    (CVE-2023-23532)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, macOS
    Monterey 12.6.4. An app may be able to modify protected parts of the file system. (CVE-2023-23533,
    CVE-2023-23538)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, macOS Big Sur
    11.7.5. Processing a maliciously crafted image may result in disclosure of process memory.
    (CVE-2023-23534)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.3, iOS 16.4
    and iPadOS 16.4, macOS Big Sur 11.7.5, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.6, tvOS 16.4,
    watchOS 9.4. Processing a maliciously crafted image may result in disclosure of process memory.
    (CVE-2023-23535)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Ventura 13.3, iOS 16.4
    and iPadOS 16.4, macOS Big Sur 11.7.5, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4, tvOS 16.4,
    watchOS 9.4. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-23536)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.3, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, watchOS 9.4, macOS Big Sur
    11.7.5. An app may be able to read sensitive location information. (CVE-2023-23537)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.3, macOS Monterey 12.6.4, macOS Big Sur 11.7.5. An app may be able to access user-
    sensitive data. (CVE-2023-23542)

  - The issue was addressed with additional restrictions on the observability of app states. This issue is
    fixed in macOS Ventura 13.3, iOS 15.7.4 and iPadOS 15.7.4, iOS 16.4 and iPadOS 16.4, watchOS 9.4. A
    sandboxed app may be able to determine which app is currently using the camera. (CVE-2023-23543)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.3, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, tvOS 16.4, watchOS 9.4, macOS
    Big Sur 11.7.5. An app may be able to access information about a user's contacts. (CVE-2023-27928)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.3, tvOS 16.4, iOS 16.4 and iPadOS 16.4, watchOS 9.4. Processing a maliciously crafted image may result
    in disclosure of process memory. (CVE-2023-27929)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Ventura 13.3, macOS
    Monterey 12.6.3, iOS 16.4 and iPadOS 16.4, macOS Big Sur 11.7.3, tvOS 16.4, watchOS 9.4. An app may be
    able to access user-sensitive data. (CVE-2023-27931)

  - This issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.3, Safari
    16.4, iOS 16.4 and iPadOS 16.4, tvOS 16.4, watchOS 9.4. Processing maliciously crafted web content may
    bypass Same Origin Policy. (CVE-2023-27932)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.3, iOS 16.4
    and iPadOS 16.4, macOS Monterey 12.6.4, tvOS 16.4, watchOS 9.4. An app with root privileges may be able to
    execute arbitrary code with kernel privileges. (CVE-2023-27933)

  - A memory initialization issue was addressed. This issue is fixed in macOS Ventura 13.3, macOS Monterey
    12.6.4. A remote attacker may be able to cause unexpected app termination or arbitrary code execution.
    (CVE-2023-27934)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Ventura 13.3, macOS
    Monterey 12.6.4, macOS Big Sur 11.7.5. A remote user may be able to cause unexpected app termination or
    arbitrary code execution. (CVE-2023-27935)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS
    Ventura 13.3, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4, macOS Big Sur 11.7.5. An app may be
    able to cause unexpected system termination or write kernel memory. (CVE-2023-27936)

  - An integer overflow was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.3, iOS 16.4 and iPadOS 16.4, macOS Big Sur 11.7.5, macOS Monterey 12.6.4, tvOS 16.4, watchOS 9.4.
    Parsing a maliciously crafted plist may lead to an unexpected app termination or arbitrary code execution.
    (CVE-2023-27937)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.3. Processing an image may result in disclosure of process memory. (CVE-2023-27939, CVE-2023-27947,
    CVE-2023-27948, CVE-2023-27950)

  - A validation issue was addressed with improved input sanitization. This issue is fixed in macOS Ventura
    13.3, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4, macOS Big Sur 11.7.5. An app may be able to
    disclose kernel memory. (CVE-2023-27941, CVE-2023-28200)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, iOS 16.4 and
    iPadOS 16.4, macOS Big Sur 11.7.5, macOS Monterey 12.6.4, tvOS 16.4, watchOS 9.4. An app may be able to
    access user-sensitive data. (CVE-2023-27942)

  - This issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, iOS 16.4 and
    iPadOS 16.4. Files downloaded from the internet may not have the quarantine flag applied. (CVE-2023-27943)

  - This issue was addressed with a new entitlement. This issue is fixed in macOS Ventura 13.3, macOS Monterey
    12.6.4, macOS Big Sur 11.7.5. An app may be able to break out of its sandbox. (CVE-2023-27944)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Ventura
    13.3, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4, macOS Big Sur 11.7.5. Processing a maliciously
    crafted file may lead to unexpected app termination or arbitrary code execution. (CVE-2023-27946)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.3, macOS Monterey 12.6.4, iOS 15.7.4 and iPadOS 15.7.4. Processing a maliciously crafted file may lead
    to unexpected app termination or arbitrary code execution. (CVE-2023-27949)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, macOS Monterey
    12.6.4, macOS Big Sur 11.7.5. An archive may be able to bypass Gatekeeper. (CVE-2023-27951)

  - A race condition was addressed with improved locking. This issue is fixed in macOS Ventura 13.3. An app
    may bypass Gatekeeper checks. (CVE-2023-27952)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.3, macOS
    Monterey 12.6.4, macOS Big Sur 11.7.5. A remote user may be able to cause unexpected system termination or
    corrupt kernel memory. (CVE-2023-27953, CVE-2023-27958)

  - The issue was addressed by removing origin information. This issue is fixed in macOS Ventura 13.3, Safari
    16.4, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, tvOS 16.4, watchOS 9.4. A website may be
    able to track sensitive user information. (CVE-2023-27954)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, iOS 16.4 and
    iPadOS 16.4, macOS Monterey 12.6.4, tvOS 16.4, macOS Big Sur 11.7.5. An app may be able to read arbitrary
    files. (CVE-2023-27955)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.3, iOS 16.4
    and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, tvOS 16.4, watchOS 9.4. Processing a maliciously crafted
    image may result in disclosure of process memory. (CVE-2023-27956)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Ventura
    13.3. Processing a maliciously crafted file may lead to unexpected app termination or arbitrary code
    execution. (CVE-2023-27957)

  - Multiple validation issues were addressed with improved input sanitization. This issue is fixed in macOS
    Ventura 13.3, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4, watchOS 9.4,
    macOS Big Sur 11.7.5. Importing a maliciously crafted calendar invitation may exfiltrate user information.
    (CVE-2023-27961)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, macOS
    Monterey 12.6.4, macOS Big Sur 11.7.5. An app may be able to modify protected parts of the file system.
    (CVE-2023-27962)

  - The issue was addressed with additional permissions checks. This issue is fixed in macOS Ventura 13.3, iOS
    16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4, tvOS 16.4, watchOS 9.4. A
    shortcut may be able to use sensitive data with certain actions without prompting the user.
    (CVE-2023-27963)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3. An app may be
    able to break out of its sandbox. (CVE-2023-27966)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Ventura
    13.3. An app may be able to cause unexpected system termination or write kernel memory. (CVE-2023-27968,
    CVE-2023-28209, CVE-2023-28210, CVE-2023-28211, CVE-2023-28212, CVE-2023-28213, CVE-2023-28214,
    CVE-2023-28215, CVE-2023-32356)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13.3, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, tvOS 16.4, watchOS 9.4. An app may be able
    to execute arbitrary code with kernel privileges. (CVE-2023-27969)

  - A logic issue was addressed with improved validation. This issue is fixed in macOS Ventura 13.3, iOS 16.4
    and iPadOS 16.4, macOS Monterey 12.6.4, tvOS 16.4, watchOS 9.4. An app may be able to bypass Privacy
    preferences. (CVE-2023-28178)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.3.
    Processing a maliciously crafted AppleScript binary may result in unexpected app termination or disclosure
    of process memory. (CVE-2023-28179)

  - A denial-of-service issue was addressed with improved memory handling. This issue is fixed in macOS
    Ventura 13.3. A user in a privileged network position may be able to cause a denial-of-service.
    (CVE-2023-28180)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.3, iOS 16.4
    and iPadOS 16.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Monterey 12.6.4, macOS Big Sur 11.7.7, tvOS 16.4,
    watchOS 9.4. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-28181)

  - The issue was addressed with improved authentication. This issue is fixed in macOS Ventura 13.3, iOS 16.4
    and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4, macOS Big Sur 11.7.5. A user in a
    privileged network position may be able to spoof a VPN server that is configured with EAP-only
    authentication on a device. (CVE-2023-28182)

  - This issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.3. A user
    may be able to cause a denial-of-service. (CVE-2023-28187)

  - A denial-of-service issue was addressed with improved input validation. This issue is fixed in macOS
    Ventura 13.3. A remote user may be able to cause a denial-of-service. (CVE-2023-28188)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3, macOS Monterey
    12.6.4, macOS Big Sur 11.7.5. An app may be able to view sensitive information. (CVE-2023-28189)

  - A privacy issue was addressed by moving sensitive data to a more secure location. This issue is fixed in
    macOS Ventura 13.3. An app may be able to access user-sensitive data. (CVE-2023-28190)

  - A permissions issue was addressed with improved validation. This issue is fixed in macOS Ventura 13.3,
    macOS Monterey 12.6.4, macOS Big Sur 11.7.5. An app may be able to read sensitive location information.
    (CVE-2023-28192)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.3. An app may be able to read sensitive location information. (CVE-2023-28195)

  - An access issue was addressed with additional sandbox restrictions. This issue is fixed in macOS Ventura
    13.3, macOS Big Sur 11.7.5, macOS Monterey 12.6.4. An app may be able to access user-sensitive data.
    (CVE-2023-28197)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 16.4 and
    iPadOS 16.4, macOS Ventura 13.3. Processing web content may lead to arbitrary code execution.
    (CVE-2023-28198)

  - An out-of-bounds read issue existed that led to the disclosure of kernel memory. This was addressed with
    improved input validation. This issue is fixed in macOS Ventura 13.3. An app may be able to disclose
    kernel memory. (CVE-2023-28199)

  - This issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.3, Safari
    16.4, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, tvOS 16.4. A remote user may be able to
    cause unexpected app termination or arbitrary code execution. (CVE-2023-28201)

  - A type confusion issue was addressed with improved checks. This issue is fixed in iOS 16.4 and iPadOS
    16.4, macOS Ventura 13.3. Processing web content may lead to arbitrary code execution. (CVE-2023-32358)

  - Error handling was changed to not reveal sensitive information. This issue is fixed in macOS Ventura 13.3.
    A website may be able to track sensitive user information. (CVE-2023-32362)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS
    Big Sur 11.7.5, macOS Ventura 13.3, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey
    12.6.4. Processing a font file may lead to arbitrary code execution. (CVE-2023-32366)

  - A logic issue was addressed with improved validation. This issue is fixed in macOS Ventura 13.3. Content
    Security Policy to block domains with wildcards may fail. (CVE-2023-32370)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13.3, macOS Big Sur 11.7.5, macOS Monterey 12.6.4. An app may be able to execute arbitrary code with
    kernel privileges. (CVE-2023-32378)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3. An app may be
    able to gain root privileges. (CVE-2023-32426)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in macOS
    Ventura 13.3, Safari 16.4, iOS 16.4 and iPadOS 16.4, iOS 15.7.7 and iPadOS 15.7.7. Processing web content
    may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively
    exploited against versions of iOS released before iOS 15.7. (CVE-2023-32435)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Ventura 13.3. An app may
    be able to cause unexpected system termination or write kernel memory. (CVE-2023-32436)

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Ventura 13.3.
    An app may be able to access user-sensitive data. (CVE-2023-40383)

  - This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.4, macOS Big Sur
    11.7.5, macOS Ventura 13.3, iOS 16.4 and iPadOS 16.4. A sandboxed process may be able to circumvent
    sandbox restrictions. (CVE-2023-40398)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.3. An app may
    bypass Gatekeeper checks. (CVE-2023-40433)

  - A type confusion issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.7.5,
    macOS Ventura 13.3, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4. An app
    may be able to execute arbitrary code with kernel privileges. (CVE-2023-41075)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.3, iOS 16.4 and iPadOS 16.4. An app may be able to read sensitive location information.
    (CVE-2023-42830)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.3, tvOS 16.4, iOS 16.4 and iPadOS 16.4, watchOS 9.4. Processing an image may result in disclosure of
    process memory. (CVE-2023-42862, CVE-2023-42865)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213670");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1745");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28201");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:13.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '13.3.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.3' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
