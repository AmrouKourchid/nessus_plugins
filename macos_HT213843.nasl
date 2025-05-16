#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178753);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/13");

  script_cve_id(
    "CVE-2022-3970",
    "CVE-2023-1801",
    "CVE-2023-1916",
    "CVE-2023-2426",
    "CVE-2023-2609",
    "CVE-2023-2610",
    "CVE-2023-28200",
    "CVE-2023-28319",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322",
    "CVE-2023-29491",
    "CVE-2023-2953",
    "CVE-2023-32364",
    "CVE-2023-32381",
    "CVE-2023-32416",
    "CVE-2023-32418",
    "CVE-2023-32429",
    "CVE-2023-32433",
    "CVE-2023-32441",
    "CVE-2023-32442",
    "CVE-2023-32443",
    "CVE-2023-32444",
    "CVE-2023-32445",
    "CVE-2023-32654",
    "CVE-2023-32734",
    "CVE-2023-34241",
    "CVE-2023-34425",
    "CVE-2023-35983",
    "CVE-2023-35993",
    "CVE-2023-36495",
    "CVE-2023-36854",
    "CVE-2023-36862",
    "CVE-2023-37285",
    "CVE-2023-37450",
    "CVE-2023-38133",
    "CVE-2023-38258",
    "CVE-2023-38259",
    "CVE-2023-38261",
    "CVE-2023-38410",
    "CVE-2023-38421",
    "CVE-2023-38424",
    "CVE-2023-38425",
    "CVE-2023-38564",
    "CVE-2023-38565",
    "CVE-2023-38571",
    "CVE-2023-38572",
    "CVE-2023-38580",
    "CVE-2023-38590",
    "CVE-2023-38592",
    "CVE-2023-38593",
    "CVE-2023-38594",
    "CVE-2023-38595",
    "CVE-2023-38597",
    "CVE-2023-38598",
    "CVE-2023-38599",
    "CVE-2023-38600",
    "CVE-2023-38601",
    "CVE-2023-38602",
    "CVE-2023-38603",
    "CVE-2023-38604",
    "CVE-2023-38605",
    "CVE-2023-38606",
    "CVE-2023-38608",
    "CVE-2023-38609",
    "CVE-2023-38611",
    "CVE-2023-38616",
    "CVE-2023-40392",
    "CVE-2023-40397",
    "CVE-2023-40437",
    "CVE-2023-40439",
    "CVE-2023-40440",
    "CVE-2023-42828",
    "CVE-2023-42829",
    "CVE-2023-42831",
    "CVE-2023-42832",
    "CVE-2023-42866"
  );
  script_xref(name:"APPLE-SA", value:"HT213843");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/16");
  script_xref(name:"IAVA", value:"2023-A-0381-S");
  script_xref(name:"IAVA", value:"2023-A-0468-S");

  script_name(english:"macOS 13.x < 13.5 Multiple Vulnerabilities (HT213843)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.5. It is, therefore, affected by
multiple vulnerabilities:

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    iOS 16.6 and iPadOS 16.6, macOS Ventura 13.5. An app may be able to read sensitive location information.
    (CVE-2023-40437, CVE-2023-40439)

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Ventura 13.5. An
    app may be able to execute arbitrary code with kernel privileges. (CVE-2023-38616)

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 9.6, macOS Monterey
    12.6.8, iOS 15.7.8 and iPadOS 15.7.8, macOS Big Sur 11.7.9, iOS 16.6 and iPadOS 16.6, macOS Ventura 13.5.
    An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-34425)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    macOS Ventura 13.5, watchOS 9.6. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-38580)

  - A downgrade issue affecting Intel-based Mac computers was addressed with additional code-signing
    restrictions. This issue is fixed in macOS Ventura 13.5. An app may be able to determine a user's current
    location. (CVE-2023-36862)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Ventura 13.5. A
    sandboxed process may be able to circumvent sandbox restrictions. (CVE-2023-32364)

  - This issue was addressed with improved data protection. This issue is fixed in macOS Monterey 12.6.8,
    macOS Ventura 13.5, macOS Big Sur 11.7.9. An app may be able to modify protected parts of the file system.
    (CVE-2023-35983)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.5. An app may be able to read sensitive location information. (CVE-2023-40392)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Ventura 13.5. An
    app may be able to gain root privileges. (CVE-2023-42828)

  - OpenPrinting CUPS is a standards-based, open source printing system for Linux and other Unix-like
    operating systems. Starting in version 2.0.0 and prior to version 2.4.6, CUPS logs data of free memory to
    the logging service AFTER the connection has been closed, when it should have logged the data right
    before. This is a use-after-free bug that impacts the entire cupsd process. The exact cause of this issue
    is the function `httpClose(con->http)` being called in `scheduler/client.c`. The problem is that httpClose
    always, provided its argument is not null, frees the pointer at the end of the call, only for
    cupsdLogClient to pass the pointer to httpGetHostname. This issue happens in function `cupsdAcceptClient`
    if LogLevel is warn or higher and in two scenarios: there is a double-lookup for the IP Address
    (HostNameLookups Double is set in `cupsd.conf`) which fails to resolve, or if CUPS is compiled with TCP
    wrappers and the connection is refused by rules from `/etc/hosts.allow` and `/etc/hosts.deny`. Version
    2.4.6 has a patch for this issue. (CVE-2023-34241)

  - A use after free vulnerability exists in curl <v8.1.0 in the way libcurl offers a feature to verify an SSH
    server's public key using a SHA 256 hash. When this check fails, libcurl would free the memory for the
    fingerprint before it returns an error message containing the (now freed) hash. This flaw risks inserting
    sensitive heap-based data into the error message that might be shown to users or otherwise get leaked and
    revealed. (CVE-2023-28319)

  - A denial of service vulnerability exists in curl <v8.1.0 in the way libcurl provides several different
    backends for resolving host names, selected at build time. If it is built to use the synchronous resolver,
    it allows name resolves to time-out slow operations using `alarm()` and `siglongjmp()`. When doing this,
    libcurl used a global buffer that was not mutex protected and a multi-threaded application might therefore
    crash or otherwise misbehave. (CVE-2023-28320)

  - An improper certificate validation vulnerability exists in curl <v8.1.0 in the way it supports matching of
    wildcard patterns when listed as Subject Alternative Name in TLS server certificates. curl can be built
    to use its own name matching function for TLS rather than one provided by a TLS library. This private
    wildcard matching function would match IDN (International Domain Name) hosts incorrectly and could as a
    result accept patterns that otherwise should mismatch. IDN hostnames are converted to puny code before
    used for certificate checks. Puny coded names always start with `xn--` and should not be allowed to
    pattern match, but the wildcard check in curl could still check for `x*`, which would match even though
    the IDN name most likely contained nothing even resembling an `x`. (CVE-2023-28321)

  - An information disclosure vulnerability exists in curl <v8.1.0 when doing HTTP(S) transfers, libcurl might
    erroneously use the read callback (`CURLOPT_READFUNCTION`) to ask for data to send, even when the
    `CURLOPT_POSTFIELDS` option has been set, if the same handle previously wasused to issue a `PUT` request
    which used that callback. This flaw may surprise the application and cause it to misbehave and either send
    off the wrong data or use memory after free or similar in the second transfer. The problem exists in the
    logic for a reused handle when it is (expected to be) changed from a PUT to a POST. (CVE-2023-28322)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.6.8, iOS
    15.7.8 and iPadOS 15.7.8, iOS 16.6 and iPadOS 16.6, macOS Ventura 13.5, watchOS 9.6. An app may be able to
    read sensitive location information. (CVE-2023-32416)

  - The issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.8, macOS Ventura
    13.5, macOS Big Sur 11.7.9. Processing a file may lead to unexpected app termination or arbitrary code
    execution. (CVE-2023-32418, CVE-2023-36854)

  - A vulnerability was found in LibTIFF. It has been classified as critical. This affects the function
    TIFFReadRGBATileExt of the file libtiff/tif_getimage.c. The manipulation leads to integer overflow. It is
    possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.
    The name of the patch is 227500897dfb07fb7d27f7aa570050e62617e3be. It is recommended to apply a patch to
    fix this issue. The identifier VDB-213549 was assigned to this vulnerability. (CVE-2022-3970)

  - A validation issue was addressed with improved input sanitization. This issue is fixed in macOS Ventura
    13.3, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.4, macOS Big Sur 11.7.5. An app may be able to
    disclose kernel memory. (CVE-2023-28200)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in watchOS 9.6,
    macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, tvOS 16.6, iOS 16.6 and iPadOS
    16.6, macOS Ventura 13.5. A remote user may be able to cause unexpected system termination or corrupt
    kernel memory. (CVE-2023-38590)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.6,
    macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, tvOS 16.6, iOS 16.6 and iPadOS
    16.6, macOS Ventura 13.5. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-38598)

  - An integer overflow was addressed with improved input validation. This issue is fixed in watchOS 9.6,
    macOS Monterey 12.6.8, iOS 15.7.8 and iPadOS 15.7.8, tvOS 16.6, iOS 16.6 and iPadOS 16.6, macOS Ventura
    13.5. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-36495)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in iOS 15.7.8 and
    iPadOS 15.7.8, macOS Big Sur 11.7.9, macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to
    execute arbitrary code with kernel privileges. (CVE-2023-37285)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in watchOS
    9.6, macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, tvOS 16.6, iOS 16.6 and
    iPadOS 16.6, macOS Ventura 13.5. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-38604)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.8, iOS
    15.7.8 and iPadOS 15.7.8, iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5,
    watchOS 9.6. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-32441)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    tvOS 16.6, macOS Ventura 13.5, watchOS 9.6. An app may be able to execute arbitrary code with kernel
    privileges. (CVE-2023-32734)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    macOS Ventura 13.5. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-38261,
    CVE-2023-38424, CVE-2023-38425)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.6.8, iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5, watchOS
    9.6. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-32381)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.6.8, iOS 15.7.8 and iPadOS 15.7.8, iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Big Sur 11.7.9,
    macOS Ventura 13.5, watchOS 9.6. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-32433, CVE-2023-35993)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, macOS
    Ventura 13.5. A user may be able to elevate privileges. (CVE-2023-38410)

  - This issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.6.8, iOS
    15.7.8 and iPadOS 15.7.8, iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5,
    watchOS 9.6. An app may be able to modify sensitive kernel state. Apple is aware of a report that this
    issue may have been actively exploited against versions of iOS released before iOS 15.7.1.
    (CVE-2023-38606)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, macOS
    Ventura 13.5. A remote user may be able to cause a denial-of-service. (CVE-2023-38603)

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Monterey
    12.6.8, iOS 16.6 and iPadOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5, watchOS 9.6. An app may be
    able to gain root privileges. (CVE-2023-38565)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.8, iOS 16.6
    and iPadOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5, watchOS 9.6. An app may be able to cause a
    denial-of-service. (CVE-2023-38593)

  - This issue was addressed with improved state management of S/MIME encrypted emails. This issue is fixed in
    macOS Monterey 12.6.8. A S/MIME encrypted email may be inadvertently sent unencrypted. (CVE-2023-40440)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.5, macOS Monterey
    12.6.8. Processing a 3D model may result in disclosure of process memory. (CVE-2023-38258, CVE-2023-38421)

  - A flaw was found in tiffcrop, a program distributed by the libtiff package. A specially crafted tiff file
    can lead to an out-of-bounds read in the extractImageSection function in tools/tiffcrop.c, resulting in a
    denial of service and limited information disclosure. This issue affects libtiff versions 4.x.
    (CVE-2023-1916)

  - This issue was addressed with improved validation of symlinks. This issue is fixed in macOS Big Sur
    11.7.9, macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to bypass Privacy preferences.
    (CVE-2023-38571)

  - ncurses before 6.4 20230408, when used by a setuid application, allows local users to trigger security-
    relevant memory corruption via malformed data in a terminfo database file that is found in $HOME/.terminfo
    or reached via the TERMINFO or TERM environment variable. (CVE-2023-29491)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Big Sur 11.7.9,
    macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to modify protected parts of the file
    system. (CVE-2023-38601)

  - A logic issue was addressed with improved validation. This issue is fixed in macOS Big Sur 11.7.9, macOS
    Monterey 12.6.8, macOS Ventura 13.5. A sandboxed process may be able to circumvent sandbox restrictions.
    (CVE-2023-32444)

  - A vulnerability was found in openldap. This security flaw causes a null pointer dereference in
    ber_memalloc_x() function. (CVE-2023-2953)

  - The issue was addressed with additional restrictions on the observability of app states. This issue is
    fixed in macOS Big Sur 11.7.9, macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to access SSH
    passphrases. (CVE-2023-42829)

  - An injection issue was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.5. An app may be able to bypass certain Privacy preferences. (CVE-2023-38609)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.6.8,
    macOS Ventura 13.5, macOS Big Sur 11.7.9. An app may be able to access user-sensitive data.
    (CVE-2023-38259)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.5. An app may be
    able to modify protected parts of the file system. (CVE-2023-38564)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Monterey
    12.6.8, macOS Ventura 13.5, macOS Big Sur 11.7.9. An app may be able to modify protected parts of the file
    system. (CVE-2023-38602)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Big Sur 11.7.9, iOS
    15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to fingerprint the
    user. (CVE-2023-42831)

  - An access issue was addressed with improved access restrictions. This issue is fixed in macOS Ventura
    13.5, macOS Monterey 12.6.8. A shortcut may be able to modify sensitive Shortcuts app settings.
    (CVE-2023-32442)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Monterey
    12.6.8, macOS Ventura 13.5, macOS Big Sur 11.7.9. Processing a file may lead to a denial-of-service or
    potentially disclose memory contents. (CVE-2023-32443)

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Big Sur 11.7.9,
    macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to gain root privileges. (CVE-2023-42832)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.5. An app may be
    able to bypass Privacy preferences. (CVE-2023-32429)

  - The SMB protocol decoder in tcpdump version 4.99.3 can perform an out-of-bounds write when decoding a
    crafted network packet. (CVE-2023-1801)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.5. A
    user may be able to read information belonging to another user. (CVE-2023-32654)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 9.0.1499. (CVE-2023-2426)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.1531. (CVE-2023-2609)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.1532. (CVE-2023-2610)

  - The issue was addressed with additional permissions checks. This issue is fixed in macOS Ventura 13.5. An
    app may be able to access user-sensitive data. (CVE-2023-38608)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Ventura 13.5. An app may be able to determine a user's current location. (CVE-2023-38605)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.5. A remote attacker
    may be able to cause arbitrary javascript code execution. (CVE-2023-40397)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. A website may be able to
    bypass Same Origin Policy. (CVE-2023-38572)

  - A logic issue was addressed with improved state management. This issue is fixed in Safari 16.6, watchOS
    9.6, iOS 15.7.8 and iPadOS 15.7.8, tvOS 16.6, iOS 16.6 and iPadOS 16.6, macOS Ventura 13.5. A website may
    be able to track sensitive user information. (CVE-2023-38599)

  - This issue was addressed with improved checks. This issue is fixed in Safari 16.6, watchOS 9.6, iOS 15.7.8
    and iPadOS 15.7.8, tvOS 16.6, iOS 16.6 and iPadOS 16.6, macOS Ventura 13.5. Processing a document may lead
    to a cross site scripting attack. (CVE-2023-32445)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    watchOS 9.6, tvOS 16.6, macOS Ventura 13.5. Processing web content may lead to arbitrary code execution.
    (CVE-2023-38592)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may
    lead to arbitrary code execution. (CVE-2023-38594)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, tvOS 16.6,
    macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may lead to arbitrary code execution.
    (CVE-2023-38595, CVE-2023-38600)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may lead to arbitrary code
    execution. (CVE-2023-38611)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, Safari
    16.5.2, tvOS 16.6, macOS Ventura 13.5, watchOS 9.6. Processing web content may lead to arbitrary code
    execution. Apple is aware of a report that this issue may have been actively exploited. (CVE-2023-37450)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.5, iOS 16.6
    and iPadOS 16.6, tvOS 16.6, Safari 16.6, watchOS 9.6. Processing web content may lead to arbitrary code
    execution. (CVE-2023-42866)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, macOS Ventura 13.5, Safari 16.6. Processing web content may lead to arbitrary code
    execution. (CVE-2023-38597)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may
    disclose sensitive information. (CVE-2023-38133)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213843");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42866");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-40397");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/24");

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
  { 'fixed_version' : '13.5.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.5' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
