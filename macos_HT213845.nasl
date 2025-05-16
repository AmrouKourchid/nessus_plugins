#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178754);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2023-1801",
    "CVE-2023-2426",
    "CVE-2023-2609",
    "CVE-2023-2610",
    "CVE-2023-28319",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322",
    "CVE-2023-29491",
    "CVE-2023-2953",
    "CVE-2023-32364",
    "CVE-2023-32381",
    "CVE-2023-32418",
    "CVE-2023-32422",
    "CVE-2023-32429",
    "CVE-2023-32433",
    "CVE-2023-32441",
    "CVE-2023-32443",
    "CVE-2023-32444",
    "CVE-2023-34241",
    "CVE-2023-34425",
    "CVE-2023-35983",
    "CVE-2023-35993",
    "CVE-2023-36854",
    "CVE-2023-37285",
    "CVE-2023-38259",
    "CVE-2023-38565",
    "CVE-2023-38571",
    "CVE-2023-38590",
    "CVE-2023-38593",
    "CVE-2023-38598",
    "CVE-2023-38601",
    "CVE-2023-38602",
    "CVE-2023-38603",
    "CVE-2023-38604",
    "CVE-2023-38606",
    "CVE-2023-40392",
    "CVE-2023-40442",
    "CVE-2023-41990",
    "CVE-2023-42829",
    "CVE-2023-42831",
    "CVE-2023-42832"
  );
  script_xref(name:"APPLE-SA", value:"HT213845");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/16");
  script_xref(name:"IAVA", value:"2023-A-0381-S");
  script_xref(name:"IAVA", value:"2023-A-0468-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/01/29");

  script_name(english:"macOS 11.x < 11.7.9 Multiple Vulnerabilities (HT213845)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.7.9. It is, therefore, affected by
multiple vulnerabilities:

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8. An app may be able to read
    sensitive location information. (CVE-2023-40442)

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 9.6, macOS Monterey
    12.6.8, iOS 15.7.8 and iPadOS 15.7.8, macOS Big Sur 11.7.9, iOS 16.6 and iPadOS 16.6, macOS Ventura 13.5.
    An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-34425)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Ventura 13.5. A
    sandboxed process may be able to circumvent sandbox restrictions. (CVE-2023-32364)

  - This issue was addressed with improved data protection. This issue is fixed in macOS Monterey 12.6.8,
    macOS Ventura 13.5, macOS Big Sur 11.7.9. An app may be able to modify protected parts of the file system.
    (CVE-2023-35983)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.5. An app may be able to read sensitive location information. (CVE-2023-40392)

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

  - The issue was addressed with improved handling of caches. This issue is fixed in tvOS 16.3, iOS 16.3 and
    iPadOS 16.3, macOS Monterey 12.6.8, macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Ventura
    13.2, watchOS 9.3. Processing a font file may lead to arbitrary code execution. Apple is aware of a report
    that this issue may have been actively exploited against versions of iOS released before iOS 15.7.1.
    (CVE-2023-41990)

  - The issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.8, macOS Ventura
    13.5, macOS Big Sur 11.7.9. Processing a file may lead to unexpected app termination or arbitrary code
    execution. (CVE-2023-32418, CVE-2023-36854)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.6.8, iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5, watchOS
    9.6. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-32381)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.6.8, iOS 15.7.8 and iPadOS 15.7.8, iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Big Sur 11.7.9,
    macOS Ventura 13.5, watchOS 9.6. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-32433, CVE-2023-35993)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, macOS
    Ventura 13.5. A remote user may be able to cause a denial-of-service. (CVE-2023-38603)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in watchOS 9.6,
    macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, tvOS 16.6, iOS 16.6 and iPadOS
    16.6, macOS Ventura 13.5. A remote user may be able to cause unexpected system termination or corrupt
    kernel memory. (CVE-2023-38590)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.6,
    macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, tvOS 16.6, iOS 16.6 and iPadOS
    16.6, macOS Ventura 13.5. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-38598)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in iOS 15.7.8 and
    iPadOS 15.7.8, macOS Big Sur 11.7.9, macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to
    execute arbitrary code with kernel privileges. (CVE-2023-37285)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in watchOS
    9.6, macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, tvOS 16.6, iOS 16.6 and
    iPadOS 16.6, macOS Ventura 13.5. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-38604)

  - This issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.6.8, iOS
    15.7.8 and iPadOS 15.7.8, iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5,
    watchOS 9.6. An app may be able to modify sensitive kernel state. Apple is aware of a report that this
    issue may have been actively exploited against versions of iOS released before iOS 15.7.1.
    (CVE-2023-38606)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.8, iOS
    15.7.8 and iPadOS 15.7.8, iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5,
    watchOS 9.6. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-32441)

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Monterey
    12.6.8, iOS 16.6 and iPadOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5, watchOS 9.6. An app may be
    able to gain root privileges. (CVE-2023-38565)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.8, iOS 16.6
    and iPadOS 16.6, macOS Big Sur 11.7.9, macOS Ventura 13.5, watchOS 9.6. An app may be able to cause a
    denial-of-service. (CVE-2023-38593)

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

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.6.8,
    macOS Ventura 13.5, macOS Big Sur 11.7.9. An app may be able to access user-sensitive data.
    (CVE-2023-38259)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Monterey
    12.6.8, macOS Ventura 13.5, macOS Big Sur 11.7.9. An app may be able to modify protected parts of the file
    system. (CVE-2023-38602)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Big Sur 11.7.9, iOS
    15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to fingerprint the
    user. (CVE-2023-42831)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Monterey
    12.6.8, macOS Ventura 13.5, macOS Big Sur 11.7.9. Processing a file may lead to a denial-of-service or
    potentially disclose memory contents. (CVE-2023-32443)

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Big Sur 11.7.9,
    macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to gain root privileges. (CVE-2023-42832)

  - This issue was addressed by adding additional SQLite logging restrictions. This issue is fixed in iOS 16.5
    and iPadOS 16.5, tvOS 16.5, macOS Ventura 13.4. An app may be able to bypass Privacy preferences.
    (CVE-2023-32422)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.5. An app may be
    able to bypass Privacy preferences. (CVE-2023-32429)

  - The SMB protocol decoder in tcpdump version 4.99.3 can perform an out-of-bounds write when decoding a
    crafted network packet. (CVE-2023-1801)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 9.0.1499. (CVE-2023-2426)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.1531. (CVE-2023-2609)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.1532. (CVE-2023-2610)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213845");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.7.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:11.0");
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
  { 'fixed_version' : '11.7.9', 'min_version' : '11.0', 'fixed_display' : 'macOS Big Sur 11.7.9' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
