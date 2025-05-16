#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186724);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/15");

  script_cve_id(
    "CVE-2020-19185",
    "CVE-2020-19186",
    "CVE-2020-19187",
    "CVE-2020-19188",
    "CVE-2020-19189",
    "CVE-2020-19190",
    "CVE-2023-3618",
    "CVE-2023-38039",
    "CVE-2023-38545",
    "CVE-2023-38546",
    "CVE-2023-40389",
    "CVE-2023-40390",
    "CVE-2023-42842",
    "CVE-2023-42874",
    "CVE-2023-42881",
    "CVE-2023-42882",
    "CVE-2023-42883",
    "CVE-2023-42884",
    "CVE-2023-42886",
    "CVE-2023-42887",
    "CVE-2023-42888",
    "CVE-2023-42890",
    "CVE-2023-42891",
    "CVE-2023-42892",
    "CVE-2023-42893",
    "CVE-2023-42894",
    "CVE-2023-42896",
    "CVE-2023-42898",
    "CVE-2023-42899",
    "CVE-2023-42900",
    "CVE-2023-42901",
    "CVE-2023-42902",
    "CVE-2023-42903",
    "CVE-2023-42904",
    "CVE-2023-42905",
    "CVE-2023-42906",
    "CVE-2023-42907",
    "CVE-2023-42908",
    "CVE-2023-42909",
    "CVE-2023-42910",
    "CVE-2023-42911",
    "CVE-2023-42912",
    "CVE-2023-42913",
    "CVE-2023-42914",
    "CVE-2023-42919",
    "CVE-2023-42922",
    "CVE-2023-42924",
    "CVE-2023-42926",
    "CVE-2023-42930",
    "CVE-2023-42931",
    "CVE-2023-42932",
    "CVE-2023-42936",
    "CVE-2023-42937",
    "CVE-2023-42947",
    "CVE-2023-42950",
    "CVE-2023-42956",
    "CVE-2023-42974",
    "CVE-2023-45866",
    "CVE-2023-5344"
  );
  script_xref(name:"APPLE-SA", value:"HT214036");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");
  script_xref(name:"IAVA", value:"2023-A-0679-S");
  script_xref(name:"IAVA", value:"2024-A-0179-S");
  script_xref(name:"IAVA", value:"2024-A-0275-S");

  script_name(english:"macOS 14.x < 14.2 Multiple Vulnerabilities (HT214036)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 14.x prior to 14.2. It is, therefore, affected by
multiple vulnerabilities:

  - Buffer Overflow vulnerability in one_one_mapping function in progs/dump_entry.c:1373 in ncurses 6.1 allows
    remote attackers to cause a denial of service via crafted command. (CVE-2020-19185)

  - Buffer Overflow vulnerability in _nc_find_entry function in tinfo/comp_hash.c:66 in ncurses 6.1 allows
    remote attackers to cause a denial of service via crafted command. (CVE-2020-19186)

  - Buffer Overflow vulnerability in fmt_entry function in progs/dump_entry.c:1100 in ncurses 6.1 allows
    remote attackers to cause a denial of service via crafted command. (CVE-2020-19187)

  - Buffer Overflow vulnerability in fmt_entry function in progs/dump_entry.c:1116 in ncurses 6.1 allows
    remote attackers to cause a denial of service via crafted command. (CVE-2020-19188)

  - Buffer Overflow vulnerability in postprocess_terminfo function in tinfo/parse_entry.c:997 in ncurses 6.1
    allows remote attackers to cause a denial of service via crafted command. (CVE-2020-19189)

  - Buffer Overflow vulnerability in _nc_find_entry in tinfo/comp_hash.c:70 in ncurses 6.1 allows remote
    attackers to cause a denial of service via crafted command. (CVE-2020-19190)

  - A flaw was found in libtiff. A specially crafted tiff file can lead to a segmentation fault due to a
    buffer overflow in the Fax3Encode function in libtiff/tif_fax3.c, resulting in a denial of service.
    (CVE-2023-3618)

  - When curl retrieves an HTTP response, it stores the incoming headers so that they can be accessed later
    via the libcurl headers API. However, curl did not have a limit in how many or how large headers it would
    accept in a response, allowing a malicious server to stream an endless series of headers and eventually
    cause curl to run out of heap memory. (CVE-2023-38039)

  - This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake. When curl is asked to
    pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting
    done by curl itself, the maximum length that host name can be is 255 bytes. If the host name is detected
    to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due
    to this bug, the local variable that means let the host resolve the name could get the wrong value
    during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target
    buffer instead of copying just the resolved address there. The target buffer being a heap based buffer,
    and the host name coming from the URL that curl has been told to operate with. (CVE-2023-38545)

  - CVE-2023-38545 is a heap-based buffer overflow vulnerability in the SOCKS5 proxy handshake in libcurl and
    curl.  When curl is given a hostname to pass along to a SOCKS5 proxy that is greater than 255 bytes in
    length, it will switch to local name resolution in order to resolve the address before passing it on to
    the SOCKS5 proxy. However, due to a bug introduced in 2020, this local name resolution could fail due to a
    slow SOCKS5 handshake, causing curl to pass on the hostname greater than 255 bytes in length into the
    target buffer, leading to a heap overflow.  The advisory for CVE-2023-38545 gives an example exploitation
    scenario of a malicious HTTPS server redirecting to a specially crafted URL. While it might seem that an
    attacker would need to influence the slowness of the SOCKS5 handshake, the advisory states that server
    latency is likely slow enough to trigger this bug. (CVE-2023-38545)

  - This flaw allows an attacker to insert cookies at will into a running program using libcurl, if the
    specific series of conditions are met. libcurl performs transfers. In its API, an application creates
    easy handles that are the individual handles for single transfers. libcurl provides a function call that
    duplicates en easy handle called
    [curl_easy_duphandle](https://curl.se/libcurl/c/curl_easy_duphandle.html). If a transfer has cookies
    enabled when the handle is duplicated, the cookie-enable state is also cloned - but without cloning the
    actual cookies. If the source handle did not read any cookies from a specific file on disk, the cloned
    version of the handle would instead store the file name as `none` (using the four ASCII letters, no
    quotes). Subsequent use of the cloned handle that does not explicitly set a source to load cookies from
    would then inadvertently load cookies from a file named `none` - if such a file exists and is readable in
    the current directory of the program using libcurl. And if using the correct file format of course.
    (CVE-2023-38546)

  - CVE-2023-38546 is a cookie injection vulnerability in the curl_easy_duphandle(), a function in libcurl
    that duplicates easy handles.  When duplicating an easy handle, if cookies are enabled, the duplicated
    easy handle will not duplicate the cookies themselves, but would instead set the filename to none.'
    Therefore, when the duplicated easy handle is subsequently used, if a source was not set for the cookies,
    libcurl would attempt to load them from the file named none' on the disk.  This vulnerability is rated
    low, as the various conditions required for exploitation are unlikely.  (CVE-2023-38546)

  - The issue was addressed with improved restriction of data container access. This issue is fixed in macOS
    Ventura 13.6.5, macOS Monterey 12.7.4. An app may be able to access sensitive user data. (CVE-2023-40389)

  - A privacy issue was addressed by moving sensitive data to a protected location. This issue is fixed in
    macOS Sonoma 14.2. An app may be able to access user-sensitive data. (CVE-2023-40390)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1. An app may be able
    to access sensitive user data. (CVE-2023-42842)

  - This issue was addressed with improved state management. This issue is fixed in macOS Sonoma 14.2. Secure
    text fields may be displayed via the Accessibility Keyboard when using a physical keyboard.
    (CVE-2023-42874)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.2.
    Processing a file may lead to unexpected app termination or arbitrary code execution. (CVE-2023-42881)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.2.
    Processing an image may lead to arbitrary code execution. (CVE-2023-42882)

  - The issue was addressed with improved memory handling. This issue is fixed in Safari 17.2, macOS Sonoma
    14.2, iOS 17.2 and iPadOS 17.2, watchOS 10.2, tvOS 17.2, iOS 16.7.3 and iPadOS 16.7.3. Processing an image
    may lead to a denial-of-service. (CVE-2023-42883)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Sonoma 14.2, iOS 17.2 and iPadOS 17.2, macOS Ventura 13.6.3, tvOS 17.2, iOS 16.7.3 and iPadOS 16.7.3. An
    app may be able to disclose kernel memory. (CVE-2023-42884)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Sonoma
    14.2, macOS Ventura 13.6.3, macOS Monterey 12.7.2. A user may be able to cause unexpected app termination
    or arbitrary code execution. (CVE-2023-42886)

  - An access issue was addressed with additional sandbox restrictions. This issue is fixed in macOS Ventura
    13.6.4, macOS Sonoma 14.2. An app may be able to read arbitrary files. (CVE-2023-42887)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.7.5 and iPadOS 16.7.5, watchOS
    10.2, macOS Ventura 13.6.4, macOS Sonoma 14.2, macOS Monterey 12.7.3, iOS 17.2 and iPadOS 17.2. Processing
    a maliciously crafted image may result in disclosure of process memory. (CVE-2023-42888)

  - The issue was addressed with improved memory handling. This issue is fixed in Safari 17.2, macOS Sonoma
    14.2, watchOS 10.2, iOS 17.2 and iPadOS 17.2, tvOS 17.2. Processing web content may lead to arbitrary code
    execution. (CVE-2023-42890)

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Sonoma
    14.2, macOS Ventura 13.6.3, macOS Monterey 12.7.2. An app may be able to monitor keystrokes without user
    permission. (CVE-2023-42891)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13.6.3, macOS Sonoma 14.2, macOS Monterey 12.7.2. A local attacker may be able to elevate their
    privileges. (CVE-2023-42892)

  - A permissions issue was addressed by removing vulnerable code and adding additional checks. This issue is
    fixed in macOS Monterey 12.7.2, macOS Ventura 13.6.3, iOS 17.2 and iPadOS 17.2, iOS 16.7.3 and iPadOS
    16.7.3, tvOS 17.2, watchOS 10.2, macOS Sonoma 14.2. An app may be able to access protected user data.
    (CVE-2023-42893)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Sonoma 14.2, macOS Ventura 13.6.3, macOS Monterey 12.7.2. An app may be able to access information about a
    user's contacts. (CVE-2023-42894)

  - An issue was addressed with improved handling of temporary files. This issue is fixed in macOS Monterey
    12.7.2, macOS Ventura 13.6.3, iOS 17.2 and iPadOS 17.2, iOS 16.7.3 and iPadOS 16.7.3, macOS Sonoma 14.2.
    An app may be able to modify protected parts of the file system. (CVE-2023-42896)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.2, watchOS
    10.2, iOS 17.2 and iPadOS 17.2, tvOS 17.2. Processing an image may lead to arbitrary code execution.
    (CVE-2023-42898)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.2, iOS 17.2
    and iPadOS 17.2, watchOS 10.2, macOS Ventura 13.6.3, tvOS 17.2, iOS 16.7.3 and iPadOS 16.7.3, macOS
    Monterey 12.7.2. Processing an image may lead to arbitrary code execution. (CVE-2023-42899)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.2. An app may be able
    to access user-sensitive data. (CVE-2023-42900)

  - Multiple memory corruption issues were addressed with improved input validation. This issue is fixed in
    macOS Sonoma 14.2. Processing a maliciously crafted file may lead to unexpected app termination or
    arbitrary code execution. (CVE-2023-42901, CVE-2023-42902, CVE-2023-42903, CVE-2023-42904, CVE-2023-42905,
    CVE-2023-42906, CVE-2023-42907, CVE-2023-42908, CVE-2023-42909, CVE-2023-42910, CVE-2023-42911,
    CVE-2023-42912, CVE-2023-42926)

  - This issue was addressed through improved state management. This issue is fixed in macOS Sonoma 14.2.
    Remote Login sessions may be able to obtain full disk access permissions. (CVE-2023-42913)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.2, iOS 17.2
    and iPadOS 17.2, watchOS 10.2, macOS Ventura 13.6.3, tvOS 17.2, iOS 16.7.3 and iPadOS 16.7.3, macOS
    Monterey 12.7.2. An app may be able to break out of its sandbox. (CVE-2023-42914)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Sonoma 14.2, iOS 17.2 and iPadOS 17.2, watchOS 10.2, macOS Ventura 13.6.3, iOS 16.7.3 and iPadOS
    16.7.3, macOS Monterey 12.7.2. An app may be able to access sensitive user data. (CVE-2023-42919)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Sonoma 14.2, iOS 17.2 and iPadOS 17.2, macOS Ventura 13.6.3, iOS 16.7.3 and iPadOS 16.7.3, macOS Monterey
    12.7.2. An app may be able to read sensitive location information. (CVE-2023-42922)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.2, macOS Ventura
    13.6.3. An app may be able to access sensitive user data. (CVE-2023-42924)

  - This issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.6.3, macOS Sonoma
    14.2, macOS Monterey 12.7.2. An app may be able to modify protected parts of the file system.
    (CVE-2023-42930)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.6.3, macOS Sonoma
    14.2, macOS Monterey 12.7.2. A process may gain admin privileges without proper authentication.
    (CVE-2023-42931)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.2, macOS Ventura
    13.6.3, macOS Monterey 12.7.2. An app may be able to access protected user data. (CVE-2023-42932)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Monterey 12.7.2, macOS Ventura 13.6.3, iOS 17.2 and iPadOS 17.2, tvOS 17.2, watchOS 10.2, macOS Sonoma
    14.2. An app may be able to access user-sensitive data. (CVE-2023-42936)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    iOS 16.7.5 and iPadOS 16.7.5, watchOS 10.2, macOS Ventura 13.6.4, macOS Sonoma 14.2, macOS Monterey
    12.7.3, iOS 17.2 and iPadOS 17.2. An app may be able to access sensitive user data. (CVE-2023-42937)

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Monterey
    12.7.2, macOS Ventura 13.6.3, iOS 17.2 and iPadOS 17.2, tvOS 17.2, watchOS 10.2, macOS Sonoma 14.2. An app
    may be able to break out of its sandbox. (CVE-2023-42947)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 17.2,
    iOS 17.2 and iPadOS 17.2, tvOS 17.2, watchOS 10.2, macOS Sonoma 14.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2023-42950)

  - The issue was addressed with improved memory handling. This issue is fixed in Safari 17.2, iOS 17.2 and
    iPadOS 17.2, macOS Sonoma 14.2. Processing web content may lead to a denial-of-service. (CVE-2023-42956)

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.7.2,
    macOS Ventura 13.6.3, iOS 17.2 and iPadOS 17.2, iOS 16.7.3 and iPadOS 16.7.3, macOS Sonoma 14.2. An app
    may be able to execute arbitrary code with kernel privileges. (CVE-2023-42974)

  - Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and
    establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of
    HID messages when no user interaction has occurred in the Central role to authorize such access. An
    example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556
    mitigation would have already addressed this Bluetooth HID Hosts issue. (CVE-2023-45866)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1969. (CVE-2023-5344)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214036");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 14.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42950");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:14.0");
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
  { 'fixed_version' : '14.2.0', 'min_version' : '14.0', 'fixed_display' : 'macOS Sonoma 14.2' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
