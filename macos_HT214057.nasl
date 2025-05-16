#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189303);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id(
    "CVE-2023-38039",
    "CVE-2023-38545",
    "CVE-2023-38546",
    "CVE-2023-42888",
    "CVE-2023-42937",
    "CVE-2024-23207",
    "CVE-2024-23212",
    "CVE-2024-23222",
    "CVE-2024-27791"
  );
  script_xref(name:"APPLE-SA", value:"HT214057");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/13");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");
  script_xref(name:"IAVA", value:"2024-A-0050-S");

  script_name(english:"macOS 12.x < 12.7.3 Multiple Vulnerabilities (HT214057)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.7.3. It is, therefore, affected by
multiple vulnerabilities:

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    iOS 16.7.5 and iPadOS 16.7.5, watchOS 10.2, macOS Ventura 13.6.4, macOS Sonoma 14.2, macOS Monterey
    12.7.3, iOS 17.2 and iPadOS 17.2. An app may be able to access sensitive user data. (CVE-2023-42937)

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 10.3, tvOS 17.3, iOS
    17.3 and iPadOS 17.3, macOS Sonoma 14.3, iOS 16.7.5 and iPadOS 16.7.5, macOS Ventura 13.6.4, macOS
    Monterey 12.7.3. An app may be able to execute arbitrary code with kernel privileges. (CVE-2024-23212)

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

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.7.5 and iPadOS 16.7.5, watchOS
    10.2, macOS Ventura 13.6.4, macOS Sonoma 14.2, macOS Monterey 12.7.3, iOS 17.2 and iPadOS 17.2. Processing
    a maliciously crafted image may result in disclosure of process memory. (CVE-2023-42888)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in watchOS
    10.3, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3, macOS Ventura 13.6.4, macOS Monterey 12.7.3. An app may
    be able to access sensitive user data. (CVE-2024-23207)

  - The issue was addressed with improved checks. This issue is fixed in iOS 17.3 and iPadOS 17.3, tvOS 17.3,
    macOS Ventura 13.6.4, iOS 16.7.5 and iPadOS 16.7.5, macOS Monterey 12.7.3, macOS Sonoma 14.3. An app may
    be able to corrupt coprocessor memory. (CVE-2024-27791)

  - A type confusion issue was addressed with improved checks. This issue is fixed in iOS 17.3 and iPadOS
    17.3, macOS Sonoma 14.3, tvOS 17.3. Processing maliciously crafted web content may lead to arbitrary code
    execution. Apple is aware of a report that this issue may have been exploited. (CVE-2024-23222)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214057");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23222");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '12.7.3', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.7.3' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
