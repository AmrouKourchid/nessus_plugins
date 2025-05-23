#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168697);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/23");

  script_cve_id(
    "CVE-2022-24836",
    "CVE-2022-29181",
    "CVE-2022-32919",
    "CVE-2022-32942",
    "CVE-2022-32943",
    "CVE-2022-35252",
    "CVE-2022-42837",
    "CVE-2022-42839",
    "CVE-2022-42840",
    "CVE-2022-42841",
    "CVE-2022-42842",
    "CVE-2022-42843",
    "CVE-2022-42845",
    "CVE-2022-42847",
    "CVE-2022-42852",
    "CVE-2022-42853",
    "CVE-2022-42854",
    "CVE-2022-42855",
    "CVE-2022-42856",
    "CVE-2022-42858",
    "CVE-2022-42859",
    "CVE-2022-42861",
    "CVE-2022-42862",
    "CVE-2022-42863",
    "CVE-2022-42864",
    "CVE-2022-42865",
    "CVE-2022-42866",
    "CVE-2022-42867",
    "CVE-2022-46689",
    "CVE-2022-46690",
    "CVE-2022-46691",
    "CVE-2022-46692",
    "CVE-2022-46693",
    "CVE-2022-46695",
    "CVE-2022-46696",
    "CVE-2022-46697",
    "CVE-2022-46698",
    "CVE-2022-46699",
    "CVE-2022-46700",
    "CVE-2022-46701",
    "CVE-2022-46703",
    "CVE-2022-46704",
    "CVE-2022-46705",
    "CVE-2022-46710",
    "CVE-2022-46716",
    "CVE-2022-46718",
    "CVE-2022-46720",
    "CVE-2022-46725",
    "CVE-2022-48618"
  );
  script_xref(name:"APPLE-SA", value:"HT213532");
  script_xref(name:"IAVA", value:"2022-A-0524-S");
  script_xref(name:"IAVA", value:"2023-A-0645");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/21");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/04");
  script_xref(name:"IAVA", value:"2024-A-0050-S");

  script_name(english:"macOS 13.x < 13.1 Multiple Vulnerabilities (HT213532)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.1. It is, therefore, affected by
multiple vulnerabilities:

  - Nokogiri is an open source XML and HTML library for Ruby. Nokogiri `< v1.13.4` contains an inefficient
    regular expression that is susceptible to excessive backtracking when attempting to detect encoding in
    HTML documents. Users are advised to upgrade to Nokogiri `>= 1.13.4`. There are no known workarounds for
    this issue. (CVE-2022-24836)

  - Nokogiri is an open source XML and HTML library for Ruby. Nokogiri prior to version 1.13.6 does not type-
    check all inputs into the XML and HTML4 SAX parsers, allowing specially crafted untrusted inputs to cause
    illegal memory access errors (segfault) or reads from unrelated memory. Version 1.13.6 contains a patch
    for this issue. As a workaround, ensure the untrusted input is a `String` by calling `#to_s` or
    equivalent. (CVE-2022-29181)

  - The issue was addressed with improved UI handling. This issue is fixed in iOS 16.2 and iPadOS 16.2, macOS
    Ventura 13.1. Visiting a website that frames malicious content may lead to UI spoofing. (CVE-2022-32919)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.2, macOS
    Ventura 13.1, macOS Big Sur 11.7.2. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-32942)

  - The issue was addressed with improved bounds checks. This issue is fixed in iOS 16.2 and iPadOS 16.2,
    macOS Ventura 13.1. Shake-to-undo may allow a deleted photo to be re-surfaced without authentication.
    (CVE-2022-32943)

  - When curl is used to retrieve and parse cookies from a HTTP(S) server, itaccepts cookies using control
    codes that when later are sent back to a HTTPserver might make the server return 400 responses.
    Effectively allowing asister site to deny service to all siblings. (CVE-2022-35252)

  - An issue existed in the parsing of URLs. This issue was addressed with improved input validation. This
    issue is fixed in iOS 16.2 and iPadOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, watchOS 9.2.
    A remote user may be able to cause unexpected app termination or arbitrary code execution.
    (CVE-2022-42837)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in iOS 16.2
    and iPadOS 16.2, macOS Ventura 13.1. An app may be able to read sensitive location information.
    (CVE-2022-42839)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.2, macOS
    Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2. An app may be
    able to execute arbitrary code with kernel privileges. (CVE-2022-42840)

  - A type confusion issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.2,
    macOS Ventura 13.1, macOS Big Sur 11.7.2. Processing a maliciously crafted package may lead to arbitrary
    code execution. (CVE-2022-42841)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 16.2, macOS Monterey
    12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. A remote user may
    be able to cause kernel code execution. (CVE-2022-42842)

  - This issue was addressed with improved data protection. This issue is fixed in iOS 16.2 and iPadOS 16.2,
    macOS Ventura 13.1, tvOS 16.2, watchOS 9.2. A user may be able to view sensitive user information.
    (CVE-2022-42843)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 16.2, macOS Monterey
    12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app with root
    privileges may be able to execute arbitrary code with kernel privileges. (CVE-2022-42845)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS
    Ventura 13.1. An app may be able to execute arbitrary code with kernel privileges. (CVE-2022-42847)

  - The issue was addressed with improved memory handling. This issue is fixed in Safari 16.2, tvOS 16.2,
    macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing
    maliciously crafted web content may result in the disclosure of process memory. (CVE-2022-42852)

  - An access issue was addressed with improved access restrictions. This issue is fixed in macOS Ventura
    13.1. An app may be able to modify protected parts of the file system. (CVE-2022-42853)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.2, macOS
    Ventura 13.1. An app may be able to disclose kernel memory. (CVE-2022-42854)

  - A logic issue was addressed with improved state management. This issue is fixed in tvOS 16.2, macOS
    Monterey 12.6.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2. An app may be
    able to use arbitrary entitlements. (CVE-2022-42855)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in Safari 16.2,
    tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.1.2. Processing maliciously crafted
    web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been
    actively exploited against versions of iOS released before iOS 15.1.. (CVE-2022-42856)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in macOS
    Ventura 13.1. An app may be able to execute arbitrary code with kernel privileges (CVE-2022-42858)

  - Multiple issues were addressed by removing the vulnerable code. This issue is fixed in iOS 16.2 and iPadOS
    16.2, macOS Ventura 13.1, watchOS 9.2. An app may be able to bypass Privacy preferences. (CVE-2022-42859)

  - This issue was addressed with improved checks. This issue is fixed in iOS 16.2 and iPadOS 16.2, macOS
    Monterey 12.6.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2. An app may be able to break out of its
    sandbox. (CVE-2022-42861)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in iOS 16.2 and iPadOS 16.2,
    macOS Ventura 13.1. An app may be able to bypass Privacy preferences. (CVE-2022-42862)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2022-42863, CVE-2022-46699)

  - A race condition was addressed with improved state handling. This issue is fixed in tvOS 16.2, macOS
    Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and
    iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-42864)

  - This issue was addressed by enabling hardened runtime. This issue is fixed in iOS 16.2 and iPadOS 16.2,
    macOS Ventura 13.1, tvOS 16.2, watchOS 9.2. An app may be able to bypass Privacy preferences.
    (CVE-2022-42865)

  - The issue was addressed with improved handling of caches. This issue is fixed in iOS 16.2 and iPadOS 16.2,
    macOS Ventura 13.1, tvOS 16.2, watchOS 9.2. An app may be able to read sensitive location information.
    (CVE-2022-42866)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 16.2,
    tvOS 16.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-42867)

  - A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS
    Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and
    iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-46689)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in iOS 16.2
    and iPadOS 16.2, macOS Ventura 13.1, tvOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code
    with kernel privileges. (CVE-2022-46690)

  - A memory consumption issue was addressed with improved memory handling. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-46691)

  - A logic issue was addressed with improved state management. This issue is fixed in Safari 16.2, tvOS 16.2,
    iCloud for Windows 14.1, iOS 15.7.2 and iPadOS 15.7.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2,
    watchOS 9.2. Processing maliciously crafted web content may bypass Same Origin Policy. (CVE-2022-46692)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in tvOS
    16.2, iCloud for Windows 14.1, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing a
    maliciously crafted file may lead to arbitrary code execution. (CVE-2022-46693)

  - A spoofing issue existed in the handling of URLs. This issue was addressed with improved input validation.
    This issue is fixed in tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS
    16.2, watchOS 9.2. Visiting a website that frames malicious content may lead to UI spoofing.
    (CVE-2022-46695)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2022-46696)

  - An out-of-bounds access issue was addressed with improved bounds checking. This issue is fixed in macOS
    Ventura 13.1. An app may be able to execute arbitrary code with kernel privileges. (CVE-2022-46697)

  - A logic issue was addressed with improved checks. This issue is fixed in Safari 16.2, tvOS 16.2, iCloud
    for Windows 14.1, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously
    crafted web content may disclose sensitive user information. (CVE-2022-46698)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-46700)

  - The issue was addressed with improved bounds checks. This issue is fixed in iOS 16.2 and iPadOS 16.2,
    macOS Ventura 13.1, tvOS 16.2. Connecting to a malicious NFS server may lead to arbitrary code execution
    with kernel privileges. (CVE-2022-46701)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 15.7.2 and iPadOS
    15.7.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2. An app may be able to read sensitive location
    information (CVE-2022-46703)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.1,
    macOS Big Sur 11.7.2, macOS Monterey 12.6.2. An app may be able to modify protected parts of the file
    system. (CVE-2022-46704)

  - A spoofing issue existed in the handling of URLs. This issue was addressed with improved input validation.
    This issue is fixed in iOS 16.2 and iPadOS 16.2, macOS Ventura 13.1, Safari 16.2. Visiting a malicious
    website may lead to address bar spoofing. (CVE-2022-46705)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 16.2 and iPadOS 16.2, macOS
    Ventura 13.1. Location data may be shared via iCloud links even if Location metadata is disabled via the
    Share Sheet. (CVE-2022-46710)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.1, iOS
    16.2 and iPadOS 16.2. Private Relay functionality did not match system settings (CVE-2022-46716)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 15.7.2 and iPadOS
    15.7.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, macOS Monterey 12.6.2. An app may be able to read
    sensitive location information (CVE-2022-46718)

  - An integer overflow was addressed with improved input validation. This issue is fixed in iOS 16.2 and
    iPadOS 16.2, macOS Ventura 13.1. An app may be able to break out of its sandbox (CVE-2022-46720)

  - A spoofing issue existed in the handling of URLs. This issue was addressed with improved input validation.
    This issue is fixed in iOS 16.4 and iPadOS 16.4. Visiting a malicious website may lead to address bar
    spoofing. (CVE-2022-46725)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.1, watchOS 9.2, iOS
    16.2 and iPadOS 16.2, tvOS 16.2. An attacker with arbitrary read and write capability may be able to
    bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited against
    versions of iOS released before iOS 15.7.1. (CVE-2022-48618)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213532");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29181");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42842");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'macOS Dirty Cow Arbitrary File Write Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:13.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '13.1.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
