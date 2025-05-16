#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152038);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/22");

  script_cve_id(
    "CVE-2021-1821",
    "CVE-2021-30677",
    "CVE-2021-3518",
    "CVE-2021-30748",
    "CVE-2021-30758",
    "CVE-2021-30759",
    "CVE-2021-30760",
    "CVE-2021-30765",
    "CVE-2021-30766",
    "CVE-2021-30768",
    "CVE-2021-30772",
    "CVE-2021-30774",
    "CVE-2021-30775",
    "CVE-2021-30776",
    "CVE-2021-30777",
    "CVE-2021-30778",
    "CVE-2021-30779",
    "CVE-2021-30780",
    "CVE-2021-30781",
    "CVE-2021-30782",
    "CVE-2021-30783",
    "CVE-2021-30784",
    "CVE-2021-30785",
    "CVE-2021-30786",
    "CVE-2021-30787",
    "CVE-2021-30788",
    "CVE-2021-30789",
    "CVE-2021-30790",
    "CVE-2021-30791",
    "CVE-2021-30792",
    "CVE-2021-30793",
    "CVE-2021-30795",
    "CVE-2021-30796",
    "CVE-2021-30797",
    "CVE-2021-30798",
    "CVE-2021-30799",
    "CVE-2021-30803",
    "CVE-2021-30804",
    "CVE-2021-30805",
    "CVE-2021-30817",
    "CVE-2021-30871",
    "CVE-2021-31004",
    "CVE-2021-31006"
  );
  script_xref(name:"APPLE-SA", value:"HT212602");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-07-21");
  script_xref(name:"IAVA", value:"2021-A-0349-S");

  script_name(english:"macOS 11.x < 11.5 Multiple Vulnerabilities (HT212602)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.5. It is, therefore, affected by
multiple vulnerabilities:

  - A logic issue was addressed with improved state management. This issue is fixed in watchOS 7.6, macOS Big
    Sur 11.5. Visiting a maliciously crafted webpage may lead to a system denial of service. (CVE-2021-1821)

  - This issue was addressed with improved environment sanitization. This issue is fixed in tvOS 14.6, iOS
    14.6 and iPadOS 14.6, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave, macOS Big Sur
    11.4, watchOS 7.5. A malicious application may be able to break out of its sandbox. (CVE-2021-30677)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 14.7,
    macOS Big Sur 11.5. An application may be able to execute arbitrary code with kernel privileges.
    (CVE-2021-30748)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in iOS 14.7, Safari
    14.1.2, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may lead to
    arbitrary code execution. (CVE-2021-30758)

  - A stack overflow was addressed with improved input validation. This issue is fixed in iOS 14.7, macOS Big
    Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-005 Mojave, Security Update 2021-004 Catalina.
    Processing a maliciously crafted font file may lead to arbitrary code execution. (CVE-2021-30759)

  - An integer overflow was addressed through improved input validation. This issue is fixed in iOS 14.7,
    macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-005 Mojave, Security Update 2021-004
    Catalina. Processing a maliciously crafted font file may lead to arbitrary code execution.
    (CVE-2021-30760)

  - An out-of-bounds write was addressed with improved input validation. This issue is fixed in macOS Big Sur
    11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. An application may be able to
    execute arbitrary code with kernel privileges. (CVE-2021-30765, CVE-2021-30766)

  - A logic issue was addressed with improved validation. This issue is fixed in iOS 14.7, macOS Big Sur 11.5,
    watchOS 7.6, tvOS 14.7, Security Update 2021-004 Catalina. A sandboxed process may be able to circumvent
    sandbox restrictions. (CVE-2021-30768)

  - This issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.5. A malicious
    application may be able to gain root privileges. (CVE-2021-30772)

  - A logic issue was addressed with improved validation. This issue is fixed in iOS 14.7, macOS Big Sur 11.5,
    watchOS 7.6, tvOS 14.7. A malicious application may be able to gain root privileges. (CVE-2021-30774)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 14.7,
    macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-004 Catalina. Processing a maliciously
    crafted audio file may lead to arbitrary code execution. (CVE-2021-30775)

  - A logic issue was addressed with improved validation. This issue is fixed in iOS 14.7, macOS Big Sur 11.5,
    watchOS 7.6, tvOS 14.7, Security Update 2021-004 Catalina. Playing a malicious audio file may lead to an
    unexpected application termination. (CVE-2021-30776)

  - An injection issue was addressed with improved validation. This issue is fixed in macOS Big Sur 11.5,
    Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. A malicious application may be able to
    gain root privileges. (CVE-2021-30777)

  - This issue was addressed with improved entitlements. This issue is fixed in macOS Big Sur 11.5. A
    malicious application may be able to bypass Privacy preferences. (CVE-2021-30778)

  - This issue was addressed with improved checks. This issue is fixed in iOS 14.7, macOS Big Sur 11.5,
    watchOS 7.6, tvOS 14.7. Processing a maliciously crafted image may lead to arbitrary code execution.
    (CVE-2021-30779)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 14.7,
    macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-005 Mojave, Security Update 2021-004
    Catalina. A malicious application may be able to gain root privileges. (CVE-2021-30780)

  - This issue was addressed with improved checks. This issue is fixed in iOS 14.7, macOS Big Sur 11.5,
    watchOS 7.6, tvOS 14.7, Security Update 2021-005 Mojave, Security Update 2021-004 Catalina. A local
    attacker may be able to cause unexpected application termination or arbitrary code execution.
    (CVE-2021-30781)

  - This issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.5, Security Update
    2021-004 Catalina, Security Update 2021-005 Mojave. A malicious application may be able to access
    restricted files. (CVE-2021-30782)

  - An access issue was addressed with improved access restrictions. This issue is fixed in macOS Big Sur
    11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. A sandboxed process may be able
    to circumvent sandbox restrictions. (CVE-2021-30783)

  - Multiple issues were addressed with improved logic. This issue is fixed in macOS Big Sur 11.5. A local
    attacker may be able to execute code on the Apple T2 Security Chip. (CVE-2021-30784)

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in iOS 14.7, macOS Big
    Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-004 Catalina. Processing a maliciously crafted
    image may lead to arbitrary code execution. (CVE-2021-30785)

  - A race condition was addressed with improved state handling. This issue is fixed in iOS 14.7, macOS Big
    Sur 11.5. Opening a maliciously crafted PDF file may lead to an unexpected application termination or
    arbitrary code execution. (CVE-2021-30786)

  - This issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.5, Security Update
    2021-004 Catalina, Security Update 2021-005 Mojave. An application may be able to cause unexpected system
    termination or write kernel memory. (CVE-2021-30787)

  - This issue was addressed with improved checks. This issue is fixed in iOS 14.7, macOS Big Sur 11.5,
    watchOS 7.6, tvOS 14.7, Security Update 2021-005 Mojave, Security Update 2021-004 Catalina. Processing a
    maliciously crafted tiff file may lead to a denial-of-service or potentially disclose memory contents.
    (CVE-2021-30788)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 14.7, macOS
    Big Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-004 Catalina. Processing a maliciously crafted
    font file may lead to arbitrary code execution. (CVE-2021-30789)

  - An information disclosure issue was addressed by removing the vulnerable code. This issue is fixed in
    macOS Big Sur 11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. Opening a
    maliciously crafted file may lead to unexpected application termination or arbitrary code execution.
    (CVE-2021-30790)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in iOS 14.7, macOS
    Big Sur 11.5. Processing a maliciously crafted file may disclose user information. (CVE-2021-30791)

  - An out-of-bounds write was addressed with improved input validation. This issue is fixed in iOS 14.7,
    macOS Big Sur 11.5. Processing a maliciously crafted image may lead to arbitrary code execution.
    (CVE-2021-30792)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.5,
    Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. An application may be able to execute
    arbitrary code with kernel privileges. (CVE-2021-30793)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.7,
    Safari 14.1.2, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may
    lead to arbitrary code execution. (CVE-2021-30795)

  - A logic issue was addressed with improved validation. This issue is fixed in iOS 14.7, macOS Big Sur 11.5,
    Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. Processing a maliciously crafted image
    may lead to a denial of service. (CVE-2021-30796)

  - This issue was addressed with improved checks. This issue is fixed in iOS 14.7, Safari 14.1.2, macOS Big
    Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may lead to code execution.
    (CVE-2021-30797)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 14.7, macOS Big Sur
    11.5, watchOS 7.6. A malicious application may be able to bypass certain Privacy preferences.
    (CVE-2021-30798)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    14.7, macOS Big Sur 11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-30799)

  - A permissions issue was addressed with improved validation. This issue is fixed in macOS Big Sur 11.5. A
    malicious application may be able to access a user's recent Contacts. (CVE-2021-30803)

  - A permissions issue was addressed with improved validation. This issue is fixed in iOS 14.7. A malicious
    application may be able to access Find My data. (CVE-2021-30804)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in macOS Big
    Sur 11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. An application may be able
    to execute arbitrary code with kernel privileges. (CVE-2021-30805)

  - A permissions issue was addressed with improved validation. This issue is fixed in macOS Big Sur 11.5. A
    malicious application may be able to access data about the accounts the user is using Family Sharing with.
    (CVE-2021-30817)

  - This issue was addressed with a new entitlement. This issue is fixed in iOS 14.7, watchOS 7.6, macOS Big
    Sur 11.5. A local attacker may be able to access analytics data. (CVE-2021-30871)

  - A race condition was addressed with improved locking. This issue is fixed in macOS Monterey 12.0.1, macOS
    Big Sur 11.5. An application may be able to gain elevated privileges. (CVE-2021-31004)

  - Description: A permissions issue was addressed with improved validation. This issue is fixed in watchOS
    7.6, tvOS 14.7, macOS Big Sur 11.5. A malicious application may be able to bypass certain Privacy
    preferences. (CVE-2021-31006)

  - There's a flaw in libxml2 in versions before 2.9.11. An attacker who is able to submit a crafted file to
    be processed by an application linked with libxml2 could trigger a use-after-free. The greatest impact
    from this flaw is to confidentiality, integrity, and availability. (CVE-2021-3518)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212602");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '11.5.0', 'min_version' : '11.0', 'fixed_display' : 'macOS Big Sur 11.5' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
