#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183881);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/10");

  script_cve_id(
    "CVE-2023-36191",
    "CVE-2023-40413",
    "CVE-2023-40416",
    "CVE-2023-40421",
    "CVE-2023-40423",
    "CVE-2023-40425",
    "CVE-2023-40446",
    "CVE-2023-40449",
    "CVE-2023-41975",
    "CVE-2023-42823",
    "CVE-2023-42840",
    "CVE-2023-42844",
    "CVE-2023-42849",
    "CVE-2023-42853",
    "CVE-2023-42854",
    "CVE-2023-42856",
    "CVE-2023-42858",
    "CVE-2023-42859",
    "CVE-2023-42860",
    "CVE-2023-42873",
    "CVE-2023-42877",
    "CVE-2023-42889",
    "CVE-2023-42952"
  );
  script_xref(name:"APPLE-SA", value:"HT213983");
  script_xref(name:"IAVA", value:"2023-A-0645");
  script_xref(name:"IAVA", value:"2023-A-0581-S");
  script_xref(name:"IAVA", value:"2024-A-0050-S");
  script_xref(name:"IAVA", value:"2024-A-0142-S");
  script_xref(name:"IAVA", value:"2024-A-0179-S");

  script_name(english:"macOS 12.x < 12.7.1 Multiple Vulnerabilities (HT213983)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.7.1. It is, therefore, affected by
multiple vulnerabilities:

  - The issue was addressed with improved checks. This issue is fixed in iOS 17.1 and iPadOS 17.1, macOS
    Ventura 13.6.3, macOS Sonoma 14.1, macOS Monterey 12.7.1. An app with root privileges may be able to
    access private information. (CVE-2023-42952)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma 14.1. An app may
    be able to cause a denial-of-service. (CVE-2023-40449)

  - The issue was resolved by sanitizing logging This issue is fixed in watchOS 10.1, macOS Sonoma 14.1, tvOS
    17.1, macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1, macOS Ventura 13.6.1.
    An app may be able to access user-sensitive data. (CVE-2023-42823)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sonoma 14.1, macOS
    Monterey 12.7.1, macOS Ventura 13.6.1. An app may be able to cause a denial-of-service to Endpoint
    Security clients. (CVE-2023-42854)

  - The issue was addressed with improved handling of caches. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma
    14.1. An app may be able to read sensitive location information. (CVE-2023-40413)

  - This issue was addressed with improved handling of symlinks. This issue is fixed in macOS Sonoma 14.1,
    macOS Monterey 12.7.1, macOS Ventura 13.6.1. A website may be able to access sensitive user data when
    resolving symlinks. (CVE-2023-42844)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.7.1, iOS
    16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1. Processing maliciously crafted input may lead to
    arbitrary code execution in user-installed apps. (CVE-2023-40446)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma 14.1. Processing
    an image may result in disclosure of process memory. (CVE-2023-40416)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma 14.1. An app may
    be able to execute arbitrary code with kernel privileges. (CVE-2023-40423)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma
    14.1. An attacker that has already achieved kernel code execution may be able to bypass kernel memory
    mitigations. (CVE-2023-42849)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.1, macOS
    Monterey 12.7.1, macOS Ventura 13.6.1. Processing a file may lead to unexpected app termination or
    arbitrary code execution. (CVE-2023-42856)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to modify protected parts of the file system.
    (CVE-2023-42859, CVE-2023-42877)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to access user-sensitive data. (CVE-2023-42840,
    CVE-2023-42858)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to bypass certain Privacy preferences. (CVE-2023-42889)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to access user-sensitive data. (CVE-2023-42853)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sonoma 14.1,
    macOS Monterey 12.7.1, macOS Ventura 13.6.1. An app may be able to modify protected parts of the file
    system. (CVE-2023-42860)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Sonoma 14.1, tvOS 17.1,
    macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1, macOS Ventura 13.6.1. An
    app may be able to execute arbitrary code with kernel privileges. (CVE-2023-42873)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Monterey 12.7.1. An app with root privileges may be able to access private information.
    (CVE-2023-40425)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn
    by its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2023-36191)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sonoma 14.1,
    macOS Monterey 12.7.1, macOS Ventura 13.6.1. An app may be able to access sensitive user data.
    (CVE-2023-40421)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sonoma 14.1, macOS
    Monterey 12.7.1, macOS Ventura 13.6.1. A website may be able to access the microphone without the
    microphone use indicator being shown. (CVE-2023-41975)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213983");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42844");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-42873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
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
  { 'fixed_version' : '12.7.1', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.7.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
