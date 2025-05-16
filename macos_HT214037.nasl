#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186730);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/14");

  script_cve_id(
    "CVE-2020-19185",
    "CVE-2020-19186",
    "CVE-2020-19187",
    "CVE-2020-19188",
    "CVE-2020-19189",
    "CVE-2020-19190",
    "CVE-2023-3618",
    "CVE-2023-41989",
    "CVE-2023-42834",
    "CVE-2023-42836",
    "CVE-2023-42838",
    "CVE-2023-42886",
    "CVE-2023-42891",
    "CVE-2023-42892",
    "CVE-2023-42893",
    "CVE-2023-42894",
    "CVE-2023-42896",
    "CVE-2023-42899",
    "CVE-2023-42914",
    "CVE-2023-42919",
    "CVE-2023-42922",
    "CVE-2023-42930",
    "CVE-2023-42931",
    "CVE-2023-42932",
    "CVE-2023-42936",
    "CVE-2023-42947",
    "CVE-2023-42974",
    "CVE-2023-5344"
  );
  script_xref(name:"APPLE-SA", value:"HT214037");
  script_xref(name:"IAVA", value:"2023-A-0679-S");
  script_xref(name:"IAVA", value:"2024-A-0050-S");
  script_xref(name:"IAVA", value:"2024-A-0179-S");
  script_xref(name:"IAVA", value:"2024-A-0275-S");

  script_name(english:"macOS 12.x < 12.7.2 Multiple Vulnerabilities (HT214037)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.7.2. It is, therefore, affected by
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

  - The issue was addressed by restricting options offered on a locked device. This issue is fixed in macOS
    Sonoma 14.1. An attacker may be able to execute arbitrary code as root from the Lock Screen.
    (CVE-2023-41989)

  - A privacy issue was addressed with improved handling of files. This issue is fixed in watchOS 10.1, macOS
    Sonoma 14.1, macOS Monterey 12.7.2, macOS Ventura 13.6.3, iOS 17.1 and iPadOS 17.1. An app may be able to
    access sensitive user data. (CVE-2023-42834)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 17.1 and iPadOS 17.1, macOS
    Ventura 13.6.3, macOS Sonoma 14.1, macOS Monterey 12.7.2. An attacker may be able to access connected
    network volumes mounted in the home directory. (CVE-2023-42836)

  - An access issue was addressed with improvements to the sandbox. This issue is fixed in macOS Ventura
    13.6.3, macOS Sonoma 14.1, macOS Monterey 12.7.2. An app may be able to execute arbitrary code out of its
    sandbox or with certain elevated privileges. (CVE-2023-42838)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Sonoma
    14.2, macOS Ventura 13.6.3, macOS Monterey 12.7.2. A user may be able to cause unexpected app termination
    or arbitrary code execution. (CVE-2023-42886)

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

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.2, iOS 17.2
    and iPadOS 17.2, watchOS 10.2, macOS Ventura 13.6.3, tvOS 17.2, iOS 16.7.3 and iPadOS 16.7.3, macOS
    Monterey 12.7.2. Processing an image may lead to arbitrary code execution. (CVE-2023-42899)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.2, iOS 17.2
    and iPadOS 17.2, watchOS 10.2, macOS Ventura 13.6.3, tvOS 17.2, iOS 16.7.3 and iPadOS 16.7.3, macOS
    Monterey 12.7.2. An app may be able to break out of its sandbox. (CVE-2023-42914)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Sonoma 14.2, iOS 17.2 and iPadOS 17.2, watchOS 10.2, macOS Ventura 13.6.3, iOS 16.7.3 and iPadOS
    16.7.3, macOS Monterey 12.7.2. An app may be able to access sensitive user data. (CVE-2023-42919)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Sonoma 14.2, iOS 17.2 and iPadOS 17.2, macOS Ventura 13.6.3, iOS 16.7.3 and iPadOS 16.7.3, macOS Monterey
    12.7.2. An app may be able to read sensitive location information. (CVE-2023-42922)

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

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Monterey
    12.7.2, macOS Ventura 13.6.3, iOS 17.2 and iPadOS 17.2, tvOS 17.2, watchOS 10.2, macOS Sonoma 14.2. An app
    may be able to break out of its sandbox. (CVE-2023-42947)

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.7.2,
    macOS Ventura 13.6.3, iOS 17.2 and iPadOS 17.2, iOS 16.7.3 and iPadOS 16.7.3, macOS Sonoma 14.2. An app
    may be able to execute arbitrary code with kernel privileges. (CVE-2023-42974)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1969. (CVE-2023-5344)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214037");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42947");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/11");

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
  { 'fixed_version' : '12.7.2', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.7.2' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
