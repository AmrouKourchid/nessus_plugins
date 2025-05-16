#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165106);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/13");

  script_cve_id(
    "CVE-2021-39537",
    "CVE-2022-0261",
    "CVE-2022-0318",
    "CVE-2022-0319",
    "CVE-2022-0351",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0368",
    "CVE-2022-0392",
    "CVE-2022-1622",
    "CVE-2022-1720",
    "CVE-2022-2000",
    "CVE-2022-2042",
    "CVE-2022-2124",
    "CVE-2022-2125",
    "CVE-2022-2126",
    "CVE-2022-32864",
    "CVE-2022-32866",
    "CVE-2022-32875",
    "CVE-2022-32877",
    "CVE-2022-32881",
    "CVE-2022-32883",
    "CVE-2022-32888",
    "CVE-2022-32896",
    "CVE-2022-32900",
    "CVE-2022-32902",
    "CVE-2022-32904",
    "CVE-2022-32908",
    "CVE-2022-32911",
    "CVE-2022-32913",
    "CVE-2022-32914",
    "CVE-2022-32917",
    "CVE-2022-32924",
    "CVE-2022-32934",
    "CVE-2022-42789",
    "CVE-2022-42790",
    "CVE-2022-42793",
    "CVE-2022-42818",
    "CVE-2022-42819",
    "CVE-2022-46701"
  );
  script_xref(name:"APPLE-SA", value:"HT213444");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/05");
  script_xref(name:"IAVA", value:"2022-A-0355-S");

  script_name(english:"macOS 12.x < 12.6 Multiple Vulnerabilities (HT213444)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.6. It is, therefore, affected by
multiple vulnerabilities:

  - An issue in code signature validation was addressed with improved checks. This issue is fixed in macOS Big
    Sur 11.7, macOS Ventura 13, macOS Monterey 12.6. An app may be able to access user-sensitive data.
    (CVE-2022-42789)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13, macOS
    Monterey 12.6, macOS Big Sur 11.7. An app may be able to bypass Privacy preferences. (CVE-2022-32902)

  - An access issue was addressed with additional sandbox restrictions. This issue is fixed in macOS Big Sur
    11.7, macOS Ventura 13, macOS Monterey 12.6. An app may be able to access user-sensitive data.
    (CVE-2022-32904)

  - An access issue was addressed with improved access restrictions. This issue is fixed in macOS Big Sur
    11.7, macOS Ventura 13, macOS Monterey 12.6. An app may be able to read sensitive location information.
    (CVE-2022-42819)

  - A configuration issue was addressed with additional restrictions. This issue is fixed in macOS Big Sur
    11.7, macOS Monterey 12.6. An app may be able to access user-sensitive data. (CVE-2022-32877)

  - LibTIFF master branch has an out-of-bounds read in LZWDecode in libtiff/tif_lzw.c:619, allowing attackers
    to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix
    is available with commit b4e79bfa. (CVE-2022-1622)

  - The issue was addressed with additional restrictions on the observability of app states. This issue is
    fixed in macOS Big Sur 11.7, macOS Ventura 13, iOS 16, watchOS 9, macOS Monterey 12.6, tvOS 16. A
    sandboxed app may be able to determine which app is currently using the camera. (CVE-2022-32913)

  - This issue was addressed by enabling hardened runtime. This issue is fixed in macOS Monterey 12.6, macOS
    Big Sur 11.7. A user may be able to view sensitive user information. (CVE-2022-32896)

  - The issue was addressed with improved bounds checks. This issue is fixed in iOS 16.2 and iPadOS 16.2,
    macOS Ventura 13.1, tvOS 16.2. Connecting to a malicious NFS server may lead to arbitrary code execution
    with kernel privileges. (CVE-2022-46701)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.7, macOS Ventura 13, iOS 16, watchOS 9, macOS Monterey 12.6, tvOS 16. An app may be able to execute
    arbitrary code with kernel privileges. (CVE-2022-32914)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Big Sur 11.7, macOS
    Ventura 13, watchOS 9, macOS Monterey 12.6, tvOS 16. An app may be able to execute arbitrary code with
    kernel privileges. (CVE-2022-32866)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6, iOS
    15.7 and iPadOS 15.7, iOS 16, macOS Big Sur 11.7. An app may be able to execute arbitrary code with kernel
    privileges. (CVE-2022-32911)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 16.1, macOS Big Sur
    11.7, macOS Ventura 13, watchOS 9.1, iOS 16.1 and iPadOS 16, macOS Monterey 12.6. An app may be able to
    execute arbitrary code with kernel privileges. (CVE-2022-32924)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6, iOS
    15.7 and iPadOS 15.7, iOS 16, macOS Big Sur 11.7. An app may be able to disclose kernel memory.
    (CVE-2022-32864)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Monterey 12.6, iOS 15.7
    and iPadOS 15.7, iOS 16, macOS Big Sur 11.7. An application may be able to execute arbitrary code with
    kernel privileges. Apple is aware of a report that this issue may have been actively exploited..
    (CVE-2022-32917)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.6, iOS
    15.7 and iPadOS 15.7, iOS 16, macOS Big Sur 11.7. An app may be able to read sensitive location
    information. (CVE-2022-32883)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in macOS
    Monterey 12.6, iOS 15.7 and iPadOS 15.7, iOS 16, macOS Big Sur 11.7. A user may be able to elevate
    privileges. (CVE-2022-32908)

  - An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer
    overflow. (CVE-2021-39537)

  - This issue was addressed with improved data protection. This issue is fixed in macOS Ventura 13. A user in
    a privileged network position may be able to track user activity. (CVE-2022-42818)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.6,
    macOS Big Sur 11.7. An app may be able to gain elevated privileges. (CVE-2022-32900)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Big Sur 11.7, macOS
    Ventura 13, iOS 16, watchOS 9, macOS Monterey 12.6, tvOS 16. An app may be able to modify protected parts
    of the file system. (CVE-2022-32881)

  - An issue in code signature validation was addressed with improved checks. This issue is fixed in macOS Big
    Sur 11.7, macOS Ventura 13, iOS 16, iOS 15.7 and iPadOS 15.7, macOS Monterey 12.6. An app may be able to
    bypass code signing checks. (CVE-2022-42793)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.7,
    macOS Ventura 13, iOS 16, iOS 15.7 and iPadOS 15.7, macOS Monterey 12.6. A user may be able to view
    restricted content from the lock screen. (CVE-2022-42790)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Big Sur 11.7, macOS
    Ventura 13, macOS Monterey 12.6. A remote user may be able to cause kernel code execution.
    (CVE-2022-32934)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0261, CVE-2022-0359,
    CVE-2022-0361, CVE-2022-2125)

  - Heap-based Buffer Overflow in vim/vim prior to 8.2. (CVE-2022-0318)

  - Out-of-bounds Read in vim/vim prior to 8.2. (CVE-2022-0319)

  - Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.
    (CVE-2022-0351)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-0368, CVE-2022-2126)

  - Heap-based Buffer Overflow in GitHub repository vim prior to 8.2. (CVE-2022-0392)

  - Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This
    vulnerability is capable of crashing the software, memory modification, and possible remote execution.
    (CVE-2022-1720)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-2000)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-2042)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2124)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.7,
    macOS Ventura 13, iOS 16, watchOS 9, macOS Monterey 12.6. An app may be able to read sensitive location
    information. (CVE-2022-32875)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Big
    Sur 11.7, macOS Ventura 13, iOS 16, iOS 15.7 and iPadOS 15.7, watchOS 9, macOS Monterey 12.6, tvOS 16.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-32888)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213444");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0318");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
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
  { 'fixed_version' : '12.6.0', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.6' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
