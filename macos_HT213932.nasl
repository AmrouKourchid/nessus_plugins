#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181760);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/13");

  script_cve_id(
    "CVE-2023-38612",
    "CVE-2023-40395",
    "CVE-2023-40403",
    "CVE-2023-40406",
    "CVE-2023-40409",
    "CVE-2023-40410",
    "CVE-2023-40412",
    "CVE-2023-40420",
    "CVE-2023-40427",
    "CVE-2023-40452",
    "CVE-2023-40454",
    "CVE-2023-41073",
    "CVE-2023-41232",
    "CVE-2023-41968",
    "CVE-2023-41984",
    "CVE-2023-41992"
  );
  script_xref(name:"APPLE-SA", value:"HT213932");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/16");
  script_xref(name:"IAVA", value:"2023-A-0503-S");
  script_xref(name:"IAVA", value:"2023-A-0529-S");

  script_name(english:"macOS 12.x < 12.7 Multiple Vulnerabilities (HT213932)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.7. It is, therefore, affected by
multiple vulnerabilities:

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.6, tvOS 17,
    macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17. An app may be able to execute arbitrary code with
    kernel privileges. (CVE-2023-40409, CVE-2023-40412)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.6, tvOS 17, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14. An app may be able
    to disclose kernel memory. (CVE-2023-40410)

  - The issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.7, iOS 16.7 and
    iPadOS 16.7, iOS 17 and iPadOS 17, macOS Sonoma 14, macOS Ventura 13.6. An app may be able to access
    protected user data. (CVE-2023-38612)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Monterey
    12.7, iOS 17 and iPadOS 17, macOS Ventura 13.6, iOS 16.7 and iPadOS 16.7. An app may be able to disclose
    kernel memory. (CVE-2023-41232)

  - The issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.7, macOS Ventura
    13.6, macOS Sonoma 14. An app may be able to read arbitrary files. (CVE-2023-40406)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.6, tvOS 17,
    iOS 16.7 and iPadOS 16.7, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14.
    Processing web content may lead to a denial-of-service. (CVE-2023-40420)

  - This issue was addressed with improved validation of symlinks. This issue is fixed in macOS Ventura 13.6,
    tvOS 17, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14. An app may be able to
    read arbitrary files. (CVE-2023-41968)

  - The issue was addressed with improved handling of caches. This issue is fixed in tvOS 17, iOS 16.7 and
    iPadOS 16.7, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14. An app may be able to
    access contacts. (CVE-2023-40395)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.6, tvOS 17,
    iOS 16.7 and iPadOS 16.7, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14. An app
    may be able to execute arbitrary code with kernel privileges. (CVE-2023-41984)

  - The issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.7, iOS 16.7 and
    iPadOS 16.7, macOS Ventura 13.6. A local attacker may be able to elevate their privileges. Apple is aware
    of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.
    (CVE-2023-41992)

  - An authorization issue was addressed with improved state management. This issue is fixed in macOS Ventura
    13.6, tvOS 17, iOS 16.7 and iPadOS 16.7, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS
    Sonoma 14. An app may be able to access protected user data. (CVE-2023-41073)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Ventura 13.6,
    tvOS 17, iOS 16.7 and iPadOS 16.7, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14.
    An app may be able to delete files for which it does not have permission. (CVE-2023-40454)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.6, tvOS 17,
    iOS 16.7 and iPadOS 16.7, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14.
    Processing web content may disclose sensitive information. (CVE-2023-40403)

  - The issue was addressed with improved handling of caches. This issue is fixed in macOS Ventura 13.6, tvOS
    17, macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14. An app may be able to read
    sensitive location information. (CVE-2023-40427)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Ventura 13.6, tvOS 17,
    macOS Monterey 12.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14. An app may be able to overwrite
    arbitrary files. (CVE-2023-40452)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213932");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40403");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-41992");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/21");

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
  { 'fixed_version' : '12.7.0', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.7' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
