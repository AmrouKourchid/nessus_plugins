#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171390);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2023-23514",
    "CVE-2023-23522",
    "CVE-2023-23524",
    "CVE-2023-23529"
  );
  script_xref(name:"APPLE-SA", value:"HT213633");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/07");
  script_xref(name:"IAVA", value:"2023-A-0078-S");
  script_xref(name:"IAVA", value:"2023-A-0162-S");

  script_name(english:"macOS 13.x < 13.2.1 Multiple Vulnerabilities (HT213633)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.2.1. It is, therefore, affected by
multiple vulnerabilities:

  - A type confusion issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.2.1,
    iOS 16.3.1 and iPadOS 16.3.1, Safari 16.3. Processing maliciously crafted web content may lead to
    arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..
    (CVE-2023-23529)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13.2.1, iOS 16.3.1 and iPadOS 16.3.1. An app may be able to execute arbitrary code with kernel
    privileges.. (CVE-2023-23514)

  - A privacy issue was addressed with improved handling of temporary files. This issue is fixed in macOS
    Ventura 13.2.1. An app may be able to observe unprotected user data.. (CVE-2023-23522)

  - A denial-of-service issue was addressed with improved input validation. This issue is fixed in macOS
    Ventura 13.2.1, iOS 16.3.1 and iPadOS 16.3.1, tvOS 16.3.2, watchOS 9.3.1. Processing a maliciously crafted
    certificate may lead to a denial-of-service. (CVE-2023-23524)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213633");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/13");

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
  { 'fixed_version' : '13.2.1', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.2.1' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
