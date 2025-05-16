#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211691);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id("CVE-2024-44308", "CVE-2024-44309");
  script_xref(name:"APPLE-SA", value:"121753");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/12/12");
  script_xref(name:"IAVA", value:"2024-A-0761-S");

  script_name(english:"macOS 15.x < 15.1.1 Multiple Vulnerabilities (121753)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 15.x prior to 15.1.1. It is, therefore, affected by
multiple vulnerabilities:

  - The issue was addressed with improved checks. This issue is fixed in Safari 18.1.1, iOS 17.7.2 and iPadOS
    17.7.2, macOS Sequoia 15.1.1, iOS 18.1.1 and iPadOS 18.1.1, visionOS 2.1.1. Processing maliciously crafted
    web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been
    actively exploited on Intel-based Mac systems. (CVE-2024-44308)

  - A cookie management issue was addressed with improved state management. This issue is fixed in Safari
    18.1.1, iOS 17.7.2 and iPadOS 17.7.2, macOS Sequoia 15.1.1, iOS 18.1.1 and iPadOS 18.1.1, visionOS 2.1.1.
    Processing maliciously crafted web content may lead to a cross site scripting attack. Apple is aware of a
    report that this issue may have been actively exploited on Intel-based Mac systems. (CVE-2024-44309)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/121753");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 15.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44308");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:15.0");
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
  { 'fixed_version' : '15.1.1', 'min_version' : '15.0', 'fixed_display' : 'macOS Sequoia 15.1.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
