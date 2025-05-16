#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234506);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/01");

  script_cve_id("CVE-2025-31200", "CVE-2025-31201");
  script_xref(name:"APPLE-SA", value:"122400");
  script_xref(name:"IAVA", value:"2025-A-0285");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/05/08");

  script_name(english:"macOS 15.x < 15.4.1 Multiple Vulnerabilities (122400)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 15.x prior to 15.4.1. It is, therefore, affected by
multiple vulnerabilities:

  - A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1,
    visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a
    maliciously crafted media file may result in code execution. Apple is aware of a report that this issue
    may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.
    (CVE-2025-31200)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS
    2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write
    capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may
    have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.
    (CVE-2025-31201)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/122400");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 15.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31201");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-31200");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '15.4.1', 'min_version' : '15.0', 'fixed_display' : 'macOS Sequoia 15.4.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
