#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181231);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id("CVE-2023-41064");
  script_xref(name:"APPLE-SA", value:"HT213914");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/02");
  script_xref(name:"IAVA", value:"2023-A-0468-S");

  script_name(english:"macOS 12.x < 12.6.9 (HT213914)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes a vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.6.9. It is, therefore, affected by a
vulnerability:

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Ventura
    13.5.2, iOS 16.6.1 and iPadOS 16.6.1. Processing a maliciously crafted image may lead to arbitrary code
    execution. Apple is aware of a report that this issue may have been actively exploited. (CVE-2023-41064)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213914");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.6.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41064");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/11");

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
  { 'fixed_version' : '12.6.9', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.6.9' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
