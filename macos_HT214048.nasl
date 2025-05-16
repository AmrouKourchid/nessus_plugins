#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187104);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/13");

  script_cve_id("CVE-2023-42940");
  script_xref(name:"APPLE-SA", value:"HT214048");
  script_xref(name:"IAVA", value:"2023-A-0679-S");

  script_name(english:"macOS 14.x < 14.2.1 (HT214048)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes a vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 14.x prior to 14.2.1. It is, therefore, affected by a
vulnerability:

  - A session rendering issue was addressed with improved session tracking. This issue is fixed in macOS
    Sonoma 14.2.1. A user who shares their screen may unintentionally share the incorrect content.
    (CVE-2023-42940)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214048");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 14.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42940");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:14.0");
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
  { 'fixed_version' : '14.2.1', 'min_version' : '14.0', 'fixed_display' : 'macOS Sonoma 14.2.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
