#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235827);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2025-25251");

  script_name(english:"Fortinet FortiClient Local privilege escalation in XPC services (FG-IR-25-016) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"remote Mac host is affected by a privilege escalation.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-25-016 advisory.

  - An Incorrect Authorization vulnerability [CWE-863] in FortiClient Mac may allow a local attacker to
    escalate privileges via crafted XPC messages. (CVE-2025-25251)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-25-016");
  script_set_attribute(attribute:"solution", value:
"For 7.0.x, see vendor advisory. For 7.2.x, upgrade to FortiClient version 7.2.9 or later. For 7.4.x, upgrade to
FortiClient version 7.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-25251");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient (macOS)");

  exit(0);
}

include('vcf.inc');

if (empty_or_null(get_kb_item('Host/local_checks_enabled'))) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (empty_or_null(get_kb_item('Host/MacOSX/Version'))) audit(AUDIT_OS_NOT, 'Mac OS');

var app_name = 'FortiClient (macOS)';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.0.999999', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.8', 'fixed_version' : '7.2.9' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.2', 'fixed_version' : '7.4.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
