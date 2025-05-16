#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206671);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2024-22184");

  script_name(english:"Intel Quartus Prime < 24.1 (INTEL-SA-01127)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Intel Quartus Prime installed on the remote host is prior to 24.1. It is, therefore, affected by a
vulnerability as referenced in the INTEL-SA-01127 advisory.

  - Uncontrolled search path for some Intel(R) Quartus(R) Prime Pro Edition Design Software before version
    24.1 may allow an authenticated user to potentially enable escalation of privilege via local access.
    (CVE-2024-22184)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01127.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06481a44");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Intel Quartus Prime version 24.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:quartus_prime");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_quartus_prime_win_installed.nbin");
  script_require_keys("installed_sw/Intel Quartus Prime", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Intel Quartus Prime', win_local:TRUE);

var edition = app_info.Edition;
if (empty_or_null(edition))
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN);
}
else
{
  if (tolower(edition) !~ 'pro')
    audit(AUDIT_INST_VER_NOT_VULN, 'The ' + edition + ' edition of ' + app_info.app);
}

var constraints = [
  { 'fixed_version' : '24.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
