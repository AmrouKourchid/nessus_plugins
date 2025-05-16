#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209165);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id("CVE-2024-45710", "CVE-2024-45715");
  script_xref(name:"IAVA", value:"2024-A-0669-S");

  script_name(english:"SolarWinds Platform 2024.2.0 < 2024.4 Multiple Vulnerabilities XSS");

  script_set_attribute(attribute:"synopsis", value:
"SolarWinds Platform is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Platform installed on the remote host is prior to 2024.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the solarwinds_platform_2024_4 advisory.

  - SolarWinds Platform is susceptible to an Uncontrolled Search Path Element Local Privilege Escalation
    vulnerability. This requires a low privilege account and local access to the affected node machine.
    (CVE-2024-45710)

  - The SolarWinds Platform was susceptible to a Cross-Site Scripting vulnerability when performing an edit
    function to existing elements. (CVE-2024-45715)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-45710
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bf39db0");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-45715
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7774f6b8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Platform version 2024.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45710");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'min_version' : '2024.2.0', 'max_version' : '2024.2.1', 'fixed_version' : '2024.4' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
