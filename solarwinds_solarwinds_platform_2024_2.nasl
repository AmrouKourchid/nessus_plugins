#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200137);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2024-28996", "CVE-2024-28999", "CVE-2024-29004");
  script_xref(name:"IAVA", value:"2024-A-0329-S");

  script_name(english:"SolarWinds Platform < 2024.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"SolarWinds Platform is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Platform installed on the remote host is prior to 2024.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the vendor advisories.

  - The SolarWinds Platform was determined to be affected by a SWQL Injection Vulnerability. Attack complexity
    is high for this vulnerability. (CVE-2024-28996)

  - The SolarWinds Platform was determined to be affected by a Race Condition Vulnerability affecting the
    web console. (CVE-2024-28999)

  - The SolarWinds Platform was determined to be affected by a stored cross-site scripting vulnerability
    affecting the web console. High-privileged user credentials are needed, and user interaction is required
    to exploit this vulnerability. (CVE-2024-29004)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28996
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bb3c909");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-29004
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5f741d8");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28999
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dc64cdb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Platform version 2024.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28999");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'fixed_version' : '2024.2' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
