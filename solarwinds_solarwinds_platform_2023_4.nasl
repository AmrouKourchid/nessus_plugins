#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184348);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/29");

  script_cve_id("CVE-2023-40061", "CVE-2023-40062");
  script_xref(name:"IAVA", value:"2023-A-0601-S");

  script_name(english:"SolarWinds Platform 2023.3.x < 2023.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"SolarWinds Platform is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Platform installed on the remote host is prior to 2023.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the solarwinds_platform_2023_4 advisory.

  - SolarWinds Platform Incomplete List of Disallowed Inputs Remote Code Execution Vulnerability. If executed,
    this vulnerability would allow a low-privileged user to execute commands with SYSTEM privileges.
    (CVE-2023-40062)

  - Insecure job execution mechanism vulnerability. This vulnerability can lead to other attacks as a result.
    (CVE-2023-40061)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2023-40062
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?875ced9f");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2023-40061
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d14d08b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Platform version 2023.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'min_version' : '2023.3.0', 'max_version' : '2023.3.1', 'fixed_version' : '2023.4' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
