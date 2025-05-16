#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216060);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2024-52606", "CVE-2024-52611", "CVE-2024-52612");
  script_xref(name:"IAVA", value:"2025-A-0113");

  script_name(english:"SolarWinds Platform 2024.4.0 < 2025.1 Multiple Vulnerabilities XSS");

  script_set_attribute(attribute:"synopsis", value:
"SolarWinds Platform is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Platform installed on the remote host is prior to 2025.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the solarwinds_platform_2025_1 advisory.

  - The SolarWinds Platform is vulnerable to an information disclosure vulnerability through an error message.
    While the data does not provide anything sensitive, the information could assist an attacker in other
    malicious actions. (CVE-2024-52611)

  - SolarWinds Platform is affected by server-side request forgery vulnerability. Proper input sanitation was
    not applied allowing for the possibility of a malicious web request. (CVE-2024-52606)

  - SolarWinds Platform is vulnerable to a reflected cross-site scripting vulnerability. This was caused by an
    insufficient sanitation of input parameters. This vulnerability requires authentication by a high-
    privileged account to be exploitable. (CVE-2024-52612)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-52606
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e6c794a");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-52611
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87b31046");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-52612
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c037fdfa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Platform version 2025.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'min_version' : '2024.4.0', 'max_version' : '2024.4.1', 'fixed_version' : '2025.1' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
