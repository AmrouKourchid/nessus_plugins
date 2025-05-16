#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193585);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id(
    "CVE-2024-28076",
    "CVE-2024-29000",
    "CVE-2024-29001",
    "CVE-2024-29003"
  );
  script_xref(name:"IAVA", value:"2024-A-0256-S");

  script_name(english:"SolarWinds Platform 2024.0 < 2024.1.1 Multiple Vulnerabilities XSS");

  script_set_attribute(attribute:"synopsis", value:
"SolarWinds Platform is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Platform installed on the remote host is prior to 2024.1.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the solarwinds_platform_2024_1_sr_1 advisory.

  - The SolarWinds Platform was susceptible to a Arbitrary Open Redirection Vulnerability. A potential
    attacker can redirect to different domain when using URL parameter with relative entry in the correct
    format (CVE-2024-28076)

  - The SolarWinds Platform was determined to be affected by a reflected cross-site scripting vulnerability
    affecting the web console. A high-privileged user and user interaction is required to exploit this
    vulnerability. (CVE-2024-29000)

  - A SolarWinds Platform SWQL Injection Vulnerability was identified in the user interface. This
    vulnerability requires authentication and user interaction to be exploited. (CVE-2024-29001)

  - The SolarWinds Platform was susceptible to a XSS vulnerability that affects the maps section of the user
    interface. This vulnerability requires authentication and requires user interaction. (CVE-2024-29003)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28076
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7aef77b1");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-29000
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b99deaa9");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-29001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9c45b99");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-29003
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eebb3c86");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Platform version 2024.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29001");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'min_version' : '2024.0', 'max_version' : '2024.1', 'fixed_version' : '2024.1.1', 'fixed_display' : '2024.1 SR 1' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
