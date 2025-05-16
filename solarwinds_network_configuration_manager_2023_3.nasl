#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189534);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id(
    "CVE-2023-23842",
    "CVE-2023-23843",
    "CVE-2023-23844",
    "CVE-2023-33224",
    "CVE-2023-33225"
  );
  script_xref(name:"IAVA", value:"2023-A-0385");

  script_name(english:"SolarWinds Platform < 2023.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Platform installed on the remote host is prior to 2023.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the solarwinds_platform_2023_3 advisory.

  - The SolarWinds Network Configuration Manager was susceptible to the Directory Traversal Vulnerability. 
    This vulnerability allows users with administrative access to SolarWinds Web Console to execute 
    arbitrary commands. (CVE-2023-23842)

  - The SolarWinds Platform was susceptible to the Incorrect Comparison Vulnerability. This vulnerability 
    allows users with administrative access to SolarWinds Web Console to execute arbitrary commands with 
    SYSTEM privileges. (CVE-2023-23844)

  - The SolarWinds Platform was susceptible to the Incorrect Behavior Order Vulnerability. This vulnerability 
    allows users with administrative access to SolarWinds Web Console to execute arbitrary commands with 
    NETWORK SERVICE privileges. (CVE-2023-33224)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2023-23842
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db18b623");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Platform version 2023.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:network_configuration_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_network_configuration_manager_win_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Network Configuration Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'SolarWinds Network Configuration Manager');

var constraints = [{ 'min_version' : '2023.2.0', 'max_version': '2023.2.1.99999', 'fixed_version' : '2023.3' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
