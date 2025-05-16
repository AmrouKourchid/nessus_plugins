#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200820);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2023-28324");
  script_xref(name:"IAVB", value:"2023-B-0048-S");

  script_name(english:"Ivanti Endpoint Manager < 2022 SU3 Privilege Escalation (SA-2023-06-06)");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"A improper input validation vulnerability exists in Ivanti Endpoint Manager 2022 and below that could allow privilege
escalation or remote code execution.

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://forums.ivanti.com/s/article/SA-2023-06-06-CVE-2023-28324
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ed049af");
  script_set_attribute(attribute:"solution", value:
"Update to version referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28324");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ivanti EPM Agent Portal Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_endpoint_manager_win_installed.nbin");
  script_require_keys("installed_sw/Ivanti Endpoint Manager");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::ivanti_epm::get_app_info(app:'Ivanti Endpoint Manager', win_local:TRUE);

var constraints = [];
if ('11.0.5' >< app_info['version'])
{
  constraints = [{'fixed_version':'11.0.5.361.3', 'fixed_display':'11.0.5.361 2022 SU3'}];
}
else
{
  # cannot check for hotfixes
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
  constraints = [{'fixed_version':'11.0.4.733.5', 'fixed_display':'11.0.4.733 2021 SU5'}];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
