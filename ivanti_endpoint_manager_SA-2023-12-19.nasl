#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187976);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/24");

  script_cve_id("CVE-2023-39336");
  script_xref(name:"IAVB", value:"2024-B-0002-S");

  script_name(english:"Ivanti Endpoint Manager < 2022 SU5 SQLi (SA-2023-12-19)");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager running on the remote host is affected by an SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager running on the remote host is prior to 2022 SU5. It is, therefore, affected by
an SQL injection (SQLi) vulnerability, which allows an attacker with access to the internal network to execute arbitrary
SQL queries and retrieve output without the need for authentication. Under specific circumstances, this may also lead to
RCE on the core server.

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://forums.ivanti.com/s/article/CVE-2023-39336-Full-details");
  script_set_attribute(attribute:"see_also", value:"https://forums.ivanti.com/s/article/SA-2023-12-19-CVE-2023-39336");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Endpoint Manager 2022 SU5 or later");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39336");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/12");

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

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::ivanti_epm::get_app_info(app:'Ivanti Endpoint Manager', win_local:TRUE);

var constraints = [
  { 'fixed_version':'11.0.5.361.5', 'fixed_display':'11.0.5.361 2022 SU5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
