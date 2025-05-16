#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207391);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2024-8191",
    "CVE-2024-8320",
    "CVE-2024-8321",
    "CVE-2024-8322",
    "CVE-2024-8441",
    "CVE-2024-29847",
    "CVE-2024-32840",
    "CVE-2024-32842",
    "CVE-2024-32843",
    "CVE-2024-32845",
    "CVE-2024-32846",
    "CVE-2024-32848",
    "CVE-2024-34779",
    "CVE-2024-34783",
    "CVE-2024-34785",
    "CVE-2024-37397"
  );
  script_xref(name:"IAVB", value:"2024-B-0133-S");

  script_name(english:"Ivanti Endpoint Manager 2022 - September Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager 2024 running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager 2024 running on the remote host lacking the September 2024 Hotfix. It is, therefore, 
affected by mutliple vulnerabilities: 
  - An unspecified SQL injection in Ivanti EPM before the 2024 September update allows a remote 
    authenticated attacker with admin privileges to achieve remote code execution. (CVE-2024-32840)

  - An unspecified SQL injection in Ivanti EPM before the 2024 September update allows a remote 
    authenticated attacker with admin privileges to achieve remote code execution. (CVE-2024-32843)
  
  - An unspecified SQL injection in Ivanti EPM before the 2024 September update allows a remote 
    authenticated attacker with admin privileges to achieve remote code execution. (CVE-2024-32845)

Note that Nessus has not tested for these issues but has instead relied only on the 
service's self-reported version number of the affected dll files.");
  # https://forums.ivanti.com/s/article/Security-Advisory-EPM-September-2024-for-EPM-2024-and-EPM-2022?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14d91dc");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8191");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager_cloud_services_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_endpoint_manager_win_installed.nbin");
  script_require_keys("installed_sw/Ivanti Endpoint Manager");

  exit(0);
}
include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::ivanti_epm::get_app_info(app:'Ivanti Endpoint Manager', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '11.0.5.361.6', 'fixed_display' : '11.0.5.361 2022 SU6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
