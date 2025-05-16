#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211457);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/24");

  script_cve_id(
    "CVE-2024-34787",
    "CVE-2024-50322",
    "CVE-2024-50324",
    "CVE-2024-50329",
    "CVE-2024-32839",
    "CVE-2024-32841",
    "CVE-2024-32844",
    "CVE-2024-32847",
    "CVE-2024-34780",
    "CVE-2024-37376",
    "CVE-2024-34781",
    "CVE-2024-34782",
    "CVE-2024-34784",
    "CVE-2024-50323",
    "CVE-2024-50326",
    "CVE-2024-50327",
    "CVE-2024-50328",
    "CVE-2024-50330"
  );
  script_xref(name:"IAVA", value:"2024-A-0741-S");

  script_name(english:"Ivanti Endpoint Manager 2024 - November 2024 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager 2024 running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager 2024 running on the remote host lacking the November 2024 Hotfix. It is, therefore, 
affected by mutliple vulnerabilities: 

  - Path traversal in Ivanti Endpoint Manager before 2024 November Security Update or 2022 SU6 November 
    Security Update allows a local unauthenticated attacker to achieve code execution. User interaction is 
    required.  (CVE-2024-34787)

  - Path traversal in Ivanti Endpoint Manager before 2024 November Security Update or 2022 SU6 November 
    Security Update allows a remote unauthenticated attacker to achieve remote code execution. User 
    interaction is required. (CVE-2024-50329)
  
  - SQL injection in Ivanti Endpoint Manager before 2024 November Security Update or 2022 SU6 November 
    Security Update allows a remote unauthenticated attacker to achieve remote code execution. 
    (CVE-2024-50330)

Note that Nessus has not tested for these issues but has instead relied only on the 
service's self-reported version number of the affected dll files.");
  # https://forums.ivanti.com/s/article/Security-Advisory-EPM-November-2024-for-EPM-2024-and-EPM-2022?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe606be2");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50330");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

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
  { 'fixed_version' : '11.0.5.2744.6', 'fixed_display' : '11.0.5.2744 2022 SU6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
