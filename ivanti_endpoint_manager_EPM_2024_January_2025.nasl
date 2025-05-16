#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214342);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2024-10811",
    "CVE-2024-13158",
    "CVE-2024-13159",
    "CVE-2024-13160",
    "CVE-2024-13161",
    "CVE-2024-13162",
    "CVE-2024-13163",
    "CVE-2024-13164",
    "CVE-2024-13165",
    "CVE-2024-13166",
    "CVE-2024-13167",
    "CVE-2024-13168",
    "CVE-2024-13169",
    "CVE-2024-13170",
    "CVE-2024-13171",
    "CVE-2024-13172"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/31");
  script_xref(name:"IAVA", value:"2025-A-0038-S");

  script_name(english:"Ivanti Endpoint Manager 2024 - January 2025 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager 2024 running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager 2024 running on the remote host lacking the January 2024 Hotfix. It is, therefore, 
affected by mutliple vulnerabilities: 

  - Absolute path traversal in Ivanti Endpoint Manager before 2024 January Security Update or 2022 SU6 November 
    Security Update allows a remote unauthenticated attacker to achieve code execution. User interaction
    is not required. (CVE-2024-10811, CVE-2024-13159, CVE-2024-13160, CVE-2024-13161)

  - Improper Validation and Deserialization of untrusted data in Ivanti Endpoint Manager before 2024 
    November Security Update or 2022 SU6 November Security Update allows a remote unauthenticated attacker 
    to achieve remote code execution. User interaction is required. 
    (CVE-2024-13163, CVE-2024-13170, CVE-2024-13171)
  
  - An out-of-bounds read in Ivanti Endpoint Manager before 2024 November Security Update or 2022 SU6 November 
    Security Update allows allows a local authenticated attacker to escalate their privileges.  
    (CVE-2024-13169)

Note that Nessus has not tested for these issues but has instead relied only on the 
service's self-reported version number of the affected dll files.");
  # https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?403cbf11");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10811");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-13161");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager_cloud_services_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_endpoint_manager_win_installed.nbin");
  script_require_keys("installed_sw/Ivanti Endpoint Manager");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::ivanti_epm::get_app_info(app:'Ivanti Endpoint Manager', win_local:TRUE);

var constraints = [
  { 'min_version' : '11.0.6', 'fixed_version' : '11.0.6.1331', 'fixed_display' : '11.0.6.1331 2024' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
