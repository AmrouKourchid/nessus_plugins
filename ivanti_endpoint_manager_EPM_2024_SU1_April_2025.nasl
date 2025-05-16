#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234221);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2025-22458",
    "CVE-2025-22459",
    "CVE-2025-22461",
    "CVE-2025-22464",
    "CVE-2025-22465",
    "CVE-2025-22466"   
  );
  script_xref(name:"IAVA", value:"2025-A-0254");

  script_name(english:"Ivanti Endpoint Manager < 2022 SU7 / 2024 < 2024 April 2025 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager running on the remote host is prior to 2022 SU7 or 2024 prior to 2024 SU1. It
is, therefore, affected by multiple vulnerabilities, including: 

  - Reflected XSS in Ivanti Endpoint Manager before version 2024 SU1 or before version 2022 SU7 allows a remote
    unauthenticated attacker to obtain admin privileges. User interaction is required. (CVE-2025-22466)

  - DLL hijacking in Ivanti Endpoint Manager before version 2024 SU1 or before version 2022 SU7 allows an authenticated
    attacker to escalate to System. (CVE-2025-22458)

  - SQL injection in Ivanti Endpoint Manager before version 2024 SU1 or before version 2022 SU7 allows a remote
    authenticated attacker with admin privileges to achieve code execution. (CVE-2025-22461)

Note that Nessus has not tested for these issues but has instead relied only on the 
service's self-reported version number of the affected dll files.");
  # https://forums.ivanti.com/s/article/Security-Advisory-EPM-April-2025-for-EPM-2024-and-EPM-2022-SU6?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7599d698");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ivanti Endpoint Manager 2022 SU7 or 2024 SU1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22466");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager");
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
  {'fixed_version':'11.0.5.2673', 'fixed_display':'11.0.5.2673 2022 SU7'},
  {'min_version':'11.0.6', 'fixed_version':'11.0.6.909', 'fixed_display':'11.0.6.909 2024 SU1'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
