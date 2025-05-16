#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216910);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id(
    "CVE-2023-2976",
    "CVE-2023-34624",
    "CVE-2023-42794",
    "CVE-2023-42795",
    "CVE-2023-45648",
    "CVE-2023-44487",
    "CVE-2024-20953"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Oracle Agile Product Lifecycle Management (PLM) 9.3.6.x < 9.3.6.26");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Agile Product Lifecycle Management (PLM) on the remote host is 9.3.6.x prior to 9.3.6.26. It is,
therefore, affected by multiple vulnerabilities, including:

  - Vulnerability in the Oracle Agile PLM product of Oracle Supply Chain (component: Export). The supported version
    that is affected is 9.3.6. Easily exploitable vulnerability allows low privileged attacker with network access via
    HTTP to compromise Oracle Agile PLM. Successful attacks of this vulnerability can result in takeover of Oracle
    Agile PLM. (CVE-2024-20953)
    
  - The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can
    reset many streams quickly, as exploited in the wild in August through October 2023. (CVE-2023-44487)
  
  - An issue was discovered htmlcleaner thru = 2.28 allows attackers to cause a denial of service or other unspecified
    impacts via crafted object that uses cyclic dependencies. (CVE-2023-34624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpujan2024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05d9c42d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Agile Product Lifecycle Management (PLM) version 9.3.6.26 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20953");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2976");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:agile_plm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_agile_plm_nix_installed.nbin", "oracle_agile_plm_win_installed.nbin");
  script_require_keys("installed_sw/Oracle Agile Product Lifecycle Management (PLM)");

  exit(0);
}

include('vcf.inc');

var win_local;
if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;
else
  win_local = FALSE;

var app_info = vcf::get_app_info(app:'Oracle Agile Product Lifecycle Management (PLM)', win_local:win_local);

var constraints = [ 
  {'min_version': '9.3.6', 'fixed_version': '9.3.6.26'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
