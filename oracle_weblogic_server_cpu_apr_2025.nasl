#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234570);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2020-13936");
  script_xref(name:"IAVA", value:"2025-A-0268");

  script_name(english:"Oracle WebLogic Server (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0 and 14.1.1.0.0 versions of WebLogic Server installed on the remote host are affected by a vulnerability
as referenced in the April 2025 CPU advisory.

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Centralized 
    Thirdparty Jars (Apache Velocity Engine)). Supported versions that are affected are 12.2.1.4.0 and 
    14.1.1.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via 
    multiple protocols to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can 
    result in takeover of Oracle WebLogic Server.(CVE-2020-13936)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13936");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.250317', 'fixed_display' : '37714186' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.250320', 'fixed_display' : '37732915' }
];

vcf::oracle_weblogic::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
