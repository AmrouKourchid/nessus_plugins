#%NASL_MIN_LEVEL 80900
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185931);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/17");

  script_cve_id("CVE-2022-45688", "CVE-2023-24998");
  script_xref(name:"IAVA", value:"2023-A-0559");

  script_name(english:"Oracle Business Process Management Suite (Oct 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Process Management Suite installed on the remote host is affected by 
multiple vulnerabilities, as referenced in the October 2023 CPU advisory. Specifically:

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
    (component: Runtime Engine (JSON-java)) affects versions 12.2.1.4.x < 12.2.1.4.231013. A stack 
    overflow in the XML.toJSONObject component of hutool-json v5.8.10 allows attackers to cause a 
    Denial of Service (DoS) via crafted JSON or XML data. (CVE-2022-45688)

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
    (component: Runtime Engine (Apache Commons FileUpload)) affects versions 12.2.1.4.x < 12.2.1.4.231013. 
    Apache Commons FileUpload before 1.5 does not limit the number of request parts to be processed 
    resulting in the possibility of an attacker triggering a DoS with a malicious upload or series of 
    uploads. Note that, like all of the file upload limits, the new configuration option 
    (FileUploadBase#setFileCountMax) is not enabled by default and must be explicitly configured. 
    (CVE-2023-24998)

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  # https://www.oracle.com/security-alerts/cpuoct2023.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e32d634e");
  # https://support.oracle.com/knowledge/Middleware/2806740_1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee8da7ad");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24998");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_process_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bpm_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Process Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Process Manager');

# fixed version is the lower of two acceptable fixes - 12.2.1.4.230827 and 12.2.1.4.231013
# according to https://support.oracle.com/knowledge/Middleware/2806740_1.html
var constraints = [
  { 'min_version':'12.2.1.4.0', 'fixed_version' : '12.2.1.4.230827' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
