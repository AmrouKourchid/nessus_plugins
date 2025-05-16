#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178437);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/19");

  script_cve_id("CVE-2023-25010", "CVE-2023-27906", "CVE-2023-27907");

  script_name(english:"Autodesk Maya USD Plugin < 0.23.0 Multiple Vulnerabilities (ADSK-SA-2023-0003)");

  script_set_attribute(attribute:"synopsis", value:
"The Autodesk Maya USD Plugin installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Maya USD Plugin installed on the remote host is prior to 0.23.0. It is, therefore, affected
by multiple vulnerabilities:

  - A malicious actor may convince a victim to open a malicious USD file that may trigger an uninitialized variable 
    which may result in code execution. (CVE-2023-25010)

  - A malicious actor may convince a victim to open a malicious USD file that may trigger an out-of-bounds read 
    vulnerability which may result in code execution. (CVE-2023-27906)
  
  - A malicious actor may convince a victim to open a malicious USD file that may trigger an out-of-bounds write 
    vulnerability which may result in code execution. (CVE-2023-27907)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/ADSK-SA-2023-0003");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk Maya USD Plugin version 0.23.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:maya");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_maya_win_plugins_detect.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/MayaUSD");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MayaUSD', win_local:TRUE);

var constraints = [ { 'fixed_version' : '0.23.0' } ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
