#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174466);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2023-0215");
  script_xref(name:"IAVA", value:"2023-A-0212-S");

  script_name(english:"Oracle MySQL Workbench <= 8.0.32 (April 2023)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a Use After Free vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL Workbench installed on the remote Windows host is prior to 8.0.32. It is, therefore, 
affected by a Use After Free vulnerability in the MySQL Workbench product of Oracle MySQL (component: Workbench: 
OpenSSL). Supported versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability which allows a 
low privileged attacker with network access via MySQL Workbench to compromise MySQL Workbench. Successful attacks of 
this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) 
of MySQL Workbench.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e8adfc4");
  # https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4c2a110");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle MySQL Workbench version 8.0.33 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_workbench");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql_workbench");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_workbench_win_installed.nbin");
  script_require_keys("installed_sw/MySQL Workbench");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MySQL Workbench');
var constraints = [{'fixed_version': '8.0.33'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);