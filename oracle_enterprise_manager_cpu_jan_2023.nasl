#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170135);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id("CVE-2022-25647");
  script_xref(name:"IAVA", value:"2023-A-0038");
  script_xref(name:"IAVA", value:"2023-A-0558");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 13.4.0.0 and 13.5.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by
a vulnerabiliy in the Application Config Console (Google Gson) component as referenced in the January 2023 CPU advisory.
Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Enterprise
Manager Base Platform. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of Enterprise Manager Base Platform.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25647");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Cloud Control');

var constraints = [
  { 'min_version' : '13.4.0.0', 'fixed_version' : '13.4.0.19', 'fixed_display' : '13.4.0.19 (Patch 34860945)' },
  { 'min_version' : '13.5.0.0', 'fixed_version' : '13.5.0.12', 'fixed_display' : '13.5.0.12 (Patch 34795383)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
