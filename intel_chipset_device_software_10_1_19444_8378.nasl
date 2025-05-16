#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186475);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/29");

  script_cve_id("CVE-2023-28388", "CVE-2024-21814", "CVE-2023-28388");
  script_xref(name:"IAVA", value:"2023-A-0652-S");
  script_xref(name:"IAVA", value:"2024-A-0300");

  script_name(english:"Intel Chipset Device Software < 10.1.19444.8378 Escalation of Privilege");

  script_set_attribute(attribute:"synopsis", value:
"A driver management application installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Intel Chipset Device Software installed on the remote Windows host is prior to 10.1.19444.8378. It is,
therefore, affected by multiple vulnerabilities: 

  - Due to an uncontrolled search path element, an authenticated, local attacker can elevate their privileges.
    (CVE-2023-28388, CVE-2024-21814)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00870.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ecbc9ca");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01032.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d63a61d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Intel Chipset Device Software version 10.1.19444.8378 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21814");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:chipset_device_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_chipset_device_software_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Intel Chipset Device Software");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Intel Chipset Device Software', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '10.1.19444.8378' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
