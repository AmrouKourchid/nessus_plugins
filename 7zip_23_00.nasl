#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180360);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2023-31102", "CVE-2023-40481");
  script_xref(name:"IAVA", value:"2023-A-0440-S");

  script_name(english:"7-Zip < 23.00 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A compression utility installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of 7-Zip installed on the remote Windows host is below 23.00. It is, therefore, affected by multiple
vulnerabilities:

  - A remote code execution vulnerability exists in 7-zip due to an integer underflow. An unauthenticated,
    remote attacker can exploit this, by tricking a user into opening a specially crafted archive, to execute
    arbitrary code on the system. (CVE-2023-31102)

  - A remote code execution vulnerability exists in 7-zip due to an out-of-bounds write. An unauthenticated,
    remote attacker can exploit this, by tricking a user into opening a specially crafted archive, to execute
    arbitrary code on the system. (CVE-2023-40481)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.7-zip.org/history.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1164/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7-Zip version 23.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40481");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-31102");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("7zip_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/7-Zip");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'7-Zip', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '23.00' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
