#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205387);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2024-25947",
    "CVE-2024-25948",
    "CVE-2024-38481",
    "CVE-2024-38489",
    "CVE-2024-38490"
  );
  script_xref(name:"IAVB", value:"2024-B-0112");

  script_name(english:"Dell iDRAC Service Module < 5.3.1.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a peripheral control application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Dell iDRAC Service Module version 5.3.0.0 and prior, contains multiple Out-of-bound Write Vulnerabilities. A 
privileged local attacker could execute arbitrary code potentially resulting in a denial of service event.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000227444/dsa-2024-086-security-update-for-dell-idrac-service-module-for-memory-corruption-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a1eb77c");
  script_set_attribute(attribute:"solution", value:
"Update Dell iDRAC Service Module to version 5.3.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:dell:idrac_service_module");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_idrac_service_module_win_installed.nbin");
  script_require_keys("installed_sw/iDRAC Service Module", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

# Only affects Windows
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::combined_get_app_info(app:'iDRAC Service Module');

var constraints = [
  { 'min_version' : '5.0.0.0', 'fixed_version' : '5.3.1.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
