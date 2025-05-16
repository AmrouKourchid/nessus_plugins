#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186666);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/11");

  script_cve_id("CVE-2023-39256", "CVE-2023-39257", "CVE-2023-43089");
  script_xref(name:"IAVB", value:"2023-B-0095");

  script_name(english:"Dell Rugged Control Center < 4.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a peripheral control application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Rugged Control Center installed on the remote host is prior to 4.7. It is, therefore, affected by
multiple vulnerabilities as described in the DSA-2023-340 and DSA-2023-371 advisories.

 - Improper access control vulnerability whereby a local attacker, with standard user privileges, can modify
   an unsecured folder, leading to privilege escalation during product installation or upgrade.
   (CVE-2023-39256)

 - Improper access control vulnerability whereby a local attacker, with standard user privileges, can modify
   an unsecured folder, leading to privilege escalation during product installation repair (CVE-2023-39257)

 - Insufficient protection for the Policy folder meaning a local attacker, with standard privileges can
   modify the contents of the policy file leading to unauthorized access to resources. (CVE-2023-43089)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000218066/dsa-2023-371");
  # https://www.dell.com/support/kbdoc/en-us/000217705/dsa-2023-340-security-update-for-dell-rugged-control-center-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ceb914e");
  script_set_attribute(attribute:"solution", value:
"Update Dell Rugged Control Center to version 4.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:rugged_control_center");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_rugged_control_center_win_installed.nbin");
  script_require_keys("installed_sw/Dell Rugged Control Center");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell Rugged Control Center', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '4.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

