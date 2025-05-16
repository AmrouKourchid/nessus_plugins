#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191550);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id("CVE-2023-6448");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/18");

  script_name(english:"Unitronics VisiLogic < 9.9.00 Default Password");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Unitronics VisiLogic installed on the remote host is prior to 9.9.00. It is, therefore, affected by a
vulnerability.

  - Unitronics VisiLogic before version 9.9.00, used in Vision and Samba PLCs and HMIs, uses a default
    administrative password. An unauthenticated attacker with network access can take administrative control
    of a vulnerable system. (CVE-2023-6448)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  #https://downloads.unitronicsplc.com/Sites/plc/Technical_Library/Unitronics-Cybersecurity-Advisory-2023-001-CVE-2023-6448.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac4f25a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade Unitronics VisiLogic to version 9.9.00 and follow the remediation advice from the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6448");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:unitronics:visilogic_oplc_ide");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("unitronics_visilogic_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Unitronics VisiLogic");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Unitronics VisiLogic', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.9.00' }
];

# Require paranoia as the vulnerablility is dependent on the project settings
# for PLC deployment and is not in the host application.
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    require_paranoia:TRUE
);
