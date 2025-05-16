#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194749);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-28977");
  script_xref(name:"IAVB", value:"2024-B-0047");

  script_name(english:"Dell Repository Manager Path Traversal (DSA-2024-190)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by a path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"Dell Repository Manager, versions 3.4.2 through 3.4.4,contains a Path Traversal vulnerability in logger module. A
local attacker with low privileges could potentially exploit this vulnerability to gain unauthorized read access to
the files stored on the server filesystem with the privileges of the running web application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-uk/000224414/dsa-2024-190-security-update-for-dell-repository-manager-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?128aeac5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Repository Manager 3.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28977");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:repository_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_repository_manager_win_installed.nbin");
  script_require_keys("installed_sw/Repository Manager", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Repository Manager', win_local:TRUE);

var constraints = [
  { 'min_version' : '3.4.2', 'fixed_version' : '3.4.5' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
