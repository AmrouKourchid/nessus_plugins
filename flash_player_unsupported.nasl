##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59196);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/01");
  script_xref(name:"IAVA", value:"0001-A-0509");

  script_name(english:"Adobe Flash Player Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Adobe Flash
Player.");
  script_set_attribute(attribute:"description", value:
"There is at least one unsupported version of Adobe Flash Player
installed on the remote host.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.adobe.com/ie/products/flashplayer/end-of-life.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b67dd54d");
  script_set_attribute(attribute:"solution", value:
"Remove the unsupported software.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl", "macosx_flash_player_installed.nasl");
  script_require_ports("SMB/Flash_Player/installed", "MacOSX/Flash_Player/Version");

  exit(0);
}

include('ucf.inc');
include('vcf.inc');

var app = 'Adobe Flash Player';

var app_info;
var macos_ver = get_kb_item('MacOSX/Flash_Player/Version');
if (!empty_or_null(macos_ver))
{
  var path = get_kb_item_or_exit('MacOSX/Flash_Player/Path');
  app_info = {
    'version'        : macos_ver,
    'parsed_version' : vcf::parse_version(macos_ver),
    'app'            : 'Adobe Flash Player',
    'path'           : path,
    'cpe'            : 'cpe:/a:adobe:flash_player:' + macos_ver
  };
}
else
{
  app_info = vcf::combined_get_app_info(app:app);
}

var constraints = [
  { min_branch : '0', seol : 20201231}
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);