#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181675);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-32784");

  script_name(english:"Keepass < 2.54 Information disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a 
workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), 
hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, 
there is different API usage and/or random string insertion for mitigation.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vdohney/keepass-password-dumper");
  # https://sourceforge.net/p/keepass/discussion/329220/thread/f3438e6283/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf0fd50c");
  script_set_attribute(attribute:"solution", value:
"Update the affected keepass package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:keepass:keepass");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("keepass_win_installed.nbin");
  script_require_keys("installed_sw/KeePass");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'KeePass');

var constraints = [
  {'min_version' : '2.00', 'fixed_version' : '2.54'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
