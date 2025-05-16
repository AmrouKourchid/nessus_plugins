#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235780);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2025-32873");
  script_xref(name:"IAVA", value:"2025-A-0317");

  script_name(english:"Python Library Django 4.2.x < 4.2.21 / 5.1.x < 5.1.9 / 5.2.x < 5.2.1 DoS");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote Windows host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The detected version of the Django Python package, Django, is 4.2.x prior to 4.2.21 or 5.1.x prior to 5.1.9 or 5.2.x 
prior to 5.2.1.

It is, therefore, affected by a denial of service vulnerability as disclosed in Django's May 7th 2025 security 
advisory. The django.utils.html.strip_tags() function is vulnerable to a potential denial-of-service (slow performance) 
when processing inputs containing large sequences of incomplete HTML tags. The template filter striptags is also 
vulnerable, because it is built on top of strip_tags().

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.djangoproject.com/weblog/2025/may/07/security-releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Django version 4.2.21 ,5.1.9, 5.2.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32873");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:djangoproject:django");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_packages_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "Host/win/Python/Packages/Enumerated");

  exit(0);
}

include('vcf.inc');
include('python.inc');

if (!get_kb_item('SMB/Registry/Enumerated'))
  audit(AUDIT_OS_NOT, 'Windows');

var os = 'win';
var os_pkg = NULL;
var pkg = 'Django';

var found_lib, libs = [];

found_lib = python::query_python_package(os:os, pkg_name:pkg);

dbg::detailed_log(
  lvl: 1,
  msg: 'Found python lib',
  msg_details: {
    'found_lib': {'lvl': 1, 'value': found_lib}});

if (!empty_or_null(found_lib))
  foreach (var found in found_lib)
  {
    found.pkg_name = pkg;
    append_element(var:libs, value:found);
  }

if (empty_or_null(libs))
  audit(AUDIT_HOST_NOT, 'affected');

var lib = branch(libs);
var lib_info = {
  'app' : lib.pkg_name,
  'version' : lib.version,
  'display_version' : lib.version,
  'parsed_version' : vcf::parse_version(lib.version),
  'path' : lib.path + '/' + lib.pkg_name
};

var constraints = [
  { 'min_version' : '4.2' , 'fixed_version' : '4.2.21' },
  { 'min_version' : '5.1' , 'fixed_version' : '5.1.9' },
  { 'min_version' : '5.2' , 'fixed_version' : '5.2.1' }
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_WARNING);
