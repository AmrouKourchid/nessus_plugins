#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206676);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2024-45230", "CVE-2024-45231");
  script_xref(name:"IAVA", value:"2024-A-0540-S");

  script_name(english:"Python Library Django 4.2.x < 4.2.16 / 5.0.x < 5.0.9 / 5.1.x < 5.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The detected version of the Django Python package, Django, is 4.2.x prior to 4.2.16, 5.0.x prior to 5.0.9 or 5.1.x prior to 
5.1.1. It is, therefore, affected by multiple vulnerabilities as disclosed in Django's September 3rd 2024 security
advisory:

  - urlize and urlizetrunc were subject to a potential denial-of-service attack via very large inputs with a
  specific sequence of characters. (CVE-2024-45230)
 
  - Due to unhandled email sending failures, the django.contrib.auth.forms.PasswordResetForm class allowed
  remote attackers to enumerate user emails by issuing password reset requests and observing the outcomes.
  (CVE-2024-45231)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.djangoproject.com/weblog/2024/sep/03/security-releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Django version 4.2.16, 5.0.9, 5.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:djangoproject:django");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("unix_enum_sw.nasl", "os_fingerprint.nasl", "python_packages_installed_nix.nbin", "python_packages_win_installed.nbin");
  script_require_ports("Host/nix/Python/Packages/Enumerated", "Host/win/Python/Packages/Enumerated");

  exit(0);
}

include('vcf.inc');
include('python.inc');
include('local_detection_nix.inc');

var host_os = get_kb_item_or_exit('Host/OS');
var os = NULL;
var os_pkg = NULL;
var pkg = 'Django';

if('windows' >< tolower(host_os))
{
  os = 'win';
  get_kb_item_or_exit("Host/win/Python/Packages/Enumerated");
}
else 
{
  os = 'nix';
  get_kb_item_or_exit("Host/nix/Python/Packages/Enumerated");
  get_kb_item_or_exit("Host/nix/packages");
  
  os_pkg = ldnix::search_packages([new('ldnix::pkg_target', 'python3-django', '(python\\d*-[Dd]jango3?)')]);
  # if the package is found, the host has a version of django backported by the OS vendor
  if (!empty_or_null(os_pkg) && report_paranoia < 2)
    audit(AUDIT_MANAGED_INSTALL, pkg + ' Python package');
}

var found_lib, libs = [];

found_lib = python::query_python_package(os:os, pkg_name:pkg);

dbg::log(msg:'found_lib: ' + obj_rep(found_lib));

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
  { 'min_version' : '4.2' , 'fixed_version' : '4.2.16' },
  { 'min_version' : '5.0' , 'fixed_version' : '5.0.9' },
  { 'min_version' : '5.1' , 'fixed_version' : '5.1.1' }
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_WARNING);