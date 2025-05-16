#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200807);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2024-37891");
  script_xref(name:"IAVA", value:"2024-A-0363");

  script_name(english:"urllib3 Python Library < 1.26.19, < 2.2.2 (CVE-2024-37891)");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"urllib3 is a user-friendly HTTP client library for Python. When using urllib3's proxy support with 'ProxyManager', the 
'Proxy-Authorization' header is only sent to the configured proxy, as expected. However, when sending HTTP requests 
without using urllib3's proxy support, it's possible to accidentally configure the 'Proxy-Authorization' header even 
though it won't have any effect as the request is not using a forwarding proxy or a tunneling proxy. In those cases, 
urllib3 doesn't treat the 'Proxy-Authorization' HTTP header as one carrying authentication material and thus doesn't 
strip the header on cross-origin redirects. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/urllib3/urllib3/security/advisories/GHSA-34jh-p97f-mpxf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b44847c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to urllib3 version 1.26.19, 2.2.2  or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37891");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:urllib3");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
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
var pkg = 'urllib3';

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
  
  os_pkg = ldnix::search_packages([new('ldnix::pkg_target', 'python3-urllib3', '(python\\d*-urllib3?)')]);
  # if the package is found, the host has a version of urllib3 backported by the OS vendor
  if (!empty_or_null(os_pkg) && report_paranoia < 2)
    audit(AUDIT_MANAGED_INSTALL, pkg + ' Python package');
}

var found_lib, libs = [];
found_lib = python::query_python_package(os:os, pkg_name:pkg);

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
  'path' : lib.path
};

var constraints = [
  { 'fixed_version' : '1.26.19' },
  { 'min_version' : '2.0', 'fixed_version' : '2.2.2'}
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_WARNING);
