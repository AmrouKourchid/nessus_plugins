#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206722);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2024-43805");
  script_xref(name:"IAVB", value:"2024-B-0128");

  script_name(english:"Jupyter Notebook Python Library 7.0.0 < 7.2.2 (CVE-2024-43805)");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"Jupyter Notebook is an extensible environment for interactive and reproducible computing. This vulnerability depends 
on user interaction by opening a malicious notebook with Markdown cells, or Markdown file using JupyterLab preview 
feature. A malicious user can access any data that the attacked user has access to as well as perform arbitrary 
requests acting as the attacked user. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/jupyterlab/jupyterlab/security/advisories/GHSA-9q39-rmj3-p4r2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5303029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jupyter Notebook version 7.2.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jupyter:notebook");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var pkg = 'notebook';

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
  
  os_pkg = ldnix::search_packages([new('ldnix::pkg_target', 'python3-notebook', '(python\\d*-notebook)')]);
  # if the package is found, the host has a version of notebook backported by the OS vendor
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
  { 'min_version' : '7.0.0', 'fixed_version': '7.2.2' },
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_WARNING);
