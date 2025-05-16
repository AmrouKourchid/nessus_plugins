#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187972);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2023-52323");
  script_xref(name:"IAVB", value:"2024-B-0003");

  script_name(english:"PyCryptodome < 3.19.1 Side Channel Leak");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PyCryptodome installed on the remote host is prior to 3.19.1. It is, 
therefore, affected by a vulnerability.

  - A side-channel leakage with OAEP decryption could be exploited to carry out
    a Manger attack. (CVE-2023-52323)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number. Also note that this plugin does not distinguish between Python packages installed via the OS package manager,
Python packages installed via PIP, or other sources. As a result, packages provided by your OS package repository may
have backported fixes that this plugin may incorrectly report as vulnerable. Please refer to the OS-specific plugins for
CVE-2023-52323 to check for backported fixes.");
  # https://github.com/Legrandin/pycryptodome/blob/b6ab9462d647f12c64d7950b4b81c2b9df3e6bc7/Changelog.rst
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fa6ab19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PyCryptodome or PyCryptodomex version 3.19.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52323");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:pycryptodome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("unix_enum_sw.nasl", "python_packages_installed_nix.nbin");
  script_require_keys("Host/nix/packages", "Host/nix/Python/Packages/Enumerated");

  exit(0);
}

include('vcf.inc');
include('python.inc');
include('local_detection_nix.inc');

get_kb_item_or_exit("Host/nix/Python/Packages/Enumerated");
get_kb_item_or_exit("Host/nix/packages");

var py_pkg = 'pycryptodome/pycryptodomex';
var os_pkg = ldnix::search_packages([new('ldnix::pkg_target', 'python3-pycryptodome', '(python\\d*-pycryptodomex?)')]);
# if the package is found, the host has a version of pycryptodome backported by the OS vendor
if (!empty_or_null(os_pkg) && report_paranoia < 2)
  audit(AUDIT_MANAGED_INSTALL, py_pkg + ' Python package');

var os = 'nix';

var pkgs = ['PyCryptodome', 'pycryptodome', 'pycryptodomex'];
var found_lib, libs = [];
foreach (var pkg in pkgs)
{
  found_lib = python::query_python_package(os:os, pkg_name:pkg);

  if (!empty_or_null(found_lib))
    foreach (var found in found_lib)
    {
      found.pkg_name = pkg;
      append_element(var:libs, value:found);
    }
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
  { 'fixed_version' : '3.19.1' }
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_WARNING);
