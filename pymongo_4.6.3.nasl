#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193202);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2024-5629");
  script_xref(name:"IAVB", value:"2024-B-0037");

  script_name(english:"PyMongo < 4.6.3 Out-of-bounds Read");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"Versions of the package pymongo before 4.6.3 are vulnerable to Out-of-bounds Read in the bson module. Using the crafted
payload the attacker could force the parser to deserialize unmanaged memory. The parser tries to interpret bytes next
to buffer and throws an exception with string. If the following bytes are not printable UTF-8 the parser throws an
exception with a single byte.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://gist.github.com/keltecc/62a7c2bf74a997d0a7b48a0ff3853a03
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8973be01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PyMongo or PyMongox version 4.6.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:pymongo");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
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

var pkg = 'pymongo';
var os_pkg = ldnix::search_packages([new('ldnix::pkg_target', 'python3-pymongo', '(python\\d*-pymongo)')]);
# if the package is found, the host has a version of pymongo backported by the OS vendor
if (!empty_or_null(os_pkg) && report_paranoia < 2)
  audit(AUDIT_MANAGED_INSTALL, pkg + ' Python package');

var os = 'nix';

var found_lib, libs = [];

found_lib = python::query_python_package(os:os, pkg_name:'pymongo');

if (!empty_or_null(found_lib))
  foreach (var found in found_lib)
  {
    found.pkg_name = 'pymongo';
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
  { 'fixed_version' : '4.6.3' }
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_HOLE);
