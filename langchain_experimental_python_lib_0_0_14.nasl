#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206977);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id("CVE-2023-44467");

  script_name(english:"LangChain Experimental Python Library <= 0.0.14 (CVE-2023-44467)");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"LangChain is a framework for developing applications powered by large language models. langchain_experimental (aka 
LangChain Experimental) in LangChain <= 0.0.14 allows an attacker to bypass the CVE-2023-36258 fix and execute 
arbitrary code via __import__ in Python code, which is not prohibited by pal_chain/base.py. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-gjjr-63x4-v8cq");
  # https://github.com/langchain-ai/langchain/commit/4c97a10bd0d9385cfee234a63b5bd826a295e483
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb012fde");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LangChain Experimental version 0.0.15 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44467");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:langchain:langchain_experimental");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "python_packages_installed_nix.nbin", "python_packages_win_installed.nbin");
  script_require_ports("Host/nix/Python/Packages/Enumerated", "Host/win/Python/Packages/Enumerated");

  exit(0);
}

include('vcf.inc');
include('python.inc');

var host_os = get_kb_item_or_exit('Host/OS');
var os = NULL;

if('windows' >< tolower(host_os))
{
  os = 'win';
  get_kb_item_or_exit("Host/win/Python/Packages/Enumerated");
}
else
{
  os = 'nix';
  get_kb_item_or_exit("Host/nix/Python/Packages/Enumerated");
}

var pkg = 'langchain_experimental';
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
  'path' : lib.path + '/' + lib.pkg_name
};

var constraints = [
  { 'fixed_version' : '0.0.15' },
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_HOLE);
