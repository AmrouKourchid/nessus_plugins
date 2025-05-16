#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192685);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2024-28863");
  script_xref(name:"IAVB", value:"2024-B-0027");

  script_name(english:"Node.js Module node-tar < 6.2.1 DoS");

  script_set_attribute(attribute:"synopsis", value:
"A module in the Node.js JavaScript run-time environment is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"In the nodejs module node-tar prior to version 6.2.1, there is no validation of the number of folders created while
unpacking a file. As a result, an attacker can use a malicious file to exhaust the CPU and memory on the host and crash
the nodejs client.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/isaacs/node-tar/security/advisories/GHSA-f5x3-32g6-xq36
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b8d8923");
  script_set_attribute(attribute:"solution", value:
"Upgrade to node-tar version 6.2.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:node-tar_project:node-tar");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_modules_win_installed.nbin", "nodejs_modules_linux_installed.nbin", "nodejs_modules_mac_installed.nbin");
  script_require_keys("Host/nodejs/modules/enumerated");

  exit(0);
}

include('vcf_extras_nodejs.inc');

get_kb_item_or_exit('Host/nodejs/modules/enumerated');
var app_info = vcf_extras::nodejs_modules::get_app_info(app:'tar');

var constraints = [
  { 'fixed_version' : '6.2.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

