#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197939);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-34077", "CVE-2024-34080", "CVE-2024-34081");
  script_xref(name:"IAVB", value:"2024-B-0053-S");

  script_name(english:"MantisBT < 2.26.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MantisBT application hosted on the remote web server is prior to 2.26.2. 
It is, therefore, affected by the following vulnerabilities :

  - Insufficient access control in the registration and password reset process allows an attacker to reset another
    user's password and takeover their account, if the victim has an incomplete request pending. The exploit is only
    possible while the verification token is valid, i.e for 5 minutes after the confirmation URL sent by e-mail has 
    been opened, and the user did not complete the process by updating their password. (CVE-2024-34077)

  - If an issue references a note that belongs to another issue that the user doesn't have access to, then it gets 
    hyperlinked. Clicking on the link gives an access denied error as expected, yet some information remains available
    via the link, link label, and tooltip. (CVE-2024-34080)

  - Improper escaping of a custom field's name allows an attacker to inject HTML and, if CSP settings permit, achieve 
    execution of arbitrary JavaScript when resolving or closing issues belonging to a project linking said custom field,
    or viewing or printing issues when the custom field is displayed as a column. (CVE-2024-34081)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/mantisbt/mantisbt/security/advisories/GHSA-wgx7-jp56-65mq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5d86d4a");
  # https://github.com/mantisbt/mantisbt/security/advisories/GHSA-99jc-wqmr-ff2q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?373ab69e");
  # https://github.com/mantisbt/mantisbt/security/advisories/GHSA-93x3-m7pw-ppqm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?098d9ab5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MantisBT version 2.26.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34077");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mantisbt_detect.nbin");
  script_require_keys("installed_sw/MantisBT");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("vcf.inc");

var app = "MantisBT";

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { "fixed_version" : "2.26.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
