#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178850);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/25");

  script_cve_id(
    "CVE-2023-1370",
    "CVE-2022-24999",
    "CVE-2023-25929",
    "CVE-2023-28530"
  );
  script_xref(name:"IAVB", value:"2023-B-0055-S");

  script_name(english:"IBM Cognos Analytics Multiple Vulnerabilities (7012621)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is 11.1.x prior to 11.1.7 Fix Pack 7 or 11.2.x 
prior to 11.2.4 FP2. It is, therefore, affected by multiple vulnerabilities, including the following:

  - netplex json-smart-v2 is vulnerable to a denial of service, caused by not limiting the nesting of arrays
  or objects. By sending a specially crafted input, a remote attacker could exploit this vulnerability to
  cause a stack exhaustion and crash the software. (CVE-2023-1370)

  - Express.js Express is vulnerable to a denial of service, caused by a prototype pollution flaw in qs. By
  adding or modifying properties of Object.prototype using a __proto__ or constructor payload, a remote
  attacker could exploit this vulnerability to cause a denial of service condition. (CVE-2022-24999)

  - IBM Cognos Analytics is vulnerable to stored cross-site scripting, caused by improper validation of SVG
  Files in Custom Visualizations. A remote attacker could exploit this vulnerability to execute scripts in a
  victim's Web browser within the security context of the hosting Web site. An attacker could use this
  vulnerability to steal the victim's cookie-based authentication credentials. (CVE-2023-28530)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7012621");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics 11.1.7 FP7, 11.2.4 FP2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28530");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:cognos_analytics");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_cognos_analytics_web_detect.nbin");
  script_require_keys("installed_sw/IBM Cognos Analytics");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'IBM Cognos Analytics';

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);


var constraints = [
  { 'min_version':'11.1', 'max_version':'11.1.6', 'fixed_display':'11.1.7 FP7' },
# Remote detection cannot determine fix pack
  { 'equal':'11.1.7', 'fixed_display':'11.1.7 FP7', 'require_paranoia':TRUE },
  { 'min_version':'11.2', 'fixed_version':'11.2.3', 'fixed_display':'11.2.4 FP2'},
# Remote detection cannot determine fix pack
  { 'equal':'11.2.4', 'fixed_display':'11.2.4 FP2', 'require_paranoia':TRUE }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});