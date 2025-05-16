#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191429);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id(
    "CVE-2022-4203",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215",
    "CVE-2023-0216",
    "CVE-2023-0217",
    "CVE-2023-0286",
    "CVE-2023-0401",
    "CVE-2023-1255",
    "CVE-2023-2454",
    "CVE-2023-2455",
    "CVE-2023-2650",
    "CVE-2023-2975",
    "CVE-2023-3446",
    "CVE-2023-3817",
    "CVE-2023-25690",
    "CVE-2023-27522",
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27537",
    "CVE-2023-27538",
    "CVE-2023-28319",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322",
    "CVE-2023-28709",
    "CVE-2023-30581",
    "CVE-2023-30582",
    "CVE-2023-30583",
    "CVE-2023-30584",
    "CVE-2023-30585",
    "CVE-2023-30586",
    "CVE-2023-30587",
    "CVE-2023-30588",
    "CVE-2023-30589",
    "CVE-2023-30590",
    "CVE-2023-31124",
    "CVE-2023-31130",
    "CVE-2023-31147",
    "CVE-2023-32002",
    "CVE-2023-32003",
    "CVE-2023-32004",
    "CVE-2023-32005",
    "CVE-2023-32006",
    "CVE-2023-32067",
    "CVE-2023-32558",
    "CVE-2023-32559",
    "CVE-2023-34035",
    "CVE-2023-35945",
    "CVE-2023-38039",
    "CVE-2023-38199",
    "CVE-2023-38545",
    "CVE-2023-38546",
    "CVE-2023-39417",
    "CVE-2023-39418",
    "CVE-2023-41080",
    "CVE-2023-46120",
    "CVE-2024-23810",
    "CVE-2024-23811",
    "CVE-2024-23812"
  );
  script_xref(name:"ICSA", value:"24-046-15");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"Siemens SINEC NMS < V2.0 SP1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Siemens SINEC NMS Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens SINEC NMS installed on the remote host is prior to 2.0.1.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA-943925 advisory.

  - coreruleset (aka OWASP ModSecurity Core Rule Set) through 3.3.4 does not detect multiple Content-Type
    request headers on some platforms. This might allow attackers to bypass a WAF with a crafted payload,
    aka Content-Type confusion between the WAF and the backend application. This occurs when the web
    application relies on only the last Content-Type header. Other platforms may reject the additional
    Content-Type header or merge conflicting headers, leading to detection as a malformed header.
    (CVE-2023-38199)

  - Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request
    Smuggling attack. Configurations are affected when mod_proxy is enabled along with some form of
    RewriteRule or ProxyPassMatch in which a non-specific pattern matches some portion of the user-supplied
    request-target (URL) data and is then re-inserted into the proxied request-target using variable
    substitution. For example, something like: RewriteEngine on RewriteRule ^/here/(.*)
    http://example.com:8080/elsewhere?$1; [P] ProxyPassReverse /here/ http://example.com:8080/ Request
    splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended
    URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version
    2.4.56 of Apache HTTP Server. (CVE-2023-25690)

  - The use of `Module._load()` can bypass the policy mechanism and require modules outside of the policy.json
    definition for a given module. This vulnerability affects all users using the experimental policy
    mechanism in all active release lines: 16.x, 18.x and, 20.x. Please note that at the time this CVE was
    issued, the policy is an experimental feature of Node.js. (CVE-2023-32002)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-24-046-15");
  # https://cert-portal.siemens.com/productcert/html/ssa-943925.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6bd043b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Siemens SINEC NMS Server version 2 Service Pack 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23810");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siemens:sinec_nms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_sinec_nms_win_installed.nbin");
  script_require_keys("installed_sw/SINEC NMS");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'SINEC NMS');
var constraints = [{'fixed_version': '2.0.1.0', 'fixed_display': 'V2.0 SP1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
