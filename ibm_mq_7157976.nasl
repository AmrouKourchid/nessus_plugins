#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201055);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2023-51775",
    "CVE-2024-22329",
    "CVE-2024-22353",
    "CVE-2024-22354",
    "CVE-2024-25026",
    "CVE-2024-27268"
  );

  script_name(english:"IBM MQ 9.1 <= 9.1.0.22 / 9.2 <= 9.2.0.26 / 9.3 < 9.3.0.20 LTS / 9.3 < 9.4 CD (7157976)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by multiple vulnerabilities as referenced in the
7157976 advisory.

  - IBM WebSphere Application Server 8.5, 9.0 and IBM WebSphere Application Server Liberty 17.0.0.3 through
    24.0.0.4 are vulnerable to a denial of service, caused by sending a specially crafted request. A remote
    attacker could exploit this vulnerability to cause the server to consume memory resources. IBM X-Force ID:
    281516. (CVE-2024-25026)

  - IBM WebSphere Application Server 8.5, 9.0 and IBM WebSphere Application Server Liberty 17.0.0.3 through
    24.0.0.5 are vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A
    remote attacker could exploit this vulnerability to expose sensitive information, consume memory
    resources, or to conduct a server-side request forgery attack. IBM X-Force ID: 280401. (CVE-2024-22354)

  - IBM WebSphere Application Server Liberty 18.0.0.2 through 24.0.0.4 is vulnerable to a denial of service,
    caused by sending a specially crafted request. A remote attacker could exploit this vulnerability to cause
    the server to consume memory resources. IBM X-Force ID: 284574. (CVE-2024-27268)

  - IBM WebSphere Application Server Liberty 17.0.0.3 through 24.0.0.4 is vulnerable to a denial of service,
    caused by sending a specially crafted request. A remote attacker could exploit this vulnerability to cause
    the server to consume memory resources. IBM X-Force ID: 280400. (CVE-2024-22353)

  - The jose4j component before 0.9.4 for Java allows attackers to cause a denial of service (CPU consumption)
    via a large p2c (aka PBES2 Count) value. (CVE-2023-51775)

  - IBM WebSphere Application Server 8.5, 9.0 and IBM WebSphere Application Server Liberty 17.0.0.3 through
    24.0.0.3 are vulnerable to server-side request forgery (SSRF). By sending a specially crafted request, an
    attacker could exploit this vulnerability to conduct the SSRF attack. X-Force ID: 279951. (CVE-2024-22329)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7157976");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 9.1.0.22 CU9, 9.2.0.26 CU9, 9.3.0.20 LTS, 9.4 CD or later. Alternatively, install  where appropriate.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27268");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:mq");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_mq_nix_installed.nbin", "websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere MQ';

var app_info = vcf::get_app_info(app:app);

if (app_info['Type'] != 'Server')
  audit(AUDIT_HOST_NOT, 'an affected product');

var constraints;
# check if CD - less than 4 version segments or non-0 3rd (M) segment
# https://www.ibm.com/support/pages/ibm-mq-faq-long-term-support-and-continuous-delivery-releases
if (app_info['version'] =~ "^9\.([0-9]+\.?){0,2}$" || app_info['version'] =~ "^9\.[0-9]\.[1-9]")
{
  constraints = [
    { 'min_version' : '9.3', 'fixed_version' : '9.4' }
  ];
}
else
{
  # Some versions require an interim fix, which we are not checking, so require paranoia for those versions only
  if ((app_info['version'] =~ "^9.1.0.22" || app_info['version'] =~ "^9.2.0.26") && report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, app, app_info['version']);
  constraints = [
    { 'min_version' : '9.1', 'max_version' : '9.1.0.22', 'fixed_display' : '9.1.0.22 CU9' },
    { 'min_version' : '9.2', 'max_version' : '9.2.0.26', 'fixed_display' : '9.2.0.26 CU9' },
    { 'min_version' : '9.3', 'fixed_version' : '9.3.0.20' }
  ];
}

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
