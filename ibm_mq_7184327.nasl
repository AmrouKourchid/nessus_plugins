#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232731);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id("CVE-2025-23225");
  script_xref(name:"IAVA", value:"2025-A-0144");

  script_name(english:"IBM MQ DoS (7184327)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability as referenced in the 7184327
advisory.

  - IBM MQ 9.3 LTS, 9.3 CD, 9.4 LTS, and 9.4 CD could allow an authenticated user to cause a denial of 
    service due to the improper handling of invalid headers sent to the queue. (CVE-2025-23225)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7184327");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 9.1.0.27 LTS, 9.2.0.31 LTS, 9.3.0.27 LTS, 9.4.0.10 LTS, 9.4.2 CD or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23225");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:mq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'min_version' : '9.3', 'max_version' : '9.3.999', 'fixed_version' : '9.4.2' },
    { 'min_version' : '9.4', 'fixed_version' : '9.4.2' }
  ];
}
else
{
  constraints = [
    { 'min_version' : '9.1', 'fixed_version' : '9.1.0.27' },
    { 'min_version' : '9.2', 'fixed_version' : '9.2.0.31' },
    { 'min_version' : '9.3', 'fixed_version' : '9.3.0.27' },
    { 'min_version' : '9.4', 'fixed_version' : '9.4.0.10' }
  ];
}

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
