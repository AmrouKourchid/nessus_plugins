#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206689);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id("CVE-2024-40681");

  script_name(english:"IBM MQ 9.1 < 9.1.0.23 LTS / 9.2 < 9.2.0.27 LTS / 9.3 < 9.3.0.21 LTS / 9.3 < 9.4 CD / 9.4 < 9.4.0.5 LTS (7167208)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability as referenced in the 7167208
advisory.

  - IBM MQ could allow an authenticated user in a specifically defined role, to bypass security restrictions
    and execute actions against the queue manager. (CVE-2024-40681)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7167208");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 9.1.0.23 LTS, 9.2.0.27 LTS, 9.3.0.21 LTS, 9.4 CD, 9.4.0.5 LTS or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40681");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:mq");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  constraints = [
    { 'min_version' : '9.1', 'fixed_version' : '9.1.0.23' },
    { 'min_version' : '9.2', 'fixed_version' : '9.2.0.27' },
    { 'min_version' : '9.3', 'fixed_version' : '9.3.0.21' },
    { 'min_version' : '9.4', 'fixed_version' : '9.4.0.5' }
  ];
}

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
