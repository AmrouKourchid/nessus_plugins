#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194848);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/30");

  script_cve_id("CVE-2023-33850", "CVE-2024-20952");

  script_name(english:"IBM MQ 9.0 <= 9.0.0.24 / 9.1 <= 9.1.0.21 / 9.2 <= 9.2.0.25 / 9.3 <= 9.3.0.17 / 9.3 <= 9.3.5.1 (7149586)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by multiple vulnerabilities as referenced in the
7149586 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Security). Supported versions that are affected are Oracle Java SE: 8u391,
    8u391-perf, 11.0.21, 17.0.9, 21.0.1; Oracle GraalVM for JDK: 17.0.9, 21.0.1; Oracle GraalVM Enterprise
    Edition: 20.3.12, 21.3.8 and 22.3.4. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition accessible data as well as unauthorized access to critical data or complete
    access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2024-20952)

  - IBM GSKit-Crypto could allow a remote attacker to obtain sensitive information, caused by a timing-based
    side channel in the RSA Decryption implementation. By sending an overly large number of trial messages for
    decryption, an attacker could exploit this vulnerability to obtain sensitive information. IBM X-Force ID:
    257132. (CVE-2023-33850)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7149586");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 9.0.0.24 CU9, 9.1.0.21 CU9, 9.2.0.25 CU9, 9.3.0.17 CU9, 9.3.5.1 CU9 CD or later. Alternatively,
install  where appropriate.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/30");

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
  # Some IBM MQ CD versions require an interim fix, which we are not checking, so require paranoia for those versions only
  if ((app_info['version'] =~ "^9.3([^0-9]|$)") && report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, app, app_info['version']);
  constraints = [
    { 'min_version' : '9.3', 'max_version' : '9.3.5.1', 'fixed_display' : '9.3.5.1 CU9' }
  ];
}
else
{
  # Some versions require an interim fix, which we are not checking, so require paranoia for those versions only
  if ((app_info['version'] =~ "^9.0.0.24" || app_info['version'] =~ "^9.1.0.21" || app_info['version'] =~ "^9.2.0.25" || app_info['version'] =~ "^9.3.0.17") && report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, app, app_info['version']);
  constraints = [
    { 'min_version' : '9.0', 'max_version' : '9.0.0.24', 'fixed_display' : '9.0.0.24 CU9' },
    { 'min_version' : '9.1', 'max_version' : '9.1.0.21', 'fixed_display' : '9.1.0.21 CU9' },
    { 'min_version' : '9.2', 'max_version' : '9.2.0.25', 'fixed_display' : '9.2.0.25 CU9' },
    { 'min_version' : '9.3', 'max_version' : '9.3.0.17', 'fixed_display' : '9.3.0.17 CU9' }
  ];
}

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
