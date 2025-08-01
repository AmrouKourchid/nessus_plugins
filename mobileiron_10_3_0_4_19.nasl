#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141366);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/29");

  script_cve_id("CVE-2020-15505", "CVE-2020-15506", "CVE-2020-15507");
  script_xref(name:"IAVA", value:"2020-A-0424");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"MobileIron Core 10.3.0.x < 10.3.0.4-19 / 10.4.0.x < 10.4.0.4-22 / 10.5.1.1 < 10.5.1.1-22 / 10.5.2.1 < 10.5.2.1-14 / 10.6.0.1 < 10.6.0.1-19 / 10.7.0.0 < 10.7.0.0-28");

  script_set_attribute(attribute:"synopsis", value:
"A MobileIron application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of MobileIron Core on the remote host is affected
  by multiple vulnerabilities: 

    - A remote command execution vulnerability exists in MobileIron Core and Connector versions 10.6 
      and earlier, and Sentry versions 9.8 and earlier.  An unauthenticated, remote attacker can 
      exploit this to bypass authentication and execute arbitrary commands as root.  (CVE-2020-15505)

    - An arbitrary file read vulnerability exists in MobileIron Core and Connector versions 10.6 
      and earlier. An unauthenticated, remote attacker can exploit this to read arbitrary files 
      and disclose sensitive information. (CVE-2020-15507)

    - An authentication bypass vulnerability exists in MobileIron Core and Connector versions 10.6 
      and earlier. An unauthenticated, remote attacker can exploit this to bypass authentication 
      and execute arbitrary actions with escalated privileges. (CVE-2020-15506)
 
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version");
  # https://www.mobileiron.com/en/blog/mobileiron-security-updates-available
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a8249df");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MobileIron version 10.3.0.4-19, 10.4.0.4-22, 10.5.1.1-22, 10.5.2.1-14, 10.6.0.1-19, 10.7.0.0-28 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15506");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MobileIron MDM Hessian-Based Java Deserialization RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mobileiron:mobileiron_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mobileiron_core_detect.nbin");
  script_require_keys("installed_sw/MobileIron Core");

  exit(0);
}

include('vcf.inc');

var app_name = 'MobileIron Core';
var app_info = NULL;

if (report_paranoia < 2)
  app_info = vcf::get_app_info(app:app_name);
else
  app_info = vcf::combined_get_app_info(app:app_name);

var constraints = [
  {'min_version':'10.3.0', fixed_version:'10.3.0.4.19', 'fixed_display':'10.3.0.4-19'},
  {'min_version':'10.4.0', fixed_version:'10.4.0.4.22', 'fixed_display':'10.4.0.4-22'},
  {'min_version':'10.5.1', fixed_version:'10.5.1.1.25', 'fixed_display':'10.5.1.1-25'},
  {'min_version':'10.5.2', fixed_version:'10.5.2.1.14', 'fixed_display':'10.5.2.1-14'},
  {'min_version':'10.6.0', fixed_version:'10.6.0.1.19', 'fixed_display':'10.6.0.1-19'},
  {'min_version':'10.7.0', fixed_version:'10.7.0.0.28', 'fixed_display':'10.7.0.0-28'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
