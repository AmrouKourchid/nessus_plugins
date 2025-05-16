#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207740);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2024-40703");
  script_xref(name:"IAVB", value:"2024-B-0140-S");

  script_name(english:"IBM Cognos Analytics 11.2.x < 11.2.4 FP4 Interim Fix 2 / 12.0.x < 12.0.3 Interim Fix 2 (7160700)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is either prior to 11.2.4 FP4 Interim Fix 2 or i
12.0.3 Interim Fix 2. It is, therefore, affected by an exposed API key  as referenced in the IBM Security Bulletin No. 
7160700:

   - A local attacker could obtain sensitive information in the form of an API key. An attacker could then use this 
     information to launch further attacks against affected applications.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7160700");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics version 11.2.4 FP4 Interim Fix 2 / 12.0.3 Interim Fix 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:cognos_analytics");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '11.2.0', 'max_version' : '11.2.4.99999', 'fixed_display' : '11.2.4 FP4 Interim Fix 2', 'require_paranoia' : TRUE },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.0.3.99999', 'fixed_display' : '12.0.3 Interim Fix 2', 'require_paranoia' : TRUE }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
