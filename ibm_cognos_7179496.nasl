#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213474);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/16");

  script_cve_id("CVE-2024-40695", "CVE-2024-51466");
  script_xref(name:"IAVB", value:"2025-B-0001");

  script_name(english:"IBM Cognos Analytics 11.2.x < 11.2.4 FP5 / 12.0.x < 12.0.4 IF1 Multiple Vulnerabilities (7179496)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is prior to 11.2.4 FP5 or 12.0.4 IF1. It is, therefore,
affected by multiple vulnerabilities as referenced in the 7179496 advisory.

  - IBM Cognos Analytics is vulnerable to an Expression Language (EL) Injection vulnerability. A remote attacker could
    exploit this vulnerability to expose sensitive information, consume memory resources, and/or cause the server to 
    crash when using a specially crafted EL statement. (CVE-2024-51466)

  - IBM Cognos Analytics could be vulnerable to malicious file upload by not validating the content of the file 
    uploaded to the web interface. Attackers can make use of this weakness and upload malicious executable files into
    the system, and it can be sent to victim for performing further attacks. (CVE-2024-40695)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7179496");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics version 11.2.4 FP5 / 12.0.4 IF1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40695");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-51466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:cognos_analytics");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_cognos_analytics_web_detect.nbin");
  script_require_keys("installed_sw/IBM Cognos Analytics");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'IBM Cognos Analytics', port:port, webapp:TRUE);

var constraints = [
  {'min_version': '11.2.0', 'max_version': '11.2.3', 'fixed_display' : '11.2.4 FP5'},
  # AC detection does not pick up fix packs (FPs)
  {'equal': '11.2.4', 'fixed_display': '11.2.4 FP5', 'require_paranoia':TRUE},
  {'min_version': '12.0.0', 'max_version': '12.0.3', 'fixed_display' : '12.0.4 IF1'},
  # AC detection does not pick up Interim fix packs (IFs)
  {'equal': '12.0.4', 'fixed_display': '12.0.4 IF1', 'require_paranoia':TRUE},
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
