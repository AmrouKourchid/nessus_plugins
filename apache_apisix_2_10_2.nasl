#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181928);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-43557");

  script_name(english:"Apache APISIX < 2.10.2 Security Bypass");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"The version of Apache APISIX installed on the remote host is prior to 2.10.2. It is, therefore, potentially affected by
a security bypass vulnerability. The uri-block plugin in Apache APISIX before 2.10.2 uses $request_uri without
verification. The $request_uri is the full original request URI without normalization. This makes it possible to
construct a URI to bypass the block list on some occasions. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/18jyd458ptocr31rnkjs71w4h366mv7h");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache APISIX version 2.10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43557");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:apisix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_apisix_http_detect.nbin");
  script_require_keys("installed_sw/Apache APISIX");

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:9080);
var app_info = vcf::get_app_info(app:'Apache APISIX', port:port, service:TRUE);

# Not able to check for mitigation
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

var constraints = [
  {'fixed_version': '2.10.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
