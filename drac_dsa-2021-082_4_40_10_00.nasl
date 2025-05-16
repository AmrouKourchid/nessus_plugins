#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182918);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id("CVE-2021-21538");

  script_name(english:"Dell EMC iDRAC9 4.40.00.00 < 4.40.10.00 (DSA-2021-082)");

  script_set_attribute(attribute:"synopsis", value:
"Dell EMC iDRAC9 installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC iDRAC9 installed on the remote host is prior to 4.40.10.00. It is, therefore, affected by a
vulnerability as referenced in the DSA-2021-082 advisory.

  - Dell EMC iDRAC9 versions 4.40.00.00 and later, but prior to 4.40.10.00, contain an improper authentication
    vulnerability. A remote unauthenticated attacker could potentially exploit this vulnerability to gain
    access to the virtual console. (CVE-2021-21538)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000186420/dsa-2021-082-dell-emc-idrac-9-security-update-for-improper-authentication-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59c74c7d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC iDRAC9 version 4.40.10.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21538");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:emc_idrac9");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:dell:emc_idrac9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");

  exit(0);
}

include('vcf_extras.inc');
include('http.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::idrac::get_app_info(port:port);
var constraints = [
{ 'min_version' : '4.40.00.00', 'fixed_version' : '4.40.10.00', 'idrac' : '9' }
];
vcf::idrac::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
