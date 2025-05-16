#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192942);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-2658");
  script_xref(name:"IAVB", value:"2024-B-0031");

  script_name(english:"Flexera FlexNet Publisher < 11.19.6 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A licensing application running on the remote host is affected by a privilege escalation vulnerabillity.");
  script_set_attribute(attribute:"description", value:
"A privilege escalation vulnerability exists in Flexera FlexNet Publisher due to an uncontrolled search path element.
An authenticated, local attacker can exploit this, to gain elevated privileges access to the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.flexera.com/t5/FlexNet-Publisher-Knowledge-Base/CVE-2024-2658-FlexNet-Publisher-potential-local-privilege/ta-p/313003
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4034d0f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FlexNet Publisher 11.19.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2658");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:flexerasoftware:flexnet_publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("flexnet_publisher_detection.nbin", "flexnet_publisher_11_16_5_1_multi_vulns.nasl");
  script_require_keys("Services/flexnet_publisher");

  exit(0);
}

include('vcf.inc');

var app = 'FlexNet Publisher';
var svc = 'flexnet_publisher';
var port = get_service(svc:svc, exit_on_fail:TRUE);

# There are two versions of the license server manager:
# lmgrd – the original license server manager with a command-line interface.
# lmadmin – a newer web-based license server manager
# The advisory states that only lmadmin.exe is vulnerable
var exe = get_one_kb_item('flexnet_publisher/lmgrd');

var exit_msg = strcat(
  'The ' + app + ' install detected on port ' + port +
  ' appears to running lmgrd.exe. Only installs running ' +
  'lmadmin.exe are vulnerable.' 
  );

if (exe)
  exit(0, exit_msg);

var app_info = vcf::get_app_info(app:app, kb_ver: svc + '/' + port + '/Version', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'fixed_version': '11.19.6.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
