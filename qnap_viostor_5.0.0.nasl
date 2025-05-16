#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, inc.
##

include('compat.inc');

if (description)
{
  script_id(189226);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/19");

  script_cve_id("CVE-2023-47565");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/01/11");

  script_name(english:"Qnap VioStor < 5.0.0 Command Injection (CVE-2023-47565)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web application that is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Qnap VioStor installed on the remote host is prior to 5.0.0. It is, therefore, affected by an
OS command injection vulnerability. If exploited, the vulnerability could allow authenticated users to execute 
commands.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-23-48");
  script_set_attribute(attribute:"solution", value:
"Upgrade Qnap VioStor QVR Firmware 5.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47565");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:viostor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_viostor_detect.nbin");
  script_require_keys("installed_sw/Qnap VioStor");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'Qnap VioStor';
var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { 'min_version': '4.0.0', 'fixed_version' : '5.0.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

