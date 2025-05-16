#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206738);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id("CVE-2024-42058");
  script_xref(name:"IAVA", value:"2024-A-0534");

  script_name(english:"Zyxel USG FLEX 4.20 < 5.39 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote security gateway is affected by a denial of service.");
  script_set_attribute(attribute:"description", value:
"The Firmware version of the Zyxel USG FLEX device is affected by a denial of service vulnerability.
A null pointer dereference vulnerability in some firewall versions could allow an unauthenticated 
attacker to cause DoS conditions by sending crafted packets to a vulnerable device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-firewalls-09-03-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?090fed1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zyxel USG FLEX to version 5.39 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:zyxel:usg_flex");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zyxel_usg_web_detect.nbin", "zyxel_usg_detect.nbin");
  script_require_keys("installed_sw/Zyxel Unified Security Gateway (USG)");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');

var app = 'Zyxel Unified Security Gateway (USG)';

var app_info = vcf::combined_get_app_info(app:app);

var model = app_info['Model'];
var constraints = [];

if(empty_or_null(model))
  audit(AUDIT_OS_CONF_UNKNOWN, 'Zyxel device');

if (model =~ "USG FLEX [25]0W?[^0]")
  constraints = [{'min_version':'4.20', 'fixed_version' : '5.39'}];
else
  audit(AUDIT_NOT_INST, 'Zyxel USG FLEX Device');

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);