#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186480);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/05");

  script_cve_id(
    "CVE-2023-35136",
    "CVE-2023-37925",
    "CVE-2023-37926",
    "CVE-2023-4398",
    "CVE-2023-5650",
    "CVE-2023-5797"
  );
  script_xref(name:"IAVA", value:"2023-A-0655");

  script_name(english:"Zyxel USG / ATP / VPN < 5.37 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote security gateway is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Firmware version of the Zyxel USG, ATP, or VPN is less than 5.37. This means the Zyxel device is vulnerable to the 
following:

  - An integer overflow vulnerability in the source code of the QuickSec IPSec toolkit could allow an unauthenticated 
    attacker to cause denial-of-service (DoS) conditions on an affected device by sending a crafted IKE packet. 
    (CVE-2023-4398)

  - An improper input validation vulnerability in the “Quagga” package could allow an authenticated local attacker to 
    access configuration files on an affected device. (CVE-2023-35136)

  - An improper privilege management vulnerability in the debug CLI command could allow an authenticated local 
    attacker to access system files on an affected device. (CVE-2023-37925)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-firewalls-and-aps
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9098644");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zyxel USG / ATP / VPN to 5.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5797");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:zyxel:usg_flex");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ('ATP' >< model) 
  constraints = [{ 'min_version' : '4.32', 'fixed_version' : '5.38', 'fixed_display' : '5.37 Patch 1' }];
else if ('USG FLEX 50W' >< model || 'USG20W-VPN' >< model)
  constraints = [{ 'min_version' : '4.16', 'fixed_version' : '5.38', 'fixed_display' : '5.37 Patch 1' }];
else if ('USG FLEX' >< model)
  constraints = [{ 'min_version' : '4.50', 'fixed_version' : '5.38', 'fixed_display' : '5.37 Patch 1' }];
else if ('VPN' >< model )
  constraints = [{ 'min_version' : '4.30', 'fixed_version' : '5.38', 'fixed_display' : '5.37 Patch 1' }];
else
  audit(AUDIT_NOT_INST, 'Zyxel USG FLEX / USG FLEX 50W / USG20W-VPN / ATP / VPN Device');

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);