#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206735);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id(
    "CVE-2024-6343",
    "CVE-2024-42057",
    "CVE-2024-42058",
    "CVE-2024-42060",
    "CVE-2024-42061"
  );
  script_xref(name:"IAVA", value:"2024-A-0534");

  script_name(english:"Zyxel USG FLEX 4.50 < 5.39 / ATP 4.32 < 5.39 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote security gateway is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Firmware version of the Zyxel USG / ATP device is affected by multiple vulnerabilities: 

  - A command injection vulnerability in the IPSec VPN feature of Zyxel ATP series firmware versions
    from V4.32 through V5.38, USG FLEX series firmware versions from V4.50 through V5.38, USG FLEX 
    50(W) series firmware versions from V4.16 through V5.38, and USG20(W)-VPN series firmware versions 
    from V4.16 through V5.38 could allow an unauthenticated attacker to execute some OS commands on an 
    affected device by sending a crafted username to the vulnerable device. Note that this attack could 
    be successful only if the device was configured in User-Based-PSK authentication mode and a valid 
    user with a long username exceeding 28 characters exists. (CVE-2024-42057)

  - A buffer overflow vulnerability in the CGI program of Zyxel ATP series firmware versions from 
    V4.32 through V5.38, USG FLEX series firmware versions from V4.50 through V5.38, USG FLEX 50(W) 
    series firmware versions from V4.16 through V5.38, and USG20(W)-VPN series firmware versions 
    from V4.16 through V5.38 could allow an authenticated attacker with administrator privileges 
    to cause denial of service (DoS) conditions by sending a crafted HTTP request to a vulnerable device.
    (CVE-2024-6343)
  
  - A post-authentication command injection vulnerability in some firewall versions could allow an 
    authenticated attacker with administrator privileges to execute some OS commands on an affected device 
    by uploading a crafted internal user agreement file to the vulnerable device. (CVE-2024-42060)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-firewalls-09-03-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?090fed1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zyxel USG FLEX / ATP to version 5.39 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42060");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-42057");

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
  constraints = [{'min_version':'4.32', 'fixed_version' : '5.39'}];
else if ((model != "USG FLEX [25]0W?[^0]") && ('USG FLEX' >< model) )
  constraints = [{'min_version':'4.50', 'fixed_version' : '5.39'}];
else
  audit(AUDIT_NOT_INST, 'Zyxel USG FLEX / ATP Device');

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);