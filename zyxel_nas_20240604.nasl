#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200515);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2024-29972",
    "CVE-2024-29973",
    "CVE-2024-29974",
    "CVE-2024-29975",
    "CVE-2024-29976"
  );

  script_name(english:"Zyxel NAS Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote security gateway is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Zyxel NAS is potentially affected by multiple vulnerabilities. 

    - This command injection vulnerability in the 'setCookie' parameter 
      in Zyxel NAS326 and NAS542 devices could allow an unauthenticated 
      attacker to execute some OS commands by sending a crafted HTTP POST 
      request. (CVE-2024-29973)

    - This remote code execution vulnerability in the CGI program 'file_upload-cgi'
      in Zyxel NAS326 and NAS542 devices could allow an unauthenticated attacker 
      to execute arbitrary code by uploading a crafted configuration file to a 
      vulnerable device. (CVE-2024-29974)

    - This improper privilege management vulnerability in the SUID executable binary
      in Zyxel NAS326 and NAS542 devices could allow an authenticated local attacker 
      with administrator privileges to execute some system commands as the “root” 
      user on a vulnerable device. (CVE-2024-29975)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported model
number.");
  # https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-nas-products-06-04-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f6c1c2e");
  script_set_attribute(attribute:"solution", value:
"See Vendor Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:zyxel:nas");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zyxel_device_detect.nbin");
  script_require_keys("installed_sw/Zyxel NAS");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app = 'Zyxel NAS';
var app_info = vcf::combined_get_app_info(app:app);
dbg::log(msg:'[app_info][' + obj_rep(app_info) + ']'); 

var model = app_info['model'];
if(empty_or_null(model))
  audit(AUDIT_OS_CONF_UNKNOWN, 'Zyxel device');
var constraints = [];

if ('NAS326' >< model)
  {
    constraints = [{
      'max_version'   : vcf::zyxel_router::transform_ver(firmware:'V5.21(AAZF.16)C0'), 
      'fixed_version' : vcf::zyxel_router::transform_ver(firmware:'V5.21(AAZF.17)C0'),
      'fixed_display' : 'V5.21(AAZF.17)C0'
    }];
  } 
  else if ('NAS542' >< model){
    constraints = [{
      'max_version'   : vcf::zyxel_router::transform_ver(firmware:'V5.21(ABAG.13)C0'), 
      'fixed_version' : vcf::zyxel_router::transform_ver(firmware:'V5.21(ABAG.14)C0'),
      'fixed_display' : 'V5.21(ABAG.14)C0'
    }];
  }
  else
    audit(AUDIT_NOT_INST, 'Zyxel NAS Device');

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
