#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202305);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/15");

  script_cve_id("CVE-2024-6151");
  script_xref(name:"IAVA", value:"2024-A-0394");

  script_name(english:"Citrix Virtual Apps and Desktops Privilege Escalation (CTX678035)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Virtual Apps and Desktops installed on the remote Windows host is prior to 2402, 1912 LTSR CU9
or 2203 LTSR CU5. It is, therefore, affected by a privilege escalation vulnerability. By exploiting this vulnerability, 
a local, low-privileged attacker could gain SYSTEM privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX678035");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 2402, 2402 LTSR, 1912 LTSR CU9, 2203 LTSR CU5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6151");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:virtual_apps_and_desktops");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_virtual_apps_and_desktops_installed.nbin");
  script_require_keys("installed_sw/Citrix Virtual Apps and Desktops");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix Virtual Apps and Desktops', win_local:TRUE);

var app = app_info['App'];
if ("Virtual Delivery Agent" >!< app)
  audit(AUDIT_HOST_NOT, "affected");

var dv = app_info['display_version'];
var cu = app_info['CU'];
var constraints;

if ('2203 LTSR' >< dv)	
{
  if (empty_or_null(cu) || cu < 5)
    constraints = [{ 'equal': '7.2203', 'fixed_display': 'Upgrade to 2203 LTSR CU5 or later' }];
  else
    audit(AUDIT_HOST_NOT, "affected");
}
else if ('1912 LTSR' >< dv)
{
  if (empty_or_null(cu) || cu < 9)
    constraints = [{ 'equal': '7.1912', 'fixed_display': 'Upgrade to 1912 LTSR CU9 or later' }];
  else
    audit(AUDIT_HOST_NOT, "affected");  
}
else
  constraints = [{ 'fixed_version': '7.2402', 'fixed_display': 'Upgrade to 2402, 2402 LTSR or later' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);