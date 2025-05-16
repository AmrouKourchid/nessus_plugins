#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210958);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2024-8068", "CVE-2024-8069");
  script_xref(name:"IAVA", value:"2024-A-0725");

  script_name(english:"Citrix Virtual Apps and Desktops Session Recording Multiple Vulnerabilities (CTX691941)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Virtual Apps and Desktops installed on the remote Windows host is prior to 2407 hotfix
24.5.200.8, 1912 LTSR prior to CU9 hotfix 19.12.9100.6, 2203 LTSR prior to CU5 hotfix 22.03.5100.11, or 2402 LTSR prior
to CU1 hotfix 24.02.1200.16. It is, therefore, affected by multiple vulnerabilities as per Citrix Security Bulletin
CTX691941:

  - Privilege escalation to NetworkService Account access in Citrix Session Recording when an attacker is an
    authenticated user in the same Windows Active Directory domain as the session recording server domain.
    (CVE-2024-8068)

  - Limited remote code execution with privilege of a NetworkService Account access in Citrix Session Recording if the
    attacker is an authenticated user on the same intranet as the session recording server. (CVE-2024-8069)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX691941");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 2407 hotfix 24.5.200.8, 1912 LTSR CU9 hotfix 19.12.9100.6, 2203 LTSR CU5 hotfix 22.03.5100.11, or 2402 LTSR CU1 hotfix 24.02.1200.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8069");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:virtual_apps_and_desktops");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

var vda_ver = app_info.version;
var sr_app = {};
sr_app.app = 'Citrix Virtual Apps and Desktops Session Recording';
sr_app.version = app_info['Session Recording Version'];
sr_app.path = app_info['Session Recording Path'];

if (empty_or_null(sr_app.version))
  audit(AUDIT_NOT_DETECT, sr_app.app);

var fix = NULL;

if ('2407' >< vda_ver)
  fix = '24.5.200.8';
if ('1912' >< vda_ver)
  fix = '19.12.9100.6';
if ('2203' >< vda_ver)
  fix = '22.03.5100.11';
if ('2402' >< vda_ver)
  fix = '24.02.1200.16';

if (isnull(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, app_info.app, app_info.version, app_info.path);

if (ver_compare(ver:sr_app.version, fix:fix) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, sr_app.app, sr_app.version, sr_app.path);

vcf::report_results(app_info:sr_app, fix:fix, severity:SECURITY_HOLE);