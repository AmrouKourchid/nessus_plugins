#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190094);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2023-49334",
    "CVE-2023-49330",
    "CVE-2023-49333",
    "CVE-2023-49332",
    "CVE-2023-49331",
    "CVE-2023-49335",
    "CVE-2023-48793",
    "CVE-2023-48792",
    "CVE-2024-0253",
    "CVE-2024-0269"
  );
  script_xref(name:"IAVA", value:"2024-A-0065-S");

  script_name(english:"ManageEngine ADAudit Plus < Build 7271 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An Active Directory management application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine ADAudit Plus running on the remote host is prior to build 7271. It is, therefore, affected by 
mutliple SQL injection vulnerabilities:

    - ManageEngine ADAudit Plus versions 7270 and below are vulnerable to the Authenticated SQL injection in home 
      Graph-Data. (CVE-2024-0253)

    - ManageEngine ADAudit Plus versions 7270 and below are vulnerable to the Authenticated SQL injection in 
      File-Summary DrillDown (CVE-2024-0269)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.manageengine.com/products/active-directory-audit/sqlfix-7271.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6832bfe5");
  # https://www.manageengine.com/products/ad-manager/release-notes.html#7203%20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e56bb494");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADAudit Plus build 7271 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adaudit_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_admanager_plus_detect.nbin", "manageengine_adaudit_plus_detect.nbin", "zoho_manageengine_adaudit_plus_win_installed.nbin");
  script_require_ports("installed_sw/ManageEngine ADAudit Plus", "installed_sw/Zoho ManageEngine ADAudit Plus");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_zoho.inc');

var app_info = vcf::zoho::adaudit::get_app_info();

var constraints = [
  {'fixed_version' : '7271'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
 );