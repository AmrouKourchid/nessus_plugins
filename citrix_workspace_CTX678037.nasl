#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202260);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id("CVE-2024-6148", "CVE-2024-6149");
  script_xref(name:"IAVA", value:"2024-A-0380");

  script_name(english:"Citrix Workspace App for HTML5 Multiple Vulnerabilities (CTX678037)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace App for HTML5 installed on the remote host is prior to 2404.1. It is
therefore affected by multiple vulnerabilities as described in the CTX678037 advisory:

  - Bypass of GACS Policy Configuration settings (CVE-2024-6148)

  - Redirection of users to a vulnerable URL (CVE-2024-6149)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX678037");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace App for HTML5 version 2404.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace_app");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_workspace_html5_win_installed.nbin");
  script_require_keys("installed_sw/Citrix Workspace HTML5 Client");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix Workspace HTML5 Client');

var constraints = [
  {'fixed_version': '24.4.1.12', 'fixed_display': '2404.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
