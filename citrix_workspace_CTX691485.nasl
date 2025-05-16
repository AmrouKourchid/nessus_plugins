#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207238);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-7889", "CVE-2024-7890");
  script_xref(name:"IAVA", value:"2024-A-0569");

  script_name(english:"Citrix Workspace App for Windows Multiple Vulnerabilities (CTX691485)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace installed on the remote host is prior 2402 LTSR CU1 or 2405. 
It is, therefore, affected by multiple vulnerabilities:

  - Local privilege escalation allows a low-privileged user to gain SYSTEM privileges 
    (Improper Control of a Resource Through its Lifetime) (CVE-2024-7889)

  - Local privilege escalation allows a low-privileged user to gain SYSTEM privileges 
    (Improper Privilage Management) (CVE-2024-7890)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/s/article/CTX691485-citrix-workspace-app-for-windows-security-bulletin-cve20247889-and-cve20247890
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c33f7066");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace version 2405, 2402 LTSR CU1, or 2203.1 LTSR CU6 Hotfix 3.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7890");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_workspace_win_installed.nbin");
  script_require_keys("installed_sw/Citrix Workspace", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Citrix Workspace');

var constraints = [
  { 'min_version' : '18.0.0.0', 'fixed_version' : '22.2.999.999', 'fixed_display' : '2405' },                 #Earlier Windows Versions
  { 'min_version' : '22.3.0.0', 'fixed_version' : '22.3.6003', 'fixed_display' : '2203.1 LTSR CU6 Hotfix 3'},#LTSR Version
  { 'min_version' : '22.4.0.0', 'fixed_version' : '24.1.999.999', 'fixed_display' : '2405' },                #Earlier Windows Versions
  { 'min_version' : '24.2.0.0', 'fixed_version' : '24.2.1000.1016', 'fixed_display' : '2402 LTSR CU1' },     #LTSR Version
  { 'min_version' : '24.3.0.0', 'fixed_version' : '24.5.0.131', 'fixed_display' : '2405' }                   #Main Version
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
