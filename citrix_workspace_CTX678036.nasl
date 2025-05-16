#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206782);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2024-6286");

  script_name(english:"Citrix Workspace App for Windows Privilege Escalation (CTX678036)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace installed on the remote host is prior to 2203.1 LTSR CU6 Hotfix 2, 2402 LTSR or 
2403.1. It is, therefore, affected by a privilege escalation vulnerability as referenced in the CTX678036 advisory.

  - Local Privilege escalation allows a low-privileged user to gain SYSTEM privileges in Citrix Workspace app
    for Windows (CVE-2024-6286)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/s/article/CTX678036-citrix-workspace-app-for-windows-security-bulletin-cve20246286?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7795636b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace version 2403.1, 2402 LTSR and 2203.1 LTSR CU6 Hotfix 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace");
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
  { 'min_version' : '22.03.0.0', 'fixed_version' : '22.03.6002.6116', 'fixed_display' : '2203.1 LTSR CU6 Hotfix 2' },
  { 'min_version' : '24.2.0.0', 'fixed_version' : '24.2.0.172', 'fixed_display' : '2402 LTSR' },
  { 'min_version' : '24.3.0.0', 'fixed_version' : '24.3.1.97', 'fixed_display' : '2403.1 CR' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
