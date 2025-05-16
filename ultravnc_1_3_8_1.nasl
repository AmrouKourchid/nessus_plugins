#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189187);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/19");

  script_cve_id("CVE-2022-24750");
  script_xref(name:"IAVB", value:"2024-B-0006");

  script_name(english:"UltraVNC < 1.3.8.1 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A remote desktop application installed on the remote Windows host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of UltraVNC Service installed on the remote Windows host is prior to 1.3.8.1. It is, therefore, affected
by an escalation of privilege vulnerability in DSM plugin module. When running as a service, a local, authenticated,
attacker can run arbitrary code in the context of the VNC server process.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/ultravnc/UltraVNC/security/advisories/GHSA-3mvp-cp5x-vj5g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88dc8569");
  script_set_attribute(attribute:"solution", value:
"Upgrade to UltraVNC version 1.3.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ultravnc:ultravnc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ultravnc_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/UltraVNC");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'UltraVNC', win_local:TRUE);

if (!app_info['Server'])
  audit(AUDIT_HOST_NOT, 'affected due to the UltraVNC server component not being installed');

if (!app_info['Service'])
  audit(AUDIT_HOST_NOT, 'affected due to UltraVNC not being configured to run as a service');

var constraints = [
  { 'fixed_version' : '1.3.8.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
