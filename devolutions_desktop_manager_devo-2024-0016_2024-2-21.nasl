#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212113);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2024-11670", "CVE-2024-11672");
  script_xref(name:"IAVB", value:"2024-B-0191-S");

  script_name(english:"Devolutions Remote Desktop Manager Multiple Vulnerabilities (DEVO-2024-0016)");

  script_set_attribute(attribute:"synopsis", value:
"The Devolutions Remote Desktop Manager instance installed on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote installation of Devolutions Server is affected by the following vulnerabilities:

- Incorrect authorization in the permission validation component of Devolutions Remote Desktop Manager 2024.2.21
  and earlier on Windows allows a malicious authenticated user to bypass the View Password 
  permission via specific actions. (CVE-2024-11670)

- Incorrect authorization in the add permission component in Devolutions Remote Desktop Manager 2024.2.21 and earlier 
  on Windows allows an authenticated malicious user to bypass the Add permission via the import in 
  vault feature. (CVE-2024-11672)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://devolutions.net/security/advisories/DEVO-2024-0016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Devolutions Remote Desktop Manager version 2024.3.10 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:devolutions:remote_desktop_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("devolutions_desktop_manager_win_installed.nbin");
  script_require_keys("installed_sw/Devolutions Remote Desktop Manager", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Devolutions Remote Desktop Manager', win_local:TRUE);

var constraints = [
  { 'max_version' : '2024.2.21.0', 'fixed_version' : '2024.3.10.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
