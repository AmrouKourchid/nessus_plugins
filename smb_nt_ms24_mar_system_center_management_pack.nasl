#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191940);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/30");

  script_cve_id("CVE-2024-21330", "CVE-2024-21334");
  script_xref(name:"IAVA", value:"2024-A-0166-S");

  script_name(english:"Security Updates for Microsoft System Center Management Pack (March 2024)");

  script_set_attribute(attribute:"synopsis", value:
"A data center management system component on the remote Windows system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft System Center Management Pack for UNIX/Linux on the remote host is missing a security update. It is,
therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-21334)

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
    (CVE-2024-21330)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

Note that this plugin requires paranoia to be reported as vulnerable, because the detection of a management pack on the
file system of a host does not necessarily mean that it is imported into a SCOM instance.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21330");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21334");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the System Center Management Pack for UNIX/Linux 2019 and 2022.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21334");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("system_center_management_pack_installed.nbin");
  script_require_keys("installed_sw/System Center Management Pack for UNIX and Linux");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'System Center Management Pack for UNIX and Linux', win_local:TRUE);

var constraints = [
  { 'min_version':'10.19.0.0',  'fixed_version':'10.19.1253.0' }, # 2019
  { 'min_version':'10.22.0.0',  'fixed_version':'10.22.1070.0' }  # 2022
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  require_paranoia:TRUE
);
