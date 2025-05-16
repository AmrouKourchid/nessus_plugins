#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(213008);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id("CVE-2024-43594");
  script_xref(name:"IAVA", value:"2024-A-0810");

  script_name(english:"Security Updates for Microsoft System Center Operations Manager (December 2024)");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote Windows system is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft System Center Operations Manager installed on the remote Windows host is affected by an
elevation of privilege vulnerability. A remote, authenticated attacker can exploit this vulnerability by sending a
specially crafted request to an affected SCOM instance.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?");
  # https://support.microsoft.com/topic/update-rollup-1-for-system-center-2022-operations-manager-3f5780c9-36d9-4bba-8361-d40ca7c7ae80
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e98891e");
  # https://support.microsoft.com/topic/788c571b-1887-4376-8b2f-c7881e797835
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b53efd0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for System Center Operations Manager 2019, 2022, and 2025.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43594");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("system_center_operations_mgr_installed.nasl");
  script_require_keys("installed_sw/System Center Operations Manager Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'System Center Operations Manager Server', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version':'10.19.0', 'fixed_version':'10.19.10457.0' },
  { 'min_version':'10.22.0', 'fixed_version':'10.22.10684.0' },
  { 'min_version':'10.25.0', 'fixed_version':'10.25.10132.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

