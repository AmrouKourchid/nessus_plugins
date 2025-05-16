#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207385);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/20");

  script_cve_id("CVE-2024-28990", "CVE-2024-28991");
  script_xref(name:"IAVB", value:"2024-B-0139");

  script_name(english:"SolarWinds ARM 2024.3.1 Multiple Vulnerabilities (2024-3-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds ARM installed on the remote host is prior to 2024.3.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2024-3-1 advisory.

  - SolarWinds Access Rights Manager (ARM) was found to contain a hard-coded credential authentication bypass
    vulnerability. If exploited, this vulnerability would allow access to the RabbitMQ management console. We
    thank Trend Micro Zero Day Initiative (ZDI) for its ongoing partnership in coordinating with SolarWinds on
    responsible disclosure of this and other potential vulnerabilities. (CVE-2024-28990)

  - SolarWinds Access Rights Manager (ARM) was found to be susceptible to a remote code execution
    vulnerability. If exploited, this vulnerability would allow an authenticated user to abuse the service,
    resulting in remote code execution. (CVE-2024-28991)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://documentation.solarwinds.com/en/success_center/arm/content/release_notes/arm_2024-3-1_release_notes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f0ba8e1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds ARM version 2024.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:access_rights_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_arm_win_installed.nbin");
  script_require_keys("installed_sw/SolarWinds ARM", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'SolarWinds ARM', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '2024.3.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
