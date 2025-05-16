#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192238);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id("CVE-2024-2431");
  script_xref(name:"IAVA", value:"2024-A-0170-S");

  script_name(english:"Palo Alto GlobalProtect Agent < 5.1.12 / 5.2.x < 5.2.13 / 6.0.x < 6.0.4 / 6.1.x < 6.1.1 (GPC-15349)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto GlobalProtect Agent installed on the remote host is prior to 5.1.12, 5.2.13, 6.0.4, or 6.1.1.
It is, therefore, affected by a vulnerability as referenced in the GPC-15349 advisory.

  - An issue in the Palo Alto Networks GlobalProtect app enables a non-privileged user to disable the
    GlobalProtect app in configurations that allow a user to disable GlobalProtect with a passcode.
    (CVE-2024-2431)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.paloaltonetworks.com/CVE-2024-2431");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto GlobalProtect Agent version 5.1.12 / 5.2.13 / 6.0.4 / 6.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2431");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:paloaltonetworks:globalprotect");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_globalprotect_agent_win_installed.nbin");
  script_require_keys("Palo Alto GlobalProtect Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Palo Alto GlobalProtect Agent');

var constraints = [
  { 'fixed_version' : '5.1.12' },
  { 'min_version' : '5.2', 'fixed_version' : '5.2.13' },
  { 'min_version' : '6.0', 'fixed_version' : '6.0.4' },
  { 'min_version' : '6.1', 'fixed_version' : '6.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
