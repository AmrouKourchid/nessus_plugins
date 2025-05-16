#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(147716);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2021-21056");
  script_xref(name:"IAVB", value:"2021-B-0015-S");

  script_name(english:"Adobe FrameMaker 2019 <= 15.0.8 (2019.0.8) / Adobe FrameMaker 2020 <= 16.0.1 (2020.0.1) Arbitrary Code Execution (APSB21-14)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host is prior or equal to Adobe FrameMaker 2019 15.0.8 /
Adobe FrameMaker 2020 16.0.1. It is, therefore, affected by a vulnerability as referenced in the apsb21-14 advisory.

  - Adobe Framemaker version 2020.0.1 (and earlier) is affected by an Out-of-bounds Read vulnerability when
    parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve
    arbitrary code execution in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-21056)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb21-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker 2019 Release Update 8 (hotfix), 2020 Release Update 1 (hotfix) or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21056");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe FrameMaker', win_local:TRUE);

# Due to unique hotfix scenario, we are temporarily adding this paranoid condition
if (app_info['version'] =~ "(15\.0\.8|16\.0\.1)([^0-9]|$)" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Adobe FrameMaker');

var constraints = [
  { 'fixed_version' : '15.0.9', 'fixed_display' : '15.0.8 / 2019.0.8 / 2019 Release Update 8 (hotfix)' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.0.2', 'fixed_display' : '16.0.1 / 2020.0.1 / 2020 Release Update 1 (hotfix)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
