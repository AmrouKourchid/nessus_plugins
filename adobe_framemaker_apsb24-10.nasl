#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190460);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2024-20738");
  script_xref(name:"IAVB", value:"2024-B-0078-S");

  script_name(english:"Adobe FrameMaker Publishing Server 2020 < 2020 Update 3 / 2022 < 2022 Update 2 Security Feature Bypass (APSB24-10)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker Publishing Server has a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker Publishing Server installed on the remote Windows host is Version 2020 prior to Update
3, or Version 2022 prior to Update 2. It is, therefore, affected by a vulnerability as referenced in the apsb24-10
advisory.

  - Adobe Framemaker Publishing Server sions 2022.1 and earlier are affected by an Improper Authentication vulnerability that
    could result in a Security feature bypass. An attacker could leverage this vulnerability to bypass
    authentication mechanisms and gain unauthorized access. Exploitation of this issue does not require user
    interaction. (CVE-2024-20738)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/framemaker-publishing-server/apsb24-10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13ea6852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker Publishing Server version 2020 Update 3, 2022 Update 2, or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker_publishing_server");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_fmps_win_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker Publishing Server", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe FrameMaker Publishing Server', win_local:TRUE);

var constraints = [
  { 'min_version' :  '0.0', 'fixed_version' : '16.0.3.229', 'fixed_display' : 'Version 2020 Update 3' },
  { 'min_version' : '17.0', 'fixed_version' : '17.0.2.56', 'fixed_display' : 'Version 2022 Update 2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
