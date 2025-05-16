#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209494);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2023-44324");

  script_name(english:"Adobe FrameMaker Publishing Server 2022 < 17.0.1 (2022.0.1) Security Feature Bypass (APSB23-58)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker Publishing Server has a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker Publishing Server installed on the remote Windows host is prior to Adobe FrameMaker
Publishing Server 2022 17.0.1. It is, therefore, affected by a vulnerability as referenced in the apsb23-58 advisory.

  - Adobe FrameMaker Publishing Server versions 2022 and earlier are affected by an Improper Authentication
    vulnerability that could result in a Security feature bypass. An unauthenticated attacker can abuse this
    vulnerability to access the API and leak default admin's password. Exploitation of this issue does not
    require user interaction. (CVE-2023-44324)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb23-58.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker Publishing Server Version 2022 Update 1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44324");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker_publishing_server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'fixed_version' : '17.0.1', 'fixed_display' : '17.0.1 / 2022.0.1 / Version 2022 Update 1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
