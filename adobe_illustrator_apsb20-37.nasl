#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137647);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id(
    "CVE-2020-9575",
    "CVE-2020-9639",
    "CVE-2020-9640",
    "CVE-2020-9641",
    "CVE-2020-9642"
  );
  script_xref(name:"IAVA", value:"2020-A-0271-S");

  script_name(english:"Adobe Illustrator < 24.2.0 Multiple Vulnerabilities (APSB20-37)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Illustrator instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator installed on the remote Windows host is prior to 24.2.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB20-37 advisory.

  - Adobe Illustrator versions 24.1.2 and earlier have a buffer errors vulnerability. Successful exploitation
    could lead to arbitrary code execution . (CVE-2020-9642)

  - Adobe Illustrator versions 24.1.2 and earlier have a memory corruption vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2020-9575, CVE-2020-9639, CVE-2020-9640,
    CVE-2020-9641)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb20-37.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator version 24.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9642");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Illustrator");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Illustrator', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '24.2.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
