#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126633);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2019-7956");
  script_bugtraq_id(109088);
  script_xref(name:"IAVA", value:"2019-A-0232");

  script_name(english:"Adobe Dreamweaver 18.0 < 2018.0 / 19.0 < 2019.0 Privilege Escalation (APSB19-40)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Dreamweaver instance installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dreamweaver installed on the remote Windows host is prior to 2018.0, 2019.0. It is, therefore,
affected by a vulnerability as referenced in the APSB19-40 advisory.

  - Adobe Dreamweaver direct download installer versions 19.0 and below, 18.0 and below have an Insecure
    Library Loading (DLL hijacking) vulnerability. Successful exploitation could lead to Privilege Escalation
    in the context of the current user. (CVE-2019-7956)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb19-40.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dreamweaver version 2018.0, 2019.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dreamweaver");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dreamweaver_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Dreamweaver");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Dreamweaver');

var constraints = [
  { 'min_version' : '18.0', 'max_version' : '18.0', 'fixed_version' : '2018.0', 'fixed_display' : '2018 Release' },
  { 'min_version' : '19.0', 'max_version' : '19.0', 'fixed_version' : '2019.0', 'fixed_display' : '2019 Release' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
