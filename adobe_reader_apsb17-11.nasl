#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(99374);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2017-3012",
    "CVE-2017-3013",
    "CVE-2017-3015",
    "CVE-2017-3017",
    "CVE-2017-3018",
    "CVE-2017-3019",
    "CVE-2017-3020",
    "CVE-2017-3021",
    "CVE-2017-3022",
    "CVE-2017-3023",
    "CVE-2017-3025",
    "CVE-2017-3026",
    "CVE-2017-3027",
    "CVE-2017-3028",
    "CVE-2017-3029",
    "CVE-2017-3030",
    "CVE-2017-3031",
    "CVE-2017-3033",
    "CVE-2017-3034",
    "CVE-2017-3035",
    "CVE-2017-3036",
    "CVE-2017-3037",
    "CVE-2017-3039",
    "CVE-2017-3040",
    "CVE-2017-3041",
    "CVE-2017-3042",
    "CVE-2017-3043",
    "CVE-2017-3044",
    "CVE-2017-3045",
    "CVE-2017-3046",
    "CVE-2017-3047",
    "CVE-2017-3048",
    "CVE-2017-3049",
    "CVE-2017-3050",
    "CVE-2017-3051",
    "CVE-2017-3052",
    "CVE-2017-3053",
    "CVE-2017-3054",
    "CVE-2017-3055",
    "CVE-2017-3056",
    "CVE-2017-3057",
    "CVE-2017-3065"
  );
  script_bugtraq_id(
    97547,
    97548,
    97549,
    97550,
    97554,
    97556
  );

  script_name(english:"Adobe Reader < 2015.006.30306 / 2017.009.20044 Multiple Vulnerabilities (APSB17-11)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior to 2015.006.30306 or 2017.009.20044.
It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader versions 11.0.19 and earlier, 15.006.30280 and earlier, 15.023.20070 and earlier have
    an exploitable memory corruption vulnerability in the JavaScript engine. Successful exploitation could
    lead to arbitrary code execution. (CVE-2017-3037)

  - Adobe Acrobat Reader versions 11.0.19 and earlier, 15.006.30280 and earlier, 15.023.20070 and earlier have
    an exploitable use after free vulnerability when manipulating an internal data structure. Successful
    exploitation could lead to arbitrary code execution. (CVE-2017-3026)

  - Adobe Acrobat Reader versions 11.0.19 and earlier, 15.006.30280 and earlier, 15.023.20070 and earlier have
    an exploitable use after free vulnerability in the XFA module, related to the choiceList element.
    Successful exploitation could lead to arbitrary code execution. (CVE-2017-3027)

  - Adobe Acrobat Reader versions 11.0.19 and earlier, 15.006.30280 and earlier, 15.023.20070 and earlier have
    an exploitable use after free vulnerability in the XML Forms Architecture (XFA) engine. Successful
    exploitation could lead to arbitrary code execution. (CVE-2017-3035)

  - Adobe Acrobat Reader versions 11.0.19 and earlier, 15.006.30280 and earlier, 15.023.20070 and earlier have
    an exploitable use after free vulnerability in the JavaScript engine's annotation-related API. Successful
    exploitation could lead to arbitrary code execution. (CVE-2017-3047)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-11.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2015.006.30306 / 2017.009.20044 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3037");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Reader', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'max_version' : '15.006.30280', 'fixed_version' : '15.006.30306', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '15.023.20070', 'fixed_version' : '17.009.20044', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
