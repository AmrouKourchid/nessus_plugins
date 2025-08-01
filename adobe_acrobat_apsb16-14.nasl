#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91096);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2016-1037",
    "CVE-2016-1038",
    "CVE-2016-1039",
    "CVE-2016-1040",
    "CVE-2016-1041",
    "CVE-2016-1042",
    "CVE-2016-1043",
    "CVE-2016-1044",
    "CVE-2016-1045",
    "CVE-2016-1046",
    "CVE-2016-1047",
    "CVE-2016-1048",
    "CVE-2016-1049",
    "CVE-2016-1050",
    "CVE-2016-1051",
    "CVE-2016-1052",
    "CVE-2016-1053",
    "CVE-2016-1054",
    "CVE-2016-1055",
    "CVE-2016-1056",
    "CVE-2016-1057",
    "CVE-2016-1058",
    "CVE-2016-1059",
    "CVE-2016-1060",
    "CVE-2016-1061",
    "CVE-2016-1062",
    "CVE-2016-1063",
    "CVE-2016-1064",
    "CVE-2016-1065",
    "CVE-2016-1066",
    "CVE-2016-1067",
    "CVE-2016-1068",
    "CVE-2016-1069",
    "CVE-2016-1070",
    "CVE-2016-1071",
    "CVE-2016-1072",
    "CVE-2016-1073",
    "CVE-2016-1074",
    "CVE-2016-1075",
    "CVE-2016-1076",
    "CVE-2016-1077",
    "CVE-2016-1078",
    "CVE-2016-1079",
    "CVE-2016-1080",
    "CVE-2016-1081",
    "CVE-2016-1082",
    "CVE-2016-1083",
    "CVE-2016-1084",
    "CVE-2016-1085",
    "CVE-2016-1086",
    "CVE-2016-1087",
    "CVE-2016-1088",
    "CVE-2016-1090",
    "CVE-2016-1092",
    "CVE-2016-1093",
    "CVE-2016-1094",
    "CVE-2016-1095",
    "CVE-2016-1112",
    "CVE-2016-1116",
    "CVE-2016-1117",
    "CVE-2016-1118",
    "CVE-2016-1119",
    "CVE-2016-1120",
    "CVE-2016-1121",
    "CVE-2016-1122",
    "CVE-2016-1123",
    "CVE-2016-1124",
    "CVE-2016-1125",
    "CVE-2016-1126",
    "CVE-2016-1127",
    "CVE-2016-1128",
    "CVE-2016-1129",
    "CVE-2016-1130",
    "CVE-2016-4088",
    "CVE-2016-4089",
    "CVE-2016-4090",
    "CVE-2016-4091",
    "CVE-2016-4092",
    "CVE-2016-4093",
    "CVE-2016-4094",
    "CVE-2016-4096",
    "CVE-2016-4097",
    "CVE-2016-4098",
    "CVE-2016-4099",
    "CVE-2016-4100",
    "CVE-2016-4101",
    "CVE-2016-4102",
    "CVE-2016-4103",
    "CVE-2016-4104",
    "CVE-2016-4105",
    "CVE-2016-4106",
    "CVE-2016-4107",
    "CVE-2016-4119"
  );
  script_bugtraq_id(90517);
  script_xref(name:"ZDI", value:"ZDI-16-285");
  script_xref(name:"ZDI", value:"ZDI-16-286");
  script_xref(name:"ZDI", value:"ZDI-16-287");
  script_xref(name:"ZDI", value:"ZDI-16-288");
  script_xref(name:"ZDI", value:"ZDI-16-289");
  script_xref(name:"ZDI", value:"ZDI-16-290");
  script_xref(name:"ZDI", value:"ZDI-16-291");
  script_xref(name:"ZDI", value:"ZDI-16-292");
  script_xref(name:"ZDI", value:"ZDI-16-293");
  script_xref(name:"ZDI", value:"ZDI-16-294");
  script_xref(name:"ZDI", value:"ZDI-16-295");
  script_xref(name:"ZDI", value:"ZDI-16-296");
  script_xref(name:"ZDI", value:"ZDI-16-297");
  script_xref(name:"ZDI", value:"ZDI-16-298");
  script_xref(name:"ZDI", value:"ZDI-16-299");
  script_xref(name:"ZDI", value:"ZDI-16-300");
  script_xref(name:"ZDI", value:"ZDI-16-301");
  script_xref(name:"ZDI", value:"ZDI-16-302");
  script_xref(name:"ZDI", value:"ZDI-16-303");
  script_xref(name:"ZDI", value:"ZDI-16-304");
  script_xref(name:"ZDI", value:"ZDI-16-305");
  script_xref(name:"ZDI", value:"ZDI-16-306");
  script_xref(name:"ZDI", value:"ZDI-16-307");
  script_xref(name:"ZDI", value:"ZDI-16-308");
  script_xref(name:"ZDI", value:"ZDI-16-309");
  script_xref(name:"ZDI", value:"ZDI-16-310");
  script_xref(name:"ZDI", value:"ZDI-16-311");
  script_xref(name:"ZDI", value:"ZDI-16-312");
  script_xref(name:"ZDI", value:"ZDI-16-313");
  script_xref(name:"ZDI", value:"ZDI-16-315");
  script_xref(name:"ZDI", value:"ZDI-16-316");
  script_xref(name:"ZDI", value:"ZDI-16-317");
  script_xref(name:"ZDI", value:"ZDI-16-318");
  script_xref(name:"ZDI", value:"ZDI-16-319");
  script_xref(name:"ZDI", value:"ZDI-16-320");
  script_xref(name:"ZDI", value:"ZDI-16-321");
  script_xref(name:"ZDI", value:"ZDI-16-322");
  script_xref(name:"ZDI", value:"ZDI-16-323");
  script_xref(name:"ZDI", value:"ZDI-16-324");
  script_xref(name:"ZDI", value:"ZDI-16-325");
  script_xref(name:"ZDI", value:"ZDI-16-326");
  script_xref(name:"ZDI", value:"ZDI-16-327");
  script_xref(name:"ZDI", value:"ZDI-16-328");
  script_xref(name:"ZDI", value:"ZDI-16-329");

  script_name(english:"Adobe Acrobat < 11.0.16 / 15.006.30172 / 15.016.20039 Multiple Vulnerabilities (APSB16-14)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 11.0.16, 15.006.30172, or
15.016.20039. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Reader and Acrobat before 11.0.16, Acrobat and Acrobat Reader DC Classic before 15.006.30172, and
    Acrobat and Acrobat Reader DC Continuous before 15.016.20039 on Windows and OS X allow attackers to bypass
    JavaScript API execution restrictions via unspecified vectors, a different vulnerability than
    CVE-2016-1038, CVE-2016-1039, CVE-2016-1040, CVE-2016-1041, CVE-2016-1042, CVE-2016-1044, and
    CVE-2016-1062. (CVE-2016-1117)

  - Adobe Reader and Acrobat before 11.0.16, Acrobat and Acrobat Reader DC Classic before 15.006.30172, and
    Acrobat and Acrobat Reader DC Continuous before 15.016.20039 on Windows and OS X allow attackers to bypass
    JavaScript API execution restrictions via unspecified vectors, a different vulnerability than
    CVE-2016-1038, CVE-2016-1039, CVE-2016-1040, CVE-2016-1041, CVE-2016-1042, CVE-2016-1044, and
    CVE-2016-1117. (CVE-2016-1062)

  - Adobe Reader and Acrobat before 11.0.16, Acrobat and Acrobat Reader DC Classic before 15.006.30172, and
    Acrobat and Acrobat Reader DC Continuous before 15.016.20039 on Windows and OS X allow attackers to bypass
    JavaScript API execution restrictions via unspecified vectors, a different vulnerability than
    CVE-2016-1038, CVE-2016-1039, CVE-2016-1040, CVE-2016-1041, CVE-2016-1042, CVE-2016-1062, and
    CVE-2016-1117. (CVE-2016-1044)

  - Adobe Reader and Acrobat before 11.0.16, Acrobat and Acrobat Reader DC Classic before 15.006.30172, and
    Acrobat and Acrobat Reader DC Continuous before 15.016.20039 on Windows and OS X allow attackers to bypass
    JavaScript API execution restrictions via unspecified vectors, a different vulnerability than
    CVE-2016-1038, CVE-2016-1039, CVE-2016-1040, CVE-2016-1041, CVE-2016-1044, CVE-2016-1062, and
    CVE-2016-1117. (CVE-2016-1042)

  - Adobe Reader and Acrobat before 11.0.16, Acrobat and Acrobat Reader DC Classic before 15.006.30172, and
    Acrobat and Acrobat Reader DC Continuous before 15.016.20039 on Windows and OS X allow attackers to bypass
    JavaScript API execution restrictions via unspecified vectors, a different vulnerability than
    CVE-2016-1038, CVE-2016-1039, CVE-2016-1040, CVE-2016-1042, CVE-2016-1044, CVE-2016-1062, and
    CVE-2016-1117. (CVE-2016-1041)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 11.0.16 / 15.006.30172 / 15.016.20039 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4119");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-1044");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Acrobat', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'max_version' : '11.0.15', 'fixed_version' : '11.0.16', 'track' : 'DC Continuous' },
  { 'max_version' : '15.006.30121', 'fixed_version' : '15.006.30172', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '15.010.20060', 'fixed_version' : '15.016.20039', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
