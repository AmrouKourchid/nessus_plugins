#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(92035);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2016-4191",
    "CVE-2016-4192",
    "CVE-2016-4193",
    "CVE-2016-4194",
    "CVE-2016-4195",
    "CVE-2016-4196",
    "CVE-2016-4197",
    "CVE-2016-4198",
    "CVE-2016-4199",
    "CVE-2016-4200",
    "CVE-2016-4201",
    "CVE-2016-4202",
    "CVE-2016-4203",
    "CVE-2016-4204",
    "CVE-2016-4205",
    "CVE-2016-4206",
    "CVE-2016-4207",
    "CVE-2016-4208",
    "CVE-2016-4209",
    "CVE-2016-4210",
    "CVE-2016-4211",
    "CVE-2016-4212",
    "CVE-2016-4213",
    "CVE-2016-4214",
    "CVE-2016-4215",
    "CVE-2016-4250",
    "CVE-2016-4251",
    "CVE-2016-4252",
    "CVE-2016-4254",
    "CVE-2016-4255",
    "CVE-2016-4265",
    "CVE-2016-4266",
    "CVE-2016-4267",
    "CVE-2016-4268",
    "CVE-2016-4269",
    "CVE-2016-4270",
    "CVE-2016-6937",
    "CVE-2016-6938"
  );
  script_bugtraq_id(
    91710,
    91711,
    91712,
    91714,
    91716,
    92635,
    92636,
    92637,
    92640,
    92641,
    92643,
    93014,
    93016
  );

  script_name(english:"Adobe Reader < 15.006.30198 / 15.017.20050 Multiple Vulnerabilities (APSB16-26)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior to 15.006.30198 or 15.017.20050. It
is, therefore, affected by multiple vulnerabilities.

  - Use-after-free vulnerability in Adobe Reader and Acrobat before 11.0.17, Acrobat and Acrobat Reader DC
    Classic before 15.006.30198, and Acrobat and Acrobat Reader DC Continuous before 15.017.20050 on Windows
    and OS X allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability
    than CVE-2016-4255. (CVE-2016-6938)

  - Integer overflow in Adobe Reader and Acrobat before 11.0.17, Acrobat and Acrobat Reader DC Classic before
    15.006.30198, and Acrobat and Acrobat Reader DC Continuous before 15.017.20050 on Windows and OS X allows
    attackers to execute arbitrary code via unspecified vectors. (CVE-2016-4210)

  - Use-after-free vulnerability in Adobe Reader and Acrobat before 11.0.17, Acrobat and Acrobat Reader DC
    Classic before 15.006.30198, and Acrobat and Acrobat Reader DC Continuous before 15.017.20050 on Windows
    and OS X allows attackers to execute arbitrary code via unspecified vectors. (CVE-2016-4255)

  - Heap-based buffer overflow in Adobe Reader and Acrobat before 11.0.17, Acrobat and Acrobat Reader DC
    Classic before 15.006.30198, and Acrobat and Acrobat Reader DC Continuous before 15.017.20050 on Windows
    and OS X allows attackers to execute arbitrary code via unspecified vectors. (CVE-2016-4209)

  - Adobe Reader and Acrobat before 11.0.17, Acrobat and Acrobat Reader DC Classic before 15.006.30198, and
    Acrobat and Acrobat Reader DC Continuous before 15.017.20050 on Windows and OS X allow attackers to bypass
    JavaScript API execution restrictions via unspecified vectors. (CVE-2016-4215)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-26.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 15.006.30198 / 15.017.20050 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'max_version' : '15.006.30174', 'fixed_version' : '15.006.30198', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '15.016.20045', 'fixed_version' : '15.017.20050', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
