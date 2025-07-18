#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(94072);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2016-1089",
    "CVE-2016-1091",
    "CVE-2016-4095",
    "CVE-2016-6939",
    "CVE-2016-6940",
    "CVE-2016-6941",
    "CVE-2016-6942",
    "CVE-2016-6943",
    "CVE-2016-6944",
    "CVE-2016-6945",
    "CVE-2016-6946",
    "CVE-2016-6947",
    "CVE-2016-6948",
    "CVE-2016-6949",
    "CVE-2016-6950",
    "CVE-2016-6951",
    "CVE-2016-6952",
    "CVE-2016-6953",
    "CVE-2016-6954",
    "CVE-2016-6955",
    "CVE-2016-6956",
    "CVE-2016-6957",
    "CVE-2016-6958",
    "CVE-2016-6959",
    "CVE-2016-6960",
    "CVE-2016-6961",
    "CVE-2016-6962",
    "CVE-2016-6963",
    "CVE-2016-6964",
    "CVE-2016-6965",
    "CVE-2016-6966",
    "CVE-2016-6967",
    "CVE-2016-6968",
    "CVE-2016-6969",
    "CVE-2016-6970",
    "CVE-2016-6971",
    "CVE-2016-6972",
    "CVE-2016-6973",
    "CVE-2016-6974",
    "CVE-2016-6975",
    "CVE-2016-6976",
    "CVE-2016-6977",
    "CVE-2016-6978",
    "CVE-2016-6979",
    "CVE-2016-6988",
    "CVE-2016-6993",
    "CVE-2016-6994",
    "CVE-2016-6995",
    "CVE-2016-6996",
    "CVE-2016-6997",
    "CVE-2016-6998",
    "CVE-2016-6999",
    "CVE-2016-7000",
    "CVE-2016-7001",
    "CVE-2016-7002",
    "CVE-2016-7003",
    "CVE-2016-7004",
    "CVE-2016-7005",
    "CVE-2016-7006",
    "CVE-2016-7007",
    "CVE-2016-7008",
    "CVE-2016-7009",
    "CVE-2016-7010",
    "CVE-2016-7011",
    "CVE-2016-7012",
    "CVE-2016-7013",
    "CVE-2016-7014",
    "CVE-2016-7015",
    "CVE-2016-7016",
    "CVE-2016-7017",
    "CVE-2016-7018",
    "CVE-2016-7019",
    "CVE-2016-7852",
    "CVE-2016-7853",
    "CVE-2016-7854"
  );
  script_bugtraq_id(
    93486,
    93487,
    93491,
    93494,
    93495,
    93496
  );

  script_name(english:"Adobe Reader < 15.006.30243 / 15.020.20039 Multiple Vulnerabilities (APSB16-33)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior to 15.006.30243 or 15.020.20039. It
is, therefore, affected by multiple vulnerabilities.

  - Adobe Reader and Acrobat before 11.0.18, Acrobat and Acrobat Reader DC Classic before 15.006.30243, and
    Acrobat and Acrobat Reader DC Continuous before 15.020.20039 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-6940, CVE-2016-6941, CVE-2016-6942, CVE-2016-6943, CVE-2016-6947,
    CVE-2016-6948, CVE-2016-6950, CVE-2016-6951, CVE-2016-6954, CVE-2016-6955, CVE-2016-6956, CVE-2016-6959,
    CVE-2016-6960, CVE-2016-6966, CVE-2016-6970, CVE-2016-6972, CVE-2016-6973, CVE-2016-6974, CVE-2016-6975,
    CVE-2016-6976, CVE-2016-6977, CVE-2016-6978, CVE-2016-6995, CVE-2016-6996, CVE-2016-6997, CVE-2016-6998,
    CVE-2016-7000, CVE-2016-7001, CVE-2016-7002, CVE-2016-7003, CVE-2016-7004, CVE-2016-7005, CVE-2016-7006,
    CVE-2016-7007, CVE-2016-7008, CVE-2016-7009, CVE-2016-7010, CVE-2016-7011, CVE-2016-7012, CVE-2016-7013,
    CVE-2016-7014, CVE-2016-7015, CVE-2016-7016, CVE-2016-7017, CVE-2016-7018, CVE-2016-7019, CVE-2016-7852,
    and CVE-2016-7853. (CVE-2016-7854)

  - Adobe Reader and Acrobat before 11.0.18, Acrobat and Acrobat Reader DC Classic before 15.006.30243, and
    Acrobat and Acrobat Reader DC Continuous before 15.020.20039 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-6940, CVE-2016-6941, CVE-2016-6942, CVE-2016-6943, CVE-2016-6947,
    CVE-2016-6948, CVE-2016-6950, CVE-2016-6951, CVE-2016-6954, CVE-2016-6955, CVE-2016-6956, CVE-2016-6959,
    CVE-2016-6960, CVE-2016-6966, CVE-2016-6970, CVE-2016-6972, CVE-2016-6973, CVE-2016-6974, CVE-2016-6975,
    CVE-2016-6976, CVE-2016-6977, CVE-2016-6978, CVE-2016-6995, CVE-2016-6996, CVE-2016-6997, CVE-2016-6998,
    CVE-2016-7000, CVE-2016-7001, CVE-2016-7002, CVE-2016-7003, CVE-2016-7004, CVE-2016-7005, CVE-2016-7006,
    CVE-2016-7007, CVE-2016-7008, CVE-2016-7009, CVE-2016-7010, CVE-2016-7011, CVE-2016-7012, CVE-2016-7013,
    CVE-2016-7014, CVE-2016-7015, CVE-2016-7016, CVE-2016-7017, CVE-2016-7018, CVE-2016-7019, CVE-2016-7852,
    and CVE-2016-7854. (CVE-2016-7853)

  - Adobe Reader and Acrobat before 11.0.18, Acrobat and Acrobat Reader DC Classic before 15.006.30243, and
    Acrobat and Acrobat Reader DC Continuous before 15.020.20039 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-6940, CVE-2016-6941, CVE-2016-6942, CVE-2016-6943, CVE-2016-6947,
    CVE-2016-6948, CVE-2016-6950, CVE-2016-6951, CVE-2016-6954, CVE-2016-6955, CVE-2016-6956, CVE-2016-6959,
    CVE-2016-6960, CVE-2016-6966, CVE-2016-6970, CVE-2016-6972, CVE-2016-6973, CVE-2016-6974, CVE-2016-6975,
    CVE-2016-6976, CVE-2016-6977, CVE-2016-6978, CVE-2016-6995, CVE-2016-6996, CVE-2016-6997, CVE-2016-6998,
    CVE-2016-7000, CVE-2016-7001, CVE-2016-7002, CVE-2016-7003, CVE-2016-7004, CVE-2016-7005, CVE-2016-7006,
    CVE-2016-7007, CVE-2016-7008, CVE-2016-7009, CVE-2016-7010, CVE-2016-7011, CVE-2016-7012, CVE-2016-7013,
    CVE-2016-7014, CVE-2016-7015, CVE-2016-7016, CVE-2016-7017, CVE-2016-7018, CVE-2016-7019, CVE-2016-7853,
    and CVE-2016-7854. (CVE-2016-7852)

  - Use-after-free vulnerability in Adobe Reader and Acrobat before 11.0.18, Acrobat and Acrobat Reader DC
    Classic before 15.006.30243, and Acrobat and Acrobat Reader DC Continuous before 15.020.20039 on Windows
    and OS X allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability
    than CVE-2016-1091, CVE-2016-6944, CVE-2016-6945, CVE-2016-6946, CVE-2016-6949, CVE-2016-6952,
    CVE-2016-6953, CVE-2016-6961, CVE-2016-6962, CVE-2016-6963, CVE-2016-6964, CVE-2016-6965, CVE-2016-6967,
    CVE-2016-6968, CVE-2016-6969, CVE-2016-6971, CVE-2016-6979, CVE-2016-6988, and CVE-2016-6993.
    (CVE-2016-1089)

  - Use-after-free vulnerability in Adobe Reader and Acrobat before 11.0.18, Acrobat and Acrobat Reader DC
    Classic before 15.006.30243, and Acrobat and Acrobat Reader DC Continuous before 15.020.20039 on Windows
    and OS X allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability
    than CVE-2016-1089, CVE-2016-6944, CVE-2016-6945, CVE-2016-6946, CVE-2016-6949, CVE-2016-6952,
    CVE-2016-6953, CVE-2016-6961, CVE-2016-6962, CVE-2016-6963, CVE-2016-6964, CVE-2016-6965, CVE-2016-6967,
    CVE-2016-6968, CVE-2016-6969, CVE-2016-6971, CVE-2016-6979, CVE-2016-6988, and CVE-2016-6993.
    (CVE-2016-1091)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-33.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 15.006.30243 / 15.020.20039 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7854");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/14");

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
  { 'max_version' : '15.006.30201', 'fixed_version' : '15.006.30243', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '15.017.20053', 'fixed_version' : '15.020.20039', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
