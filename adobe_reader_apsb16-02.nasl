#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87918);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2016-0931",
    "CVE-2016-0932",
    "CVE-2016-0933",
    "CVE-2016-0934",
    "CVE-2016-0935",
    "CVE-2016-0936",
    "CVE-2016-0937",
    "CVE-2016-0938",
    "CVE-2016-0939",
    "CVE-2016-0940",
    "CVE-2016-0941",
    "CVE-2016-0942",
    "CVE-2016-0943",
    "CVE-2016-0944",
    "CVE-2016-0945",
    "CVE-2016-0946",
    "CVE-2016-0947",
    "CVE-2016-1111"
  );
  script_xref(name:"ZDI", value:"ZDI-16-273");

  script_name(english:"Adobe Reader < 15.006.30119 / 15.010.20056 Multiple Vulnerabilities (APSB16-02)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior to 15.006.30119 or 15.010.20056. It
is, therefore, affected by multiple vulnerabilities.

  - Adobe Reader and Acrobat before 11.0.14, Acrobat and Acrobat Reader DC Classic before 15.006.30119, and
    Acrobat and Acrobat Reader DC Continuous before 15.010.20056 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-0931, CVE-2016-0933, CVE-2016-0936, CVE-2016-0938, CVE-2016-0939,
    CVE-2016-0942, CVE-2016-0944, and CVE-2016-0945. (CVE-2016-0946)

  - Adobe Reader and Acrobat before 11.0.14, Acrobat and Acrobat Reader DC Classic before 15.006.30119, and
    Acrobat and Acrobat Reader DC Continuous before 15.010.20056 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-0931, CVE-2016-0933, CVE-2016-0936, CVE-2016-0938, CVE-2016-0939,
    CVE-2016-0942, CVE-2016-0944, and CVE-2016-0946. (CVE-2016-0945)

  - Adobe Reader and Acrobat before 11.0.14, Acrobat and Acrobat Reader DC Classic before 15.006.30119, and
    Acrobat and Acrobat Reader DC Continuous before 15.010.20056 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-0931, CVE-2016-0933, CVE-2016-0936, CVE-2016-0938, CVE-2016-0939,
    CVE-2016-0942, CVE-2016-0945, and CVE-2016-0946. (CVE-2016-0944)

  - Adobe Reader and Acrobat before 11.0.14, Acrobat and Acrobat Reader DC Classic before 15.006.30119, and
    Acrobat and Acrobat Reader DC Continuous before 15.010.20056 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-0931, CVE-2016-0933, CVE-2016-0936, CVE-2016-0938, CVE-2016-0939,
    CVE-2016-0944, CVE-2016-0945, and CVE-2016-0946. (CVE-2016-0942)

  - Adobe Reader and Acrobat before 11.0.14, Acrobat and Acrobat Reader DC Classic before 15.006.30119, and
    Acrobat and Acrobat Reader DC Continuous before 15.010.20056 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (uninitialized pointer dereference and memory
    corruption) via unspecified vectors, a different vulnerability than CVE-2016-0931, CVE-2016-0933,
    CVE-2016-0936, CVE-2016-0938, CVE-2016-0942, CVE-2016-0944, CVE-2016-0945, and CVE-2016-0946.
    (CVE-2016-0939)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 15.006.30119 / 15.010.20056 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/14");

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
  { 'max_version' : '15.006.30097', 'fixed_version' : '15.006.30119', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '15.009.20077', 'fixed_version' : '15.010.20056', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
