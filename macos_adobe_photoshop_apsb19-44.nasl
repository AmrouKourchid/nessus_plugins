#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127898);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2019-7968",
    "CVE-2019-7969",
    "CVE-2019-7970",
    "CVE-2019-7971",
    "CVE-2019-7972",
    "CVE-2019-7973",
    "CVE-2019-7975",
    "CVE-2019-7976",
    "CVE-2019-7977",
    "CVE-2019-7978",
    "CVE-2019-7979",
    "CVE-2019-7980",
    "CVE-2019-7981",
    "CVE-2019-7982",
    "CVE-2019-7983",
    "CVE-2019-7984",
    "CVE-2019-7985",
    "CVE-2019-7986",
    "CVE-2019-7987",
    "CVE-2019-7988",
    "CVE-2019-7989",
    "CVE-2019-7990",
    "CVE-2019-7991",
    "CVE-2019-7992",
    "CVE-2019-7993",
    "CVE-2019-7994",
    "CVE-2019-7995",
    "CVE-2019-7996",
    "CVE-2019-7997",
    "CVE-2019-7998",
    "CVE-2019-7999",
    "CVE-2019-8000",
    "CVE-2019-8001"
  );

  script_name(english:"Adobe Photoshop CC 19.x < 19.1.9 / CC 20.x < 20.0.6 Multiple Vulnerabilities (macOS APSB19-44)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC installed on the remote macOS or Mac OS X host is prior to 19.1.9/20.0.6. It is,
therefore, affected by multiple vulnerabilities as referenced in the apsb19-44 advisory.

  - Adobe Photoshop CC versions 19.1.8 and earlier and 20.0.5 and earlier have an out of bound write
    vulnerability. Successful exploitation could lead to arbitrary code execution. (CVE-2019-7976,
    CVE-2019-7979, CVE-2019-7982, CVE-2019-7983, CVE-2019-7984, CVE-2019-7986, CVE-2019-7988, CVE-2019-7992,
    CVE-2019-7994, CVE-2019-7997, CVE-2019-7998, CVE-2019-8001)

  - Adobe Photoshop CC versions 19.1.8 and earlier and 20.0.5 and earlier have a heap overflow vulnerability.
    Successful exploitation could lead to arbitrary code execution. (CVE-2019-7978, CVE-2019-7985,
    CVE-2019-7990, CVE-2019-7993)

  - Adobe Photoshop CC versions 19.1.8 and earlier and 20.0.5 and earlier have a type confusion vulnerability.
    Successful exploitation could lead to arbitrary code execution. (CVE-2019-7969, CVE-2019-7970,
    CVE-2019-7971, CVE-2019-7972, CVE-2019-7973, CVE-2019-7975, CVE-2019-7980)

  - Adobe Photoshop CC versions 19.1.8 and earlier and 20.0.5 and earlier have an out of bound read
    vulnerability. Successful exploitation could lead to memory leak. (CVE-2019-7977, CVE-2019-7981,
    CVE-2019-7987, CVE-2019-7991, CVE-2019-7995, CVE-2019-7996, CVE-2019-7999, CVE-2019-8000)

  - Adobe Photoshop CC versions 19.1.8 and earlier and 20.0.5 and earlier have a command injection
    vulnerability. Successful exploitation could lead to arbitrary code execution. (CVE-2019-7968,
    CVE-2019-7989)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb19-44.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 19.1.9/20.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8001");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/MacOSX/Version", "Host/local_checks_enabled", "installed_sw/Adobe Photoshop");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Photoshop');

var constraints = [
  { 'min_version' : '19.0.0', 'fixed_version' : '19.1.9' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.0.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
