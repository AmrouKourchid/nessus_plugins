#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87243);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2015-8045",
    "CVE-2015-8047",
    "CVE-2015-8048",
    "CVE-2015-8049",
    "CVE-2015-8050",
    "CVE-2015-8055",
    "CVE-2015-8056",
    "CVE-2015-8057",
    "CVE-2015-8058",
    "CVE-2015-8059",
    "CVE-2015-8060",
    "CVE-2015-8061",
    "CVE-2015-8062",
    "CVE-2015-8063",
    "CVE-2015-8064",
    "CVE-2015-8065",
    "CVE-2015-8066",
    "CVE-2015-8067",
    "CVE-2015-8068",
    "CVE-2015-8069",
    "CVE-2015-8070",
    "CVE-2015-8071",
    "CVE-2015-8401",
    "CVE-2015-8402",
    "CVE-2015-8403",
    "CVE-2015-8404",
    "CVE-2015-8405",
    "CVE-2015-8406",
    "CVE-2015-8407",
    "CVE-2015-8408",
    "CVE-2015-8409",
    "CVE-2015-8410",
    "CVE-2015-8411",
    "CVE-2015-8412",
    "CVE-2015-8413",
    "CVE-2015-8414",
    "CVE-2015-8415",
    "CVE-2015-8416",
    "CVE-2015-8417",
    "CVE-2015-8418",
    "CVE-2015-8419",
    "CVE-2015-8420",
    "CVE-2015-8421",
    "CVE-2015-8422",
    "CVE-2015-8423",
    "CVE-2015-8424",
    "CVE-2015-8425",
    "CVE-2015-8426",
    "CVE-2015-8427",
    "CVE-2015-8428",
    "CVE-2015-8429",
    "CVE-2015-8430",
    "CVE-2015-8431",
    "CVE-2015-8432",
    "CVE-2015-8433",
    "CVE-2015-8434",
    "CVE-2015-8435",
    "CVE-2015-8436",
    "CVE-2015-8437",
    "CVE-2015-8438",
    "CVE-2015-8439",
    "CVE-2015-8440",
    "CVE-2015-8441",
    "CVE-2015-8442",
    "CVE-2015-8443",
    "CVE-2015-8444",
    "CVE-2015-8445",
    "CVE-2015-8446",
    "CVE-2015-8447",
    "CVE-2015-8448",
    "CVE-2015-8449",
    "CVE-2015-8450",
    "CVE-2015-8451",
    "CVE-2015-8452",
    "CVE-2015-8453",
    "CVE-2015-8454",
    "CVE-2015-8455",
    "CVE-2015-8456",
    "CVE-2015-8457",
    "CVE-2015-8652",
    "CVE-2015-8653",
    "CVE-2015-8654",
    "CVE-2015-8655",
    "CVE-2015-8656",
    "CVE-2015-8657",
    "CVE-2015-8658",
    "CVE-2015-8820",
    "CVE-2015-8821",
    "CVE-2015-8822"
  );
  script_bugtraq_id(
    78710,
    78712,
    78713,
    78714,
    78715,
    78716,
    78717,
    78718,
    78802
  );
  script_xref(name:"ZDI", value:"ZDI-15-601");
  script_xref(name:"ZDI", value:"ZDI-15-602");
  script_xref(name:"ZDI", value:"ZDI-15-603");
  script_xref(name:"ZDI", value:"ZDI-15-604");
  script_xref(name:"ZDI", value:"ZDI-15-605");
  script_xref(name:"ZDI", value:"ZDI-15-606");
  script_xref(name:"ZDI", value:"ZDI-15-607");
  script_xref(name:"ZDI", value:"ZDI-15-608");
  script_xref(name:"ZDI", value:"ZDI-15-609");
  script_xref(name:"ZDI", value:"ZDI-15-610");
  script_xref(name:"ZDI", value:"ZDI-15-611");
  script_xref(name:"ZDI", value:"ZDI-15-612");
  script_xref(name:"ZDI", value:"ZDI-15-613");
  script_xref(name:"ZDI", value:"ZDI-15-614");
  script_xref(name:"ZDI", value:"ZDI-15-655");
  script_xref(name:"ZDI", value:"ZDI-15-656");
  script_xref(name:"ZDI", value:"ZDI-15-657");
  script_xref(name:"ZDI", value:"ZDI-15-658");
  script_xref(name:"ZDI", value:"ZDI-15-659");
  script_xref(name:"ZDI", value:"ZDI-15-660");
  script_xref(name:"ZDI", value:"ZDI-15-661");
  script_xref(name:"ZDI", value:"ZDI-15-662");
  script_xref(name:"ZDI", value:"ZDI-15-663");
  script_xref(name:"ZDI", value:"ZDI-15-664");
  script_xref(name:"EDB-ID", value:"39042");
  script_xref(name:"EDB-ID", value:"39043");
  script_xref(name:"EDB-ID", value:"39047");
  script_xref(name:"EDB-ID", value:"39049");
  script_xref(name:"EDB-ID", value:"39051");
  script_xref(name:"EDB-ID", value:"39052");
  script_xref(name:"EDB-ID", value:"39053");
  script_xref(name:"EDB-ID", value:"39054");
  script_xref(name:"EDB-ID", value:"39072");

  script_name(english:"Adobe AIR <= 19.0.0.241 Multiple Vulnerabilities (APSB15-32)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Windows host is equal
or prior to version 19.0.0.241. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-8438, CVE-2015-8446)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2015-8045,
    CVE-2015-8047, CVE-2015-8060, CVE-2015-8408,
    CVE-2015-8416, CVE-2015-8417, CVE-2015-8418,
    CVE-2015-8419, CVE-2015-8443, CVE-2015-8444,
    CVE-2015-8451, CVE-2015-8455, CVE-2015-8652,
    CVE-2015-8654, CVE-2015-8656, CVE-2015-8657,
    CVE-2015-8658, CVE-2015-8820)

  - Multiple security bypass vulnerabilities exist that
    allow an attacker to write arbitrary data to the file
    system under user permissions. (CVE-2015-8453,
    CVE-2015-8440,  CVE-2015-8409)

  - A stack buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8407,
    CVE-2015-8457)

  - A type confusion error exists that allows an attacker to
    execute arbitrary code. (CVE-2015-8439, CVE-2015-8456)

  - An integer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8445)

  - A buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8415)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-8048,
    CVE-2015-8049, CVE-2015-8050, CVE-2015-8055,
    CVE-2015-8056, CVE-2015-8057, CVE-2015-8058,
    CVE-2015-8059, CVE-2015-8061, CVE-2015-8062,
    CVE-2015-8063, CVE-2015-8064, CVE-2015-8065,
    CVE-2015-8066, CVE-2015-8067, CVE-2015-8068,
    CVE-2015-8069, CVE-2015-8070, CVE-2015-8071,
    CVE-2015-8401, CVE-2015-8402, CVE-2015-8403,
    CVE-2015-8404, CVE-2015-8405, CVE-2015-8406,
    CVE-2015-8410, CVE-2015-8411, CVE-2015-8412,
    CVE-2015-8413, CVE-2015-8414, CVE-2015-8420,
    CVE-2015-8421, CVE-2015-8422, CVE-2015-8423,
    CVE-2015-8424, CVE-2015-8425, CVE-2015-8426,
    CVE-2015-8427, CVE-2015-8428, CVE-2015-8429,
    CVE-2015-8430, CVE-2015-8431, CVE-2015-8432,
    CVE-2015-8433, CVE-2015-8434, CVE-2015-8435,
    CVE-2015-8436, CVE-2015-8437, CVE-2015-8441,
    CVE-2015-8442, CVE-2015-8447, CVE-2015-8448,
    CVE-2015-8449, CVE-2015-8450, CVE-2015-8452,
    CVE-2015-8454, CVE-2015-8653, CVE-2015-8655,
    CVE-2015-8821, CVE-2015-8822");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 20.0.0.204 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8457");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui + ' (' + version + ')';

cutoff_version = '19.0.0.245';
fix = '20.0.0.204';
fix_ui = '20.0';

if (ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
