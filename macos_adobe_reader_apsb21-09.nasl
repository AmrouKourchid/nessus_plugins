##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146423);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-21017",
    "CVE-2021-21021",
    "CVE-2021-21028",
    "CVE-2021-21033",
    "CVE-2021-21034",
    "CVE-2021-21035",
    "CVE-2021-21036",
    "CVE-2021-21037",
    "CVE-2021-21038",
    "CVE-2021-21039",
    "CVE-2021-21040",
    "CVE-2021-21041",
    "CVE-2021-21042",
    "CVE-2021-21044",
    "CVE-2021-21045",
    "CVE-2021-21046",
    "CVE-2021-21057",
    "CVE-2021-21058",
    "CVE-2021-21059",
    "CVE-2021-21060",
    "CVE-2021-21061",
    "CVE-2021-21062",
    "CVE-2021-21063",
    "CVE-2021-21086",
    "CVE-2021-21088",
    "CVE-2021-21089",
    "CVE-2021-28545",
    "CVE-2021-28546",
    "CVE-2021-40723"
  );
  script_xref(name:"IAVA", value:"2021-A-0092-S");
  script_xref(name:"IAVA", value:"2021-A-0157-S");
  script_xref(name:"IAVA", value:"2021-A-0229-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Adobe Reader < 2017.011.30190 / 2020.001.30020 / 2021.001.20135 Multiple Vulnerabilities (APSB21-09) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 2017.011.30190, 2020.001.30020, or
2021.001.20135. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a Use After Free vulnerability. An unauthenticated attacker
    could leverage this vulnerability to achieve arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-21021, CVE-2021-21028, CVE-2021-21033, CVE-2021-21035, CVE-2021-21039, CVE-2021-21040,
    CVE-2021-21088)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a Memory corruption vulnerability when parsing a specially
    crafted PDF file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2021-21058, CVE-2021-21059, CVE-2021-21062, CVE-2021-21063)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an memory corruption vulnerability. An unauthenticated
    attacker could leverage this vulnerability to cause an application denial-of-service. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-21046)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a heap-based buffer overflow vulnerability. An
    unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-21017)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a Path Traversal vulnerability. An unauthenticated attacker
    could leverage this vulnerability to achieve arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-21037)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2017.011.30190 / 2020.001.30020 / 2021.001.20135 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21063");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21035");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Adobe Reader');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '17.8', 'max_version' : '17.011.30188', 'fixed_version' : '17.011.30190', 'track' : 'DC Classic' },
  { 'min_version' : '20.1', 'max_version' : '20.001.30018', 'fixed_version' : '20.001.30020', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '20.013.20074', 'fixed_version' : '21.001.20135', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
