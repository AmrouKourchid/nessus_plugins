#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154154);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2021-40728",
    "CVE-2021-40729",
    "CVE-2021-40730",
    "CVE-2021-40731"
  );
  script_xref(name:"IAVA", value:"2021-A-0458-S");

  script_name(english:"Adobe Reader < 17.011.30204 / 20.004.30017 / 21.007.20099 Multiple Vulnerabilities (APSB21-104) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 17.011.30204, 20.004.30017, or
21.007.20099. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader DC version 21.007.20095 (and earlier), 21.007.20096 (and earlier), 20.004.30015 (and
    earlier), and 17.011.30202 (and earlier) is affected by an out-of-bounds write vulnerability when parsing
    a crafted JPEG2000 file, which could result in arbitrary code execution in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-40731)

  - Adobe Acrobat Reader DC version 21.007.20095 (and earlier), 21.007.20096 (and earlier), 20.004.30015 (and
    earlier), and 17.011.30202 (and earlier) is affected by a use-after-free vulnerability in the processing
    of the GetURL function on a global object window that could result in arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-40728)

  - Adobe Acrobat Reader DC version 21.007.20095 (and earlier), 21.007.20096 (and earlier), 20.004.30015 (and
    earlier), and 17.011.30202 (and earlier) is affected by a out-of-bounds read vulnerability that could lead
    to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations
    such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious
    PDF file. (CVE-2021-40729)

  - Adobe Acrobat Reader DC version 21.007.20095 (and earlier), 21.007.20096 (and earlier), 20.004.30015 (and
    earlier), and 17.011.30202 (and earlier) is affected by a use-after-free that allow a remote attacker to
    disclose sensitive information on affected installations of of Adobe Acrobat Reader DC. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the parsing of JPG2000 images. (CVE-2021-40730)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-104.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 17.011.30204 / 20.004.30017 / 21.007.20099 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40731");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

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
  { 'min_version' : '17.8', 'max_version' : '17.011.30202', 'fixed_version' : '17.011.30204', 'track' : 'DC Classic' },
  { 'min_version' : '20.1', 'max_version' : '20.004.30015', 'fixed_version' : '20.004.30017', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '21.007.20096', 'fixed_version' : '21.007.20099', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_WARNING
);
