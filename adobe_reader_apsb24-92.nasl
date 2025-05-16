#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212262);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2024-49530",
    "CVE-2024-49531",
    "CVE-2024-49532",
    "CVE-2024-49533",
    "CVE-2024-49534",
    "CVE-2024-49535"
  );
  script_xref(name:"IAVA", value:"2024-A-0781-S");

  script_name(english:"Adobe Reader < 20.005.30748 / 24.005.20320 Multiple Vulnerabilities (APSB24-92)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior to 20.005.30748 or 24.005.20320. It
is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader versions 24.005.20307, 24.001.30213, 24.001.30193, 20.005.30730, 20.005.30710 and earlier
    are affected by a Use After Free vulnerability that could result in arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2024-49530)

  - Acrobat Reader versions 24.005.20307, 24.001.30213, 24.001.30193, 20.005.30730, 20.005.30710 and earlier
    are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could
    result in arbitrary code execution. This vulnerability allows an attacker to provide malicious XML input
    containing a reference to an external entity, leading to data disclosure or potentially code execution.
    Exploitation of this issue requires user interaction in that a victim must process a malicious XML
    document. (CVE-2024-49535)

  - Acrobat Reader versions 24.005.20307, 24.001.30213, 24.001.30193, 20.005.30730, 20.005.30710 and earlier
    are affected by a NULL Pointer Dereference vulnerability that could result in an application denial-of-
    service. An attacker could exploit this vulnerability to crash the application, leading to a denial-of-
    service condition. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2024-49531)

  - Acrobat Reader versions 24.005.20307, 24.001.30213, 24.001.30193, 20.005.30730, 20.005.30710 and earlier
    are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An
    attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2024-49532, CVE-2024-49533,
    CVE-2024-49534)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb24-92.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 20.005.30748 / 24.005.20320 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49530");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(125, 416, 476, 611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '20.1', 'max_version' : '20.005.30730', 'fixed_version' : '20.005.30748', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '24.005.20307', 'fixed_version' : '24.005.20320', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
