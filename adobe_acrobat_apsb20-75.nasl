##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144109);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id("CVE-2020-29075");
  script_xref(name:"IAVA", value:"2020-A-0572-S");

  script_name(english:"Adobe Acrobat < 2017.011.30188 / 2020.001.30018 / 2020.013.20074 Vulnerability (APSB20-75)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 2017.011.30188, 2020.001.30018,
or 2020.013.20074. It is, therefore, affected by a vulnerability.

  - Acrobat Reader DC versions 2020.013.20066 (and earlier), 2020.001.30010 (and earlier) and 2017.011.30180
    (and earlier) are affected by an information exposure vulnerability, that could enable an attacker to get
    a DNS interaction and track if the user has opened or closed a PDF file when loaded from the filesystem
    without a prompt. User interaction is required to exploit this vulnerability. (CVE-2020-29075)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-75.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2017.011.30188 / 2020.001.30018 / 2020.013.20074 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29075");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '17.8', 'max_version' : '17.011.30180', 'fixed_version' : '17.011.30188', 'track' : 'DC Classic' },
  { 'min_version' : '20.1', 'max_version' : '20.001.30010', 'fixed_version' : '20.001.30018', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '20.013.20066', 'fixed_version' : '20.013.20074', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_WARNING
);
