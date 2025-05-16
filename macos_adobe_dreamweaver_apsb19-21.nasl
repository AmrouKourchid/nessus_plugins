#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209424);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2019-7097");

  script_name(english:"Adobe Dreamweaver 18.0.0 < 18.2.1 / 19.0 < 19.1 Sensitive data disclosure if SMB request is subject to a relay attack (APSB19-21) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Dreamweaver instance installed on the remote host is affected by a sensitive data disclosure if smb request is
subject to a relay attack vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dreamweaver installed on the remote macOS host is prior to 18.2.1, 19.1. It is, therefore, affected
by a vulnerability as referenced in the APSB19-21 advisory.

  - Adobe Dreamweaver versions 19.0 and earlier have an insecure protocol implementation vulnerability.
    Successful exploitation could lead to sensitive data disclosure if smb request is subject to a relay
    attack. (CVE-2019-7097)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb19-21.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dreamweaver version 18.2.1, 19.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dreamweaver");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_dreamweaver_installed.nbin");
  script_require_keys("installed_sw/Adobe Dreamweaver");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Dreamweaver');

var constraints = [
  { 'min_version' : '18.0.0', 'max_version' : '18.2.0', 'fixed_version' : '18.2.1' },
  { 'min_version' : '19.0', 'max_version' : '19.0', 'fixed_version' : '19.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
