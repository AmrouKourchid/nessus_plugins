#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152029);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2021-35997");
  script_xref(name:"IAVA", value:"2021-A-0340-S");

  script_name(english:"Adobe Premiere Pro < 15.4 Arbitrary Code Execution (APSB21-56)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Premiere Pro instance installed on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Pro installed on the remote Windows host is prior to 15.4. It is, therefore, affected by a
vulnerability as referenced in the APSB21-56 advisory.

  - Adobe Premiere Pro version 15.2 (and earlier) is affected by a memory corruption vulnerability when
    parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve
    arbitrary code execution in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-35997)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/premiere_pro/apsb21-56.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Pro version 15.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35997");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro_cc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_pro_installed.nasl");
  script_require_keys("installed_sw/Adobe Premiere Pro", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Premiere Pro', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '15.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
