#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209458);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2019-7870");

  script_name(english:"Adobe Character Animator 2.0.0 < 2.1.1 Arbitrary code execution (APSB19-32)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Character Animator instance installed on the remote host is affected by an arbitrary code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Character Animator installed on the remote Windows host is prior to 2.1.1. It is, therefore,
affected by a vulnerability as referenced in the APSB19-32 advisory.

  - Adobe Character Animator versions 2.1 and earlier have an insecure library loading (dll hijacking)
    vulnerability. Successful exploitation could lead to arbitrary code execution. (CVE-2019-7870)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/character_animator/apsb19-32.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2559f59b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Character Animator version 2.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7870");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:character_animator");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_character_animator_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Character Animator");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Character Animator', win_local:TRUE);

var constraints = [
  { 'min_version' : '2.0.0', 'fixed_version' : '2.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
