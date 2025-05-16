#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186910);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id("CVE-2023-6186");
  script_xref(name:"IAVB", value:"2023-B-0098-S");

  script_name(english:"LibreOffice 7.5 < 7.5.9 / 7.6 < 7.6.4 Arbitrary Script Execution (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An Arbitrary Script Execution vulnerability exist in Document Foundation LibreOffice versions prior to 7.5.9 or 7.6.4.");
  script_set_attribute(attribute:"description", value:
"LibreOffice supports hyperlinks. In addition to the typical common protocols such as http/https hyperlinks can also 
have target URLs that can launch built-in macros or dispatch built-in internal commands. In affected version of 
LibreOffice there are scenarios where these can be executed without warning if the user activates such hyperlinks. In 
later versions the users's explicit macro execution permissions for the document are now consulted if these non-typical 
hyperlinks can be executed. The possibility to use these variants of hyperlink targets for floating frames has been removed.
This issue affects: The Document Foundation LibreOffice 7.5 versions prior to 7.5.9; 7.6 versions prior to 7.6.4.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2023-6186");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 7.5.9, 7.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'LibreOffice');

var constraints = [
  {'min_version':'7.5', 'fixed_version':'7.5.9'},
  {'min_version':'7.6', 'fixed_version':'7.6.4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
