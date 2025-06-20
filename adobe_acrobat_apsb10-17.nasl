#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if (description)
{
  script_id(48374);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_xref(name:"Secunia", value:"40766");
  script_xref(name:"Secunia", value:"40907");

  script_name(english:"Adobe Acrobat < 9.3.4 / 8.2.4  Multiple Vulnerabilities (APSB10-17)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_cve_id(
    "CVE-2010-0209",
    "CVE-2010-1240",
    "CVE-2010-2188",
    "CVE-2010-2213",
    "CVE-2010-2214",
    "CVE-2010-2215",
    "CVE-2010-2216",
    "CVE-2010-2862"
  );
  script_bugtraq_id(39109, 40798, 42203, 42358, 42361, 42362, 42363, 42364);

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Acrobat on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 9.3.4 / 8.2.4.  Such versions are reportedly affected by multiple
vulnerabilities :

  - Multiple vulnerabilities in the bundled Flash
    Player as noted in APSB10-16. (CVE-2010-0209,
    CVE-2010-2188, CVE-2010-2213, CVE-2010-2214,
    CVE-2010-2215, CVE-2010-2216)

  - A social engineering attack could lead to code 
    execution. (CVE-2010-1240)

  - An integer overflow vulnerability could lead to
    code execution. (CVE-2010-2862)");
  script_set_attribute(attribute:"see_also", value:"http://securityevaluators.com/knowledge/papers/CrashAnalysis.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-17.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 9.3.4 / 8.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0209");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe PDF Escape EXE Social Engineering (No JavaScript)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");
  script_dependencies('adobe_acrobat_installed.nasl');
  script_require_keys('installed_sw/Adobe Acrobat');
  exit(0);
}

include('install_func.inc');

var install = get_single_install(app_name:'Adobe Acrobat', exit_if_unknown_ver:TRUE);

var version = install.version;
var version_ui = install.display_version;

var version_report;
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

var ver = split(version, sep:'.', keep:FALSE);
for (var i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if ( 
  ver[0]  < 8 ||
  (ver[0] == 8 && ver[1]  < 2) ||
  (ver[0] == 8 && ver[1] == 2  && ver[2] < 4) ||
  (ver[0] == 9 && ver[1]  < 3) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 4)
)
{
  if (report_verbosity > 0)
  {
    var path = install.path;
    if (isnull(path)) path = 'n/a';

    var report =
      '\n  Product           : Adobe Acrobat'+
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 9.3.4 / 8.2.4\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The host is not affected since Adobe Acrobat "+version_report+" is installed.");
