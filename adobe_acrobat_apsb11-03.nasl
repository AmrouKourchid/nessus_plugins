#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('compat.inc');

if (description)
{
  script_id(51924);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2010-4091", "CVE-2011-0558", "CVE-2011-0559", "CVE-2011-0560",
                "CVE-2011-0561", "CVE-2011-0562", "CVE-2011-0563", "CVE-2011-0564",
                "CVE-2011-0565", "CVE-2011-0566", "CVE-2011-0567", "CVE-2011-0570", 
                "CVE-2011-0571", "CVE-2011-0572", "CVE-2011-0573", "CVE-2011-0574", 
                "CVE-2011-0575", "CVE-2011-0577", "CVE-2011-0578", "CVE-2011-0585",
                "CVE-2011-0586", "CVE-2011-0587", "CVE-2011-0588", "CVE-2011-0589", 
                "CVE-2011-0590", "CVE-2011-0591", "CVE-2011-0592", "CVE-2011-0593", 
                "CVE-2011-0594", "CVE-2011-0595", "CVE-2011-0596", "CVE-2011-0598", 
                "CVE-2011-0599", "CVE-2011-0600", "CVE-2011-0602", "CVE-2011-0603", 
                "CVE-2011-0604", "CVE-2011-0606", "CVE-2011-0607", "CVE-2011-0608");

  script_bugtraq_id(
    44638,
    46186,
    46187,
    46188,
    46189,
    46190,
    46191,
    46192,
    46193,
    46194,
    46195,
    46196,
    46197,
    46198, 
    46199,
    46201,
    46202,
    46204,
    46207,
    46208,
    46209,
    46210,
    46211,
    46212,
    46213,
    46214,
    46216,
    46217,
    46218,
    46219,
    46220,
    46221,
    46222,
    46251,
    46252,
    46254,
    46255,
    46257,
    46282,
    46283
  );

  script_name(english:"Adobe Acrobat < 10.0.1 / 9.4.2 / 8.2.5 Multiple Vulnerabilities (APSB11-03)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Acrobat on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 10.0.1 / 9.4.2 / 8.2.5.  Such versions are reportedly affected by
multiple vulnerabilities :

  - Multiple input validation vulnerability exist that could
    lead to code execution. (CVE-2010-4091, CVE-2011-0586,
    CVE-2011-0587, CVE-2011-0604)
    
  - Multiple library loading vulnerabilities exist that 
    could lead to code execution. (CVE-2011-0562, 
    CVE-2011-0570, CVE-2011-0575, CVE-2011-0588)
    
  - Multiple memory corruption vulnerabilities exist that 
    could lead to code execution. (CVE-2011-0563, 
    CVE-2011-0559, CVE-2011-0560, CVE-2011-0561,
    CVE-2011-0571, CVE-2011-0572, CVE-2011-0573,
    CVE-2011-0574, CVE-2011-0578, CVE-2011-0589,
    CVE-2011-0606, CVE-2011-0607, CVE-2011-0608)
    
  - A Windows-only file permissions issue exists that could 
    lead to privilege escalation. (CVE-2011-0564)
    
  - An unspecified vulnerability exists that could cause the
    application to crash or potentially lead to code 
    execution. (CVE-2011-0565)
    
  - Multiple image-parsing memory corruption vulnerabilities 
    exist that could lead to code execution. (CVE-2011-0566, 
    CVE-2011-0567, CVE-2011-0596, CVE-2011-0598,
    CVE-2011-0599, CVE-2011-0602, CVE-2011-0603)

  - An unspecified vulnerability exists that could cause the
    application to crash or potentially lead to code
    execution. (CVE-2011-0585)

  - Multiple 3D file parsing input validation 
    vulnerabilities exist that could lead to code execution.
    (CVE-2011-0590, CVE-2011-0591, CVE-2011-0592,
     CVE-2011-0593, CVE-2011-0595, CVE-2011-0600)
  
  - Multiple font parsing input validation vulnerabilities 
    exist that could lead to code execution. (CVE-2011-0594,
    CVE-2011-0577)

  - An integer overflow vulnerability exists that could lead 
    to code execution. (CVE-2011-0558)");

  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-065/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-066/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-067/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-068/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-069/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-070/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-071/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-072/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-073/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-074/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-075/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-077/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-081/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-03.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 8.2.6 / 9.4.2 / 10.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4091");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable Network Security, Inc.");
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
  (ver[0] < 8) ||
  (ver[0] == 8 && ver[1] < 2) ||
  (ver[0] == 8 && ver[1] == 2 && ver[2] < 6) ||
  (ver[0] == 9 && ver[1]  < 4) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 2) ||
  (ver[0] == 10 && ver[1] == 0 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    var path = install.path;
    if (isnull(path)) path = 'n/a';

    var report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 8.2.6 / 9.4.2 / 10.0.1\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The host is not affected since Adobe Acrobat "+version_report+" is installed.");
