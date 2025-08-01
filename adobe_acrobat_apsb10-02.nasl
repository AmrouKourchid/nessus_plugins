#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(43875);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2009-3953",
    "CVE-2009-3954",
    "CVE-2009-3955",
    "CVE-2009-3956",
    "CVE-2009-3957",
    "CVE-2009-3958",
    "CVE-2009-3959",
    "CVE-2009-4324",
    "CVE-2010-1278"
  );
  script_bugtraq_id(
    37331,
    37756,
    37757,
    37758,
    37759,
    37760,
    37761,
    37763,
    39615
  );
  script_xref(name:"CERT", value:"508357");
  script_xref(name:"Secunia", value:"37690");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Adobe Acrobat < 9.3 / 8.2  Multiple Vulnerabilities (APSB10-02)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 9.3 / 8.2.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A use-after-free vulnerability in 'Multimedia.api' can
    lead to code execution. (CVE-2009-4324)

  - An array boundary issue in 'U3D' support can lead to
    code execution. (CVE-2009-3953)

  - A DLL-loading vulnerability in '3D' can allow arbitrary
    code execution. (CVE-2009-3954)

  - A memory corruption vulnerability can lead to code
    execution. (CVE-2009-3955)

  - A script injection vulnerability. (CVE-2009-3956)

  - A NULL pointer dereference vulnerability can lead to a
    denial of service. (CVE-2009-3957)

  - A buffer overflow vulnerability in the Download Manager
    can lead to code execution. (CVE-2009-3958)

  - An integer overflow vulnerability in 'U3D' support can
    lead to code execution. (CVE-2009-3959)

  - A buffer overflow in the 'gp.ocx' ActiveX control can
    lead to code execution. (CVE-2010-1278)");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-10-077/");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/510868/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 9.3 / 8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3959");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Doc.media.newPlayer Use After Free Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(16, 94, 119, 189, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("installed_sw/Adobe Acrobat");

  exit(0);
}

include('install_func.inc');

var install = get_single_install(app_name:'Adobe Acrobat', exit_if_unknown_ver:TRUE);

var version = install.version;

var ver = split(version, sep:'.', keep:FALSE);
for (var i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if  ( 
  ver[0] < 8 ||
  (ver[0] == 8 && ver[1] < 2) ||
  (ver[0] == 9 && ver[1] < 3)
)
{
  var version_ui = install.display_version;
  if (report_verbosity > 0 && version_ui)
  {
    var path = install.path;
    if (isnull(path)) path = 'n/a';

    var report = string(
      '\n',
      '  Product           : Adobe Acrobat\n',
      '  Path              : ', path, '\n',
      '  Installed version : ', version_ui, '\n',
      '  Fixed version     : 9.3 / 8.2\n'
    );
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The host is not affected since Adobe Acrobat "+version+" is installed.");
