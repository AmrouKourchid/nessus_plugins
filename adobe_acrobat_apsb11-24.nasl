#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('compat.inc');

if (description)
{
  script_id(56197);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2011-2130",
    "CVE-2011-2134",
    "CVE-2011-2135",
    "CVE-2011-2136",
    "CVE-2011-2137",
    "CVE-2011-2138",
    "CVE-2011-2139",
    "CVE-2011-2140",
    "CVE-2011-2414",
    "CVE-2011-2415",
    "CVE-2011-2416",
    "CVE-2011-2417",
    "CVE-2011-2424",
    "CVE-2011-2425",
    "CVE-2011-2431",
    "CVE-2011-2432",
    "CVE-2011-2433",
    "CVE-2011-2434",
    "CVE-2011-2435",
    "CVE-2011-2436",
    "CVE-2011-2437",
    "CVE-2011-2438",
    "CVE-2011-2439",
    "CVE-2011-2440",
    "CVE-2011-2441",
    "CVE-2011-2442"
  );
  script_bugtraq_id(
    49073,
    49074,
    49075,
    49076,
    49077,
    49079,
    49080,
    49081,
    49082,
    49083,
    49084,
    49085,
    49086,
    49186,
    49572,
    49575,
    49576,
    49577,
    49578,
    49579,
    49580,
    49581,
    49582,
    49583,
    49584,
    49585
  );
  script_xref(name:"EDB-ID", value:"18437");
  script_xref(name:"EDB-ID", value:"18479");
  
  script_name(english:"Adobe Acrobat < 10.1.1 / 9.4.6 / 8.3.1 Multiple Vulnerabilities (APSB11-21, APSB11-24)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Acrobat on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 10.1.1 / 9.4.6 / 8.3.1.  It is, therefore, potentially affected 
by the following vulnerabilities :

  - An unspecified error exists that can allow an attacker
    to bypass security leading to code execution. 
    (CVE-2011-2431)

  - Several errors exist that allow buffer overflows
    leading to code execution. (CVE-2011-2432, 
    CVE-2011-2435)

  - Several errors exist that allow heap overflows leading
    to code execution. (CVE-2011-2433, CVE-2011-2434, 
    CVE-2011-2436, CVE-2011-2437)

  - Several errors exist that allow stack overflows leading
    to code execution. (CVE-2011-2438)

  - An error exists that can allow memory leaks leading to
    code execution. (CVE-2011-2439)

  - A use-after-free error exists that can allow code
    exection. (CVE-2011-2440)

  - Several errors exist in the 'CoolType.dll' library that
    can allow stack overflows leading to code execution.
    (CVE-2011-2441)

  - A logic error exists that can lead to code execution.
    (CVE-2011-2442)

  - Multiple issues exist as noted in APSB11-21, a security
    update for Adobe Flash Player. (CVE-2011-2130, 
    CVE-2011-2134, CVE-2011-2135, CVE-2011-2136, 
    CVE-2011-2137, CVE-2011-2138, CVE-2011-2139, 
    CVE-2011-2140, CVE-2011-2414, CVE-2011-2415, 
    CVE-2011-2416, CVE-2011-2417, CVE-2011-2425, 
    CVE-2011-2424)");

  # http://www.abysssec.com/blog/2012/01/31/exploiting-cve-2011-2140-another-flash-player-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46d1fce8");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-282/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-283/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-284/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-296/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-297/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-298/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-299/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-300/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-301/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-302/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-310/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 8.3.1 / 9.4.6 / 10.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2130");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

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
  (ver[0] == 8 && ver[1]  < 3) ||
  (ver[0] == 8 && ver[1] == 3  && ver[2] < 1) ||
  (ver[0] == 9 && ver[1]  < 4) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 6) ||
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    var path = install.path;
    if (isnull(path)) path = 'n/a';

    var report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 8.3.1 / 9.4.6 / 10.1.1\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The host is not affected since Adobe Acrobat "+version_report+" is installed.");
