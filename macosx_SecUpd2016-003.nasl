#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91229);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id(
    "CVE-2016-1791",
    "CVE-2016-1800",
    "CVE-2016-1833",
    "CVE-2016-1834",
    "CVE-2016-1835",
    "CVE-2016-1836",
    "CVE-2016-1837",
    "CVE-2016-1838",
    "CVE-2016-1839",
    "CVE-2016-1840",
    "CVE-2016-1841",
    "CVE-2016-1847"
  );
  script_bugtraq_id(90696);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-05-16-4");

  script_name(english:"Mac OS X 10.9.5 / 10.10.5 Multiple Vulnerabilities (Security Update 2016-003)");
  script_summary(english:"Checks for the presence of Security Update 2016-003.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.9.5 or
10.10.5 and is missing Security Update 2016-003. It is, therefore,
affected by multiple vulnerabilities in the following components :

  - AMD
  - Captive Network Assistant
  - libxml2
  - libxslt
  - OpenGL

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206567");
  # http://lists.apple.com/archives/security-announce/2016/May/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46de3fda");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2016-003 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1834");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

patch = "2016-003";

# Compare 2 patch numbers to determine if patch requirements are satisfied.
# Return true if this patch or a later patch is applied
# Return false otherwise
function check_patch(year, number)
{
  local_var p_split = split(patch, sep:"-");
  local_var p_year  = int( p_split[0]);
  local_var p_num   = int( p_split[1]);

  if (year >  p_year) return TRUE;
  else if (year <  p_year) return FALSE;
  else if (number >=  p_num) return TRUE;
  else return FALSE;
}

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os)
  audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.(9|10)\.5([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.9.5 or Mac OS X 10.10.5");

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = egrep(pattern:"^com\.apple\.pkg\.update\.security\..*bom$", string:packages);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab patch year and number
  match = eregmatch(pattern:"[^0-9](20[0-9][0-9])[-.]([0-9]{3})[^0-9]", string:package);
  if (empty_or_null(match[1]) || empty_or_null(match[2]))
    continue;

  patch_found = check_patch(year:int(match[1]), number:int(match[2]));
  if (patch_found) exit(0, "The host has Security Update " + patch + " or later installed and is therefore not affected.");
}

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
