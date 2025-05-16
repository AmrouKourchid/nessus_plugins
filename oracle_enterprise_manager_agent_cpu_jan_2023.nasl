#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192753);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/25");

  script_cve_id("CVE-2022-42889");
  script_xref(name:"IAVA", value:"2023-A-0038");

  script_name(english:"Oracle Enterprise Manager Agent (January 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an arbitrary code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The 13.4.0.0 and 13.5.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by a
vulnerability as referenced in the January 2023 CPU advisory.

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Management Agent). Supported versions that are affected are 13.4.0.0 and 13.5.0.0. Apache Commons Text performs 
    variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for 
    interpolation is '${prefix:name}', where 'prefix' is used to locate an instance of 
    org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and 
    continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary 
    code execution or contact with remote servers. These lookups are: - 'script' - execute expressions using the JVM 
    script execution engine (javax.script) - 'dns' - resolve dns records - 'url' - load values from urls, including 
    from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to 
    remote code execution or unintentional contact with remote servers if untrusted configuration values are used. 
    (CVE-2022-42889)

    Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42889");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Commons Text RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_agent_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Agent");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");
include("install_func.inc");
include("debug.inc");
include("oracle_manager_agent_patch_mapping.inc");

var product = 'Oracle Enterprise Manager Agent';
var install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
var version = install['version'];
var emchome = install['path'];


if (version != '13.4.0.0.0' && version != '13.5.0.0.0')
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

var patch;
if (version == '13.4.0.0.0')
{
  patch = '34692141';
}
else if (version == '13.5.0.0.0')
{
  patch = '34795397';
}

var patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));

var patchid, ver;

if (!isnull(patchesinstalled))
{
  foreach patchid (keys(patchesinstalled[emchome]))
  {
    dbg::detailed_log(lvl: 3, src: SCRIPT_NAME, msg: "Found patch " + patchid + " corresponding to home " + emchome);
    ver = enterprise_manager_agent_version_map[patchid];
    if (!isnull(ver))
    {
      dbg::detailed_log(lvl: 3, src: SCRIPT_NAME, msg: "Patch " + patchid + " is for version " + ver);

      if ((version == '13.4.0.0.0' && ver_compare(ver:ver, fix:'13.4.0.19', strict:FALSE) >= 0) ||
          (version == '13.5.0.0.0' && ver_compare(ver:ver, fix:'13.5.0.12', strict:FALSE) >= 0))
      {
        audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);
      }
    }
  }
}

var report =
  '\n  Product       : ' + product +
  '\n  Version       : ' + version +
  '\n  Path          : ' + emchome +
  '\n  Missing patch : ' + patch + ' or later'
  '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
