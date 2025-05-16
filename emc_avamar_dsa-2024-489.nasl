#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(213006);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2024-47977", "CVE-2024-47484", "CVE-2024-52538");
  script_xref(name:"IAVA", value:"2024-A-0795");

  script_name(english:"Dell Avamar / AVE < 19.10 Hotfix 338869 Multiple Vulnerabilities (DSA-2024-489)");

  script_set_attribute(attribute:"synopsis", value:
"A backup solution running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Dell Avamar or Avamar Virtual Edition (AVE)
software running on the remote host is 19.x prior to 19.10 Hotfix 338869 (19.10.0.166). It is, 
therefore, affected by multiple vulnerabilities: 

  - Dell Avamar, version(s) 19.9, contain(s) an Improper Neutralization of Special 
    Elements used in an SQL Command ('SQL Injection') vulnerability. A low privileged 
    attacker with remote access could potentially exploit this vulnerability, 
    leading to Command execution. (CVE-2024-47977)

  - Dell Avamar, version(s) 19.9, contain(s) an Improper Neutralization of Special 
    Elements used in an SQL Command ('SQL Injection') vulnerability. An 
    unauthenticated attacker with remote access could potentially exploit this 
    vulnerability, leading to Command execution. (CVE-2024-47484)

  - Dell Avamar, version(s) 19.9, contain(s) an Improper Neutralization of Special 
    Elements used in an SQL Command ('SQL Injection') vulnerability. A low privileged 
    attacker with remote access could potentially exploit this vulnerability, leading to 
    Script injection. (CVE-2024-52538)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000258636/dsa-2024-489-security-update-for-dell-avamar-and-dell-avamar-virtual-edition-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27c4c1fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Avamar ADS / AVE version 7.3.1 Hotfix 290316 (7.3.1.125)
/ 7.4.1 Hotfix 291882 (7.4.1.58) / 7.5.0 Hotfix 291881 (7.5.0.183)
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_data_store");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_server_virtual_edition");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_avamar_server_detect.nbin", "emc_avamar_server_installed_nix.nbin");
  script_require_keys("installed_sw/EMC Avamar");

  exit(0);
}

include("install_func.inc");
include("http.inc");

var app = "EMC Avamar";
get_install_count(app_name:app, exit_if_zero:TRUE);

var install = make_array();
var port = 0;

if (get_kb_item("installed_sw/EMC Avamar/local"))
{
  install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
}
else
{
  port = get_http_port(default:443);
  install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
}

var version    = install['version'];
var version_ui = install['display_version'];
var hotfixes   = install['Hotfixes'];

var note = NULL;

if (version =~ "^19\.([4789]|10)")
{
  var fix_ver = '19.10.0.166';
  var fix_hf  = '338869';
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) > 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0)
{
  # Remote detection cannot detect hotfix; only flag host if paranoid reporting is enabled
  if (port != 0)
  {
    if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN);
    else
      note = "Note that Nessus was unable to remotely detect the hotfix.";
  }

  if (!empty_or_null(hotfixes))
  {
    hotfixes = split(hotfixes, sep:";", keep:FALSE);
    foreach var hotfix (hotfixes)
    {
      if (fix_hf == hotfix)
        audit(AUDIT_INST_VER_NOT_VULN, app, version_ui + " HF" + hotfix);
    }
  }
}

var report =
  '\n  Installed version : ' + version_ui +
  '\n  Fixed version     : ' + fix_ver + " HF" + fix_hf +
  '\n';

if (!isnull(note))
  report += note + '\n';

security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
