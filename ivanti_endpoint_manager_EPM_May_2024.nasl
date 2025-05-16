#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197921);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id(
    "CVE-2024-29822",
    "CVE-2024-29823",
    "CVE-2024-29824",
    "CVE-2024-29825",
    "CVE-2024-29826",
    "CVE-2024-29827",
    "CVE-2024-29828",
    "CVE-2024-29829",
    "CVE-2024-29830",
    "CVE-2024-29846"
  );
  script_xref(name:"IAVB", value:"2024-B-0066-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/23");

  script_name(english:"Ivanti Endpoint Manager - May 2024 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager running on the remote host lacking the May 2024 
Hotfix. It is, therefore, affected by multiple vulnerabilities.

  - An unspecified SQL Injection vulnerability in Core server 
    of Ivanti EPM 2022 SU5 and prior allows an unauthenticated 
    attacker within the same network to execute arbitrary code. 
    (CVE-2024-29822, CVE-2024-29823, CVE-2024-29824, 
    CVE-2024-29825,CVE-2024-29826,CVE-2024-29827)

  - An unspecified SQL Injection vulnerability in Core server 
    of Ivanti EPM 2022 SU5 and prior allows an authenticated 
    attacker within the same network to execute arbitrary code.
    (CVE-2024-29828, CVE-2024-29829, CVE-2024-29830, 
    CVE-2024-29846)

Note that Nessus has not tested for these issues but has instead relied only on the 
service's self-reported version number of the affected dll files.");
  script_set_attribute(attribute:"see_also", value:"https://forums.ivanti.com/s/article/Security-Advisory-May-2024");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29827");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ivanti EPM RecordGoodApp SQLi RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager_cloud_services_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_endpoint_manager_win_installed.nbin");
  script_require_keys("installed_sw/Ivanti Endpoint Manager");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('debug.inc');

# Because we need to include some error checking and debugging, moving this to a seperate function. 
function vcf_dll(version, comparator, max_version) #'<' for dll, '<=' for main version
{
  dbg::detailed_log(lvl:2, msg:'Vcf dll check');
  if (version == '')
  {
    dbg::detailed_log(lvl:2, msg:'Empty Version In Comparison. Assuming file not found');
    return FALSE;
  }
  var check_result = vcf::compare_version_to_check(version:version, comparator:comparator, cmp_ver:max_version, strict:TRUE);
  if (empty_or_null(check_result))
  {
    dbg::detailed_log(lvl:2, msg:'Null result found for file which was detected.');
    return FALSE;
  }
  if (vcf::is_error(check_result))
  {
    dbg::detailed_log(lvl:2, msg:'VCF error recorded:' + check_result);
    return FALSE;
  }
  if (check_result)
  {
    dbg::detailed_log(lvl:2, msg:'Found Vulnerable');
    return(TRUE);
  }
  return FALSE;
  dbg::detailed_log(lvl:2, msg:'Found Not Vulnerable');
}

var app_info = vcf::ivanti_epm::get_app_info(app:'Ivanti Endpoint Manager', win_local:TRUE);
var version = app_info.version; 
var max_version = '11.0.5.361.5';
var report;
var vuln_check = FALSE;

vuln_check = vcf_dll(version:app_info.parsed_version, comparator:'<=', max_version:max_version);

if (!vuln_check)
{
  dbg::detailed_log(lvl:2, msg:'Vuln Check Output : ' + vuln_check);
  audit(AUDIT_INST_VER_NOT_VULN, 'Ivanti Endpoint Manager', version);
}

var file_ver, error, file_path, file;

get_kb_item_or_exit('SMB/Registry/Enumerated');
hotfix_check_fversion_init();
var drive = hotfix_get_systemdrive(exit_on_fail:TRUE);
var files_versions = [];

var check_files = [
drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\LANDesk.AlertManager.Business.dll",
drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\LANDesk.AlertManager.Data.dll",
drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\PatchBiz.dll",
drive + ":\Program Files\LANDesk\ManagementSuite\patchapi\bin\PatchApi.dll",
drive + ":\Program Files\LANDesk\ManagementSuite\PatchBiz.dll",
drive + ":\Program Files\LANDesk\ManagementSuite\LANDesk\mbsdkservice\bin\PatchBiz.dll",
drive + ":\Program Files\LANDesk\ManagementSuite\LANDesk\SAM\samserver\bin\PatchBiz.dll"
];

foreach file (check_files)
{
  dbg::detailed_log(lvl:2, msg:'Checking existence of ' + file);
  if(hotfix_file_exists(path:file))
  {
    file_ver = hotfix_get_fversion(path:file);
    if (empty_or_null(file_ver))
    {
      dbg::detailed_log(lvl:2, msg:'Version of ' + file + ' : null or empty');
      continue;
    }
    if (file_ver.error != HCF_OK)
    {
      dbg::detailed_log(lvl:2, msg:'Error with Version of ' + file + ' : ' + file_ver.error);
      continue;
    }
    dbg::detailed_log(lvl:2, msg:'Version of ' + file + ' : ' + file_ver.version);
    if (file=~ 'PatchBiz')
      max_version = '11.0.5.2541';
    else
      max_version = '11.0.5.2525';
    vuln_check = vcf_dll(version:vcf::parse_version(file_ver.version), comparator:'<', max_version:max_version);
    if (vuln_check)
      report = report + '\n\nVulnerable File : ' + file + '\nInstalled version :                    ' + file_ver.version + '\nFixed version :                    ' + max_version;
  }
}
hotfix_check_fversion_end();

if (!empty_or_null(report)) 
{
  report = report + '\n\nThese files should be updated per the instructions in the linked vendor advisory.\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report, sqli:TRUE);
}

audit(AUDIT_INST_VER_NOT_VULN, "Ivanti Endpoint Manager", "May 2024 Emergency DLL Hotfix");