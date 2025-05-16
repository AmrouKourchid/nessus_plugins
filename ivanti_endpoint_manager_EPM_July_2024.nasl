#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202716);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2024-37381");
  script_xref(name:"IAVA", value:"2024-A-0420-S");

  script_name(english:"Ivanti Endpoint Manager - July 2024 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager running on the remote host is affected by a SQL injection vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager running on the remote host lacking the July 2024 Hotfix. It is, therefore, 
affected by an unspecified SQL Injection vulnerability in the Core server of Ivanti EPM 2024 flat that allows an 
authenticated attacker within the same network to execute arbitrary code.  


Note that Nessus has not tested for these issues but has instead relied only on the 
service's self-reported version number of the affected dll files.");
  # https://forums.ivanti.com/s/article/Security-Advisory-EPM-July-2024-for-EPM-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11cc45ed");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/19");

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
var max_version = '11.0.6.0';
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
drive + ":\Program Files\LANDesk\ManagementSuite\patchapi\bin\PatchApi.dll",
drive + ":\Program Files\LANDesk\ManagementSuite\LANDesk\mbsdkservice\bin\MBSDKService.dll",
drive + ":\Program Files\LANDesk\ManagementSuite\ldmain\landesk\mbsdkservice\bin\MBSDKService.dll"
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
    max_version = '11.0.6.884';
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

audit(AUDIT_INST_VER_NOT_VULN, "Ivanti Endpoint Manager", "July 2024 Emergency DLL Hotfix");
