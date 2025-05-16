#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207247);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2024-8191",
    "CVE-2024-8320",
    "CVE-2024-8321",
    "CVE-2024-8322",
    "CVE-2024-8441",
    "CVE-2024-29847",
    "CVE-2024-32840",
    "CVE-2024-32842",
    "CVE-2024-32843",
    "CVE-2024-32845",
    "CVE-2024-32846",
    "CVE-2024-32848",
    "CVE-2024-34779",
    "CVE-2024-34783",
    "CVE-2024-34785",
    "CVE-2024-37397"
  );
  script_xref(name:"IAVB", value:"2024-B-0133-S");

  script_name(english:"Ivanti Endpoint Manager 2024 - September 2024 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager 2024 running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager 2024 running on the remote host lacking the September 2024 Hotfix. It is, therefore, 
affected by mutliple vulnerabilities: 

  - An unspecified SQL injection in Ivanti EPM before the 2024 September update allows a remote 
    authenticated attacker with admin privileges to achieve remote code execution. (CVE-2024-32840)

  - An unspecified SQL injection in Ivanti EPM before the 2024 September update allows a remote 
    authenticated attacker with admin privileges to achieve remote code execution. (CVE-2024-32843)
  
  - An unspecified SQL injection in Ivanti EPM before the 2024 September update allows a remote 
    authenticated attacker with admin privileges to achieve remote code execution. (CVE-2024-32845)

Note that Nessus has not tested for these issues but has instead relied only on the 
service's self-reported version number of the affected dll files.");
  # https://forums.ivanti.com/s/article/Security-Advisory-EPM-September-2024-for-EPM-2024-and-EPM-2022?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14d91dc");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8191");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager_cloud_services_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_endpoint_manager_win_installed.nbin");
  script_require_keys("installed_sw/Ivanti Endpoint Manager");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

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
  drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\LANDesk.AlertManager.Business.dll",
  drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\LANDesk.AlertManager.Data.dll",
  drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\LANDesk.ManagementSuite.Data.dll",
  drive + ":\Program Files\LANDesk\ManagementSuite\Core\Core.Webservices\bin\LANDesk.Provisioning.Business.dll",
  drive + ":\Program Files\LANDesk\ManagementSuite\Core\provisioning.secure\bin\LANDesk.Provisioning.Business.dll",
  drive + ":\Program Files\LANDesk\ManagementSuite\Core\provisioningwebservice\bin\LANDesk.Provisioning.Business.dll",
  drive + ":\Program Files\LANDesk\ManagementSuite\Core\ssl\information\bin\LANDesk.Provisioning.Business.dll",
  drive + ":\Program Files\LANDesk\mbsdkservice\bin\\LANDesk.Provisioning.Business.dll",
  drive + ":\Program Files\ldlogon\provisioning\windows\LANDesk.Provisioning.Business.dll",
  drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\LANDesk.ServerInfo.Data.dll",
  drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\LANDesk.ServerInfo.UI.dll",
  drive + ":\Program Files\LANDesk\ManagementSuite\PatchBiz.dll",
  drive + ":\Inetpub\wwwroot\LANDesk\LDMS\bin\PatchBiz.dll",
  drive + ":\Program Files\LANDesk\SAM\samserver\bin\PatchBiz.dll",
  drive + ":\Program Files\WSVulnerabilityCore\bin\WSVulnerabilityCore.dll"
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
    max_version = '11.0.6.951';
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

audit(AUDIT_INST_VER_NOT_VULN, "Ivanti Endpoint Manager 2024", "September 2024 Emergency DLL Hotfix");
