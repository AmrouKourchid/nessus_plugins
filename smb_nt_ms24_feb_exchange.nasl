#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190473);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-21410");
  script_xref(name:"MSFT", value:"MS24-5035606");
  script_xref(name:"MSKB", value:"5035606");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/07");
  script_xref(name:"IAVA", value:"2024-A-0088-S");

  script_name(english:"Security Updates for Microsoft Exchange Server (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update. It is, therefore, affected by a
vulnerability as referenced in the Feb, 2024 security bulletin.

  - Microsoft Exchange Server Elevation of Privilege Vulnerability (CVE-2024-21410)

While Exchange Server 2016 is included in the advisory as an affected product, no patch has been issued for mitigation,
and no version is documented as including a fix for the vulnerability. Microsoft recommends users enable Extended
Protection for Authentication (EPA) to protect against the vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5035606 to address this issue, or enable Extended
Protection for Authentication (EPA) to be protected from the vulnerability.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21410
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18dfb6b3");
  # https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-extended-protection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e8e2d04");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21410");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server:2016");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server:2019");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin", "microsoft_iis_enum_sites.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_microsoft.inc');
include('json2.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app_info = vcf::microsoft::exchange::get_app_info();
var version = app_info['product_version'];
var epa_enum = get_kb_item("SMB/IIS/locations");
var default_site_list = ['owa','api','ecp','ews','rpc','mapi'];
var backend_site_list = ['powershell','mapi/emsmdb','pushnotifications','mapi/nspi','oab','owa','api','ecp','ews','rpc','rpcwithcert'];

function check_epa()
{
  if (epa_enum)
  {
    var i, key;
    var EPA_enabled = TRUE;
    var protected = 'Require';
    var epa_list = json_read(epa_enum);
    var ex_site = epa_list[0]['Default Web Site'];
    var ex_back = epa_list[0]['Exchange Back End'];
  
    # Check Exchange Back End values
    foreach (key in keys(ex_back))
    {
      for (i = 0; i < max_index(backend_site_list); i++)
      {
        if(ex_back[key]['component'] == backend_site_list[i])
        {
          if(ex_back[key]['ep'] != protected)
          {
            EPA_enabled = FALSE;
            dbg::detailed_log(
              lvl:1, 
              msg:'Unprotected Exchange Back End EPA configuration found:',
              msg_details:{
                'Component ':{'lvl':1, 'value': ex_back[key]['component']},
                'Value     ':{'lvl':1, 'value': ex_back[key]['ep']}
            });
            break;
          }
        }
      }
    }
    # Check Default Web Site values
    foreach (key in keys(ex_site))
    {
      for (i = 0; i < max_index(default_site_list); i++)
      {
        if(ex_site[key]['component'] == default_site_list[i])
        {
          if(ex_site[key]['ep'] != protected)
          {
            EPA_enabled = FALSE;
            dbg::detailed_log(
              lvl:1, 
              msg:'Unprotected Default Web Site EPA configuration found:',
              msg_details:{
                'Component ':{'lvl':1, 'value': ex_site[key]['component']},
                'Value     ':{'lvl':1, 'value': ex_site[key]['ep']}
            });
            break;
          }
        }
      }
    }
  }
  return EPA_enabled;
}

var protected = check_epa();

if(protected)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange Server ' +version+ ' with EPA enabled');

var constraints = [
  { 'fixed_version' : '15.2.1544.4', 'product' : '2019', 'cu' : 13, 'unsupported_cu' : 12, 'kb' : '5035606' },
  { 'fixed_version' : '15.2.1544.4', 'product' : '2019', 'cu' : 14, 'unsupported_cu' : 12, 'kb' : '5035606' },
  { 'fixed_display' : 'See vendor advisory', 'fixed_version' : '15.1.9999.9', 'product' : '2016', 'cu' : 23, 'unsupported_cu' : 22 }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  bulletin:'MS24-02',
  constraints:constraints,
  severity:SECURITY_HOLE
);
