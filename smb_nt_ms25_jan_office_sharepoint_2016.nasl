#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(214134);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2025-21344", "CVE-2025-21348", "CVE-2025-21393");
  script_xref(name:"MSKB", value:"5002672");
  script_xref(name:"MSFT", value:"MS25-5002672");
  script_xref(name:"IAVA", value:"2025-A-0031-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server 2016 (January 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2016 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2016 installation on the remote host is missing
security updates. It is, therefore, affected by multiple vulnerabilities:
  - Remote Code Execution Vulnerability.
    (CVE-2025-21348, CVE-2025-21344)

  - Spoofing Vulnerability.
    (CVE-2025-21393)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002672");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002672 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21348");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-21344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server:2016");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::sharepoint::get_app_info();
var kb_checks = 
[
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '5002672',
    'path'         : app_info.path,
    'version'      : '16.0.5483.1000',
    'append'       : 'webservices\\conversionservices',
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft Sharepoint Enterprise Server 2016 SP1' 
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS25-01',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
