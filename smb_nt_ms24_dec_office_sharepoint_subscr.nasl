#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(212241);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id(
    "CVE-2024-49070",
    "CVE-2024-49064",
    "CVE-2024-49068",
    "CVE-2024-49062"
  );
  script_xref(name:"MSKB", value:"5002658");
  script_xref(name:"MSFT", value:"MS24-5002658");
  script_xref(name:"IAVA", value:"2024-A-0809-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server Subscription Edition (December 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server Subscription Edition installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server Subscription Edition installation on the remote host is missing
security updates. It is, therefore, affected by a privilage elevation vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002658");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002658 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server:subscription");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product'      : 'Subscription Edition',
    'edition'      : 'Server',
    'kb'           : '5002658',
    'path'         : app_info.path,
    'version'      : '16.0.17928.20290',
    'append'       : 'webservices\\conversionservices',
    'file'         : 'pptconversion.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server Subscription Edition'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS24-12',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
