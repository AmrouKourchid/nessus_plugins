#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(190471);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2024-21364");
  script_xref(name:"MSKB", value:"5034599");
  script_xref(name:"MSFT", value:"MS24-5034599");
  script_xref(name:"IAVA", value:"2024-A-0102-S");

  script_name(english:"Security Updates for Microsoft Azure Site Recovery (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Azure Site Recovery installation on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Azure Site Recovery installation on the remote host is missing
a security update. It is, therefore, affected by an elevation of privilege 
vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/topic/update-rollup-70-for-azure-site-recovery-kb5034599-e94901f6-7624-4bb4-8d43-12483d2e1d50
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31e5a78a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Update rollup 70 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21364");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_site_recovery_vmware_to_azure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_site_recovery_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft Azure Site Recovery", "SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_name = "Microsoft Azure Site Recovery";
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  {'min_version': '9.0', 'fixed_version': '9.57.6920.1'}
];

vcf::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_HOLE
);
