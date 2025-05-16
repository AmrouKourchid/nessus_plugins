#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(234220);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

   script_cve_id("CVE-2025-29803");
   script_xref(name:"IAVA", value:"2025-B-0053");
   
  script_name(english:"Security Updates for SQL Server Management Studio (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The SQL Server Management Studio installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The SQL Server Management Studio installation on the remote
host is missing a security update. It is, therefore,
affected by the following vulnerability:

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2025-29803)
");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released  to address this issue.");
  script_set_attribute(attribute:"see_also", value:"https://learn.microsoft.com/en-us/ssms/release-notes-ssms");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server_management_studio");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_ssms_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft SSMS");
  script_require_ports(139, 445);

  exit(0);
}

include("vdf.inc");

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [{'scope': 'target'}],
  'checks': [
    {
      'product':{'name': 'Microsoft SSMS', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {
          'min_version': '20.0',
          'fixed_version': '20.2.37.0',
          'fixed_display':'20.2.37.0 (20.2.1)'
        }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);