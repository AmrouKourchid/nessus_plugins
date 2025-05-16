#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232610);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id("CVE-2025-24078", "CVE-2025-24079");
  script_xref(name:"MSKB", value:"5002662");
  script_xref(name:"MSFT", value:"MS25-5002662");
  script_xref(name:"IAVA", value:"2025-A-0171");
  script_xref(name:"IAVA", value:"2025-A-0177-S");
  script_xref(name:"IAVA", value:"2025-A-0174-S");

  script_name(english:"Security Updates for Microsoft Word Products (March 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by a security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates. They are, therefore, affected by multiple remote code
execution vulnerabilities. An attacker can exploit these to bypass authentication and execute unauthorized arbitrary
commands.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002662");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002662 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24079");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS25-03';
var kbs = make_list(
  '5002662'
);

var constraints = [
  { 'kb':'5002662', 'channel':'MSI', 'fixed_version': '16.0.5491.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Word'
);
