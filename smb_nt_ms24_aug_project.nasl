#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(205611);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id("CVE-2024-38189");
  script_xref(name:"MSKB", value:"5002561");
  script_xref(name:"MSFT", value:"MS24-5002561");
  script_xref(name:"IAVA", value:"2024-A-0495");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/03");

  script_name(english:"Security Update for Microsoft Project RCE (August 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Project installed on the remote host is affected by a remote code execution vulnerability, 
that, if exploited, would allow an attacker to run commands on the host machine. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-gb/topic/description-of-the-security-update-for-project-2016-august-13-2024-kb5002561-8a993125-0341-49f9-aa20-ef56f66703bd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?331769e5");
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/download/details.aspx?id=106187");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002561");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38189");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS24-08';
var kbs = make_list(
  '5002561'
);
var severity = SECURITY_HOLE;

var constraints = [
  { 'kb':'5002561', 'fixed_version': '16.0.5461.1001', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Project'
);
