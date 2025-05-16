#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192940);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2024-30370", "CVE-2024-36052");
  script_xref(name:"IAVA", value:"2024-A-0194-S");
  script_xref(name:"IAVA", value:"2024-A-0303-S");

  script_name(english:"WinRAR < 7.00 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed which is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WinRAR, an archive manager for Windows, whose reported version is prior to 7.00. It is,
therefore, affected by multiple vulnerabilties:

  - The vulnerability exists due to an error within the archive extraction functionality. A remote attacker can 
    use a specially crafted archive to bypass the Mark-Of-The-Web protection mechanism and potentially compromise 
    the affected system. (CVE-2024-30370)

  - RARLAB WinRAR before 7.00, on Windows, allows attackers to spoof the screen output via ANSI escape sequences, a
    different issue than CVE-2024-33899. (CVE-2024-36052)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-357/");
  script_set_attribute(attribute:"see_also", value:"https://www.rarlab.com/rarnew.htm");
  # https://sdushantha.medium.com/ansi-escape-injection-vulnerability-in-winrar-a2cbfac4b983
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64afd272");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WinRAR version 7.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30370");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-36052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rarlab:winrar");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winrar_win_installed.nbin");
  script_require_keys("installed_sw/RARLAB WinRAR", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'RARLAB WinRAR', win_local:TRUE);

var constraints = [ { 'fixed_version' : '7.0' } ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
