#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182521);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id(
    "CVE-2022-27665",
    "CVE-2023-40044",
    "CVE-2023-40045",
    "CVE-2023-40046",
    "CVE-2023-42657"
  );
  script_xref(name:"CEA-ID", value:"CEA-2023-0049");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/26");
  script_xref(name:"IAVA", value:"2023-A-0514-S");

  script_name(english:"Progress WS_FTP Server < 8.7.4, 8.8.0 < 8.8.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of WS_FTP earlier than 8.7.4 or 8.8.0 prior to 8.8.2. Such versions are reportedly
affected by multiple vulnerabilities :

  - A pre-authenticated attacker could leverage a .NET deserialization vulnerability in the Ad Hoc Transfer
    module to execute remote commands on the underlying WS_FTP Server operating system. (CVE-2023-40044)

  - A directory traversal vulnerability was discovered.  An attacker could leverage this vulnerability to
    perform file operations (delete, rename, rmdir, mkdir) on files and folders outside of their authorized
    WS_FTP folder path.  Attackers could also escape the context of the WS_FTP Server file structure and
    perform the same level of operations (delete, rename, rmdir, mkdir) on file and folder locations on
    the underlying operating system. (CVE-2023-42657)

  - A reflected cross-site scripting (XSS) vulnerability exists in WS_FTP Server's Ad Hoc Transfer module.
    An attacker could leverage this vulnerability to target WS_FTP Server users with a specialized payload
    which results in the execution of malicious JavaScript within the context of the victims browser.
    (CVE-2023-40045)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://community.progress.com/s/article/WS-FTP-Server-Critical-Vulnerability-September-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67cee97f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WS_FTP Server version 8.7.4, 8.8.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40044");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-42657");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Progress Software WS_FTP Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:ws_ftp_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ws_ftp_server_detect.nasl");
  script_require_keys("installed_sw/Progress WS_FTP Server", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Progress WS_FTP Server', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '8.7.4' },
  { 'min_version' : '8.8.0', 'fixed_version' : '8.8.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
