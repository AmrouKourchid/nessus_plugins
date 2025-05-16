#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206677);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id("CVE-2024-7744", "CVE-2024-7745");
  script_xref(name:"IAVA", value:"2024-A-0533");

  script_name(english:"Progress WS_FTP Server < 8.8.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of WS_FTP earlier than 8.8.8. It is, therefore, 
affected by multiple vulnerabilities: 

  - In WS_FTP Server versions before 8.8.8 (2022.0.8), a 
    Missing Critical Step in Multi-Factor Authentication of 
    the Web Transfer Module allows users to skip the 
    second-factor verification and log in with username 
    and password only.

  - a path traversal vulnerability in the Web Transfer Module 
    allows a attacker with certain user privilages to craft an 
    API call to that allows them to download a file from an 
    arbitrary folder host's root folder is located

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://community.progress.com/s/article/WS-FTP-Server-Service-Pack-August-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f37ef442");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WS_FTP Server version 8.8.8 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:ws_ftp_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ws_ftp_server_detect.nasl");
  script_require_keys("installed_sw/Progress WS_FTP Server", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Progress WS_FTP Server', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '8.8.8' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
