#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182522);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id("CVE-2023-40047", "CVE-2023-40048", "CVE-2023-40049");
  script_xref(name:"IAVA", value:"2023-A-0514-S");

  script_name(english:"Progress WS_FTP Server < 8.8.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of WS_FTP earlier than to 8.8.2. Such versions are reportedly affected by multiple
vulnerabilities :

  - A stored cross-site scripting (XSS) vulnerability exists in WS_FTP Server's Management module. An attacker
    with administrative privileges could import a SSL certificate with malicious attributes containing
    cross-site scripting payloads.  Once the cross-site scripting payload is successfully stored,  an attacker
    could leverage this vulnerability to target WS_FTP Server admins with a specialized payload which results
    in the execution of malicious JavaScript within the context of the victims browser. (CVE-2023-40047)

  - The WS_FTP Server Manager interface was missing cross-site request forgery (CSRF) protection on a POST
    transaction corresponding to a WS_FTP Server administrative function. (CVE-2023-40048)

  - An unauthenticated user could enumerate files under the 'WebServiceHost' directory listing. (CVE-2023-40049)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://community.progress.com/s/article/WS-FTP-Server-Critical-Vulnerability-September-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67cee97f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WS_FTP Server version 8.8.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  { 'fixed_version' : '8.8.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
