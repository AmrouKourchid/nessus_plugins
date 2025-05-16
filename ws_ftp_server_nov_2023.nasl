#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189824);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/31");

  script_cve_id("CVE-2023-42659");

  script_name(english:"Progress WS_FTP Server < 8.7.6, 8.8.x < 8.8.4 Arbitrary File Upload");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of WS_FTP earlier than 8.7.6 or 8.8.x prior to 8.8.4. It is, therefore, affected
by an arbitrary file upload vulnerability in the Ad Hoc Transfer Mode module. An authenticated Ad Hoc Transfer user
has the ability to craft an API call which allows them to upload a file to a specified location on the underlying
operating system hosting the WS_FTP Server application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://community.progress.com/s/article/WS-FTP-Server-Service-Pack-November-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d64049e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WS_FTP Server version 8.7.6, 8.8.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42659");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:ws_ftp_server");
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
  { 'min_version' : '0.0', 'fixed_version' : '8.7.6' },
  { 'min_version' : '8.8.0', 'fixed_version' : '8.8.4' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
