#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108536);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2001-0222", "CVE-2001-1074");
  script_bugtraq_id(2795);

  script_name(english:"Webmin < 0.85 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Webmin install hosted on
the remote host is earlier than 0.85. It is, therefore, affected by multiple
vulnerabilities:
  
  - A privilege escalation vulnerability which may make
    authentication information available to all CGI
    programs and allows local users to gain privileges.
    (CVE-2001-1074)

  - Local users can overwrite and create arbitrary
    files via a symlink attack. (CVE-2001-0222)");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/bid/2795");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin 0.85 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-1074");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);

get_kb_item_or_exit('www/'+port+'/webmin');
version = get_kb_item_or_exit('www/webmin/'+port+'/version', exit_code:1);
source = get_kb_item_or_exit('www/webmin/'+port+'/source', exit_code:1);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = "/";
install_url = build_url(port:port, qs:dir);

fix = "0.85";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Version Source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
