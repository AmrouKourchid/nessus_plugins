#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81575);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2014-9508");
  script_bugtraq_id(71646);

  script_name(english:"TYPO3 Anchor-only Links Remote Spoofing Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a URL spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The TYPO3 content management system running on the remote host is
affected by a URL spoofing vulnerability involving anchor-only links
on the homepage. A remote attacker, using a specially crafted request,
can modify links so they point to arbitrary domains. Furthermore, an
attacker can utilize this vulnerability to poison the cache in order
to temporarily alter the links on the index page until cache
expiration.");
  # https://typo3.org/security/advisory/typo3-core-sa-2014-003/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be948b13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a patched version or set the 'config.absRefPrefix'
configuration option to a non-empty value.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9508");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "TYPO3";

# the url spoof will only work against the root URL
# therefore, we only want to test once per port
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

exploit_url = "/http://www.example.com/?no_cache=1";
res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : exploit_url,
  exit_on_fail : TRUE);

# look for successfully spoofed anchor links
item = eregmatch(pattern: "<a\s*href\s*=\s*(" +
  "'http://www\.example\.com/\?no_cache=1#[^']*'|" +
  '"http://www\\.example\\.com/\\?no_cache=1#[^"]*"' +
  ")\s*>", string:res[2]);

# double check we are indeed looking at a TYPO3 install
# and that the exploit was successful
if("powered by TYPO3" >< res[2] &&
   !isnull(item))
{
  security_report_v4(
    port        : port,
    generic    : TRUE,
    severity    : SECURITY_WARNING,
    request     : make_list(build_url(qs:exploit_url, port:port)),
    output      : '\n' + item[0]
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:'/'));
