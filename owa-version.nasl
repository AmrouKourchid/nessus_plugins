#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(14255);
 script_version("1.25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/03");
 
 script_name(english:"Microsoft Outlook Web Access (OWA) Version Detection");
script_summary(english:"Outlook Web Access version check.");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to extract the version of Microsoft Exchange Server
installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"Microsoft Exchange Server with Outlook Web Access (OWA) embeds the 
Exchange version number inside the default HTML web page. By
requesting the default HTML page, Nessus was able to extract the
Microsoft Exchange server version." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/11");
 
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook_web_access");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_family(english:"CGI abuses");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

include('http.inc');
include('install_func.inc');

var exchange_vers = make_array();
# Exchange 2007
exchange_vers['8']['product'] = '2007';
exchange_vers['8']['sp'] = make_array(0, '8.0.685', 1, '8.1.240', 2, '8.2.176', 3, '8.3.83');

# Exchange 2010
exchange_vers['14']['product'] = '2010';
exchange_vers['14']['sp'] = make_array(0, '14.0.639', 1, '14.1.218', 2, '14.2.247', 3, '14.3.123');

# Exchange 2013
exchange_vers['15']['product'] = '2013';
exchange_vers['15']['sp'] = make_array(0, '15.0.516', 1, '15.0.620', 2, '15.0.712', 3, '15.0.775', 4, '15.0.847', 5, '15.0.913', 6, '15.0.995',
  7, '15.0.1044', 8, '15.0.1076', 9, '15.0.1104', 10, '15.0.1130', 11, '15.0.1156', 12, '15.0.1178', 13, '15.0.1210', 14, '15.0.1236', 15, '15.0.1263', 16, '15.0.1293', 
  17, '15.0.1320', 18, '15.0.1347', 19, '15.0.1365', 20, '15.0.1367', 21, '15.0.1395', 22, '15.0.1473', 23, '15.0.1497');

# Exchange 2016
exchange_vers['16']['product'] = '2016';
exchange_vers['16']['sp'] = make_array(0, '15.1.225', 1, '15.1.396', 2, '15.1.466', 3, '15.1.544', 4, '15.1.669', 5, '15.1.845', 6, '15.1.1034',
  7, '15.1.1261', 8, '15.1.1415', 9, '15.1.1466', 10, '15.1.1531', 11, '15.1.1591', 12, '15.1.1713', 13, '15.1.1779', 14, '15.1.1847', 15, '15.1.1913', 16, '15.1.1979', 
  17, '15.1.2044', 18, '15.1.2106', 19, '15.1.2176', 20, '15.1.2242', 21, '15.1.2308', 22, '15.1.2375', 23, '15.1.2507');

# Exchange 2019  
exchange_vers['19']['product'] = '2019';
exchange_vers['19']['sp'] = make_array(0, '15.2.221', 1, '15.2.330', 2, '15.2.397', 3, '15.2.464', 4, '15.2.529', 5, '15.2.595', 6, '15.2.659',
  7, '15.2.721', 8, '15.2.792', 9, '15.2.858', 10, '15.2.922', 11, '15.2.986', 12, '15.2.1118', 13, '15.2.1258', 14, '15.2.1544');

# This section is for old versions of Exchange
# so, default Microsoft Exchange with OWA embeds version number inside HTML comments like:
# size=2><BR>Microsoft Exchange Server </FONT><FONT color=black size=2>Version 5.5 
#      SP4<BR><!-- 2653.23 -->Microsoft (R) Outlook (TM) Web Access <snip>
#
# go out on google and you'll see that most sites keep at least one of sigs[]
# or text[] 

var sigs = make_array();
sigs['5.0'] = make_array('product', '5.0', 'version', '5.0.1457.0', 'sp', 0);
sigs['5.0 SP1'] = make_array('product', '5.0', 'version', '5.0.1458.0', 'sp', 1);
sigs['5.0 SP2'] = make_array('product', '5.0', 'version', '5.0.1460.13', 'sp', 2);
sigs['5.5'] = make_array('product', '5.5', 'version', '5.5.1960.4', 'sp', 0);
sigs['5.5 SP1'] = make_array('product', '5.5', 'version', '5.5.2232.5', 'sp', 1);
sigs['5.5 SP2'] = make_array('product', '5.5', 'version', '5.5.2448.4', 'sp', 2);
sigs['5.5 SP3'] = make_array('product', '5.5', 'version', '5.5.2650.24', 'sp', 3);
sigs['5.5 SP4'] = make_array('product', '5.5', 'version', '5.5.2653.23', 'sp', 4);
sigs['5.5 SP5'] = make_array('product', '5.5', 'version', '5.5.2658.10', 'sp', 5);
sigs['6.0'] = make_array('product', '2000', 'version', '6.0.4417.0', 'sp', 0);
sigs['6.0 SP1'] = make_array('product', '2000', 'version', '6.0.4712.0', 'sp', 1);
sigs['6.0 SP2'] = make_array('product', '2000', 'version', '6.0.5762.0', 'sp', 2);
sigs['6.0 SP3'] = make_array('product', '2000', 'version', '6.0.6249.0', 'sp', 3);
sigs['6.5'] = make_array('product', '2003', 'version', '6.5.6944.0', 'sp', 0);
sigs['6.5 SP1'] = make_array('product', '2003', 'version', '6.5.7226.0', 'sp', 1);
sigs['6.5 SP2'] = make_array('product', '2003', 'version', '6.5.7683.0', 'sp', 2);

var port = get_http_port(default:80);

if ( ! can_host_asp(port:port) ) exit(0, 'The web server on port '+port+' does not support ASP');

var owaversion, match, release, url, res, r, w, sig, sp;
url = '/owa/auth/logon.aspx';
res = http_send_recv3(method:'GET', port:port, item:url, exit_on_fail:TRUE);
dbg::detailed_log(lvl:2, msg:'Response:\n' +  obj_rep(res));

if ('X-OWA-Version' >< res[1])
{
  owaversion = strstr(res[1], 'X-OWA-Version: ') - 'X-OWA-Version: ';
  owaversion = owaversion - strstr(owaversion, '\n');
}
else
{
  # In case the X-OWA-Version header is missing
  if ("OwaPage = " >< res[2] &&
     ("<title>Outlook Web App" >< res[2] ||
      "<title>Outlook</title>" >< res[2] ||
      "<title>Microsoft Exchange - Outlook Web Access</title>" >< res[2]))
  {
    match = pregmatch(pattern:'<link (?:rel="shortcut icon"|type="text/css" rel="stylesheet") href="/owa/(?:auth/)?((?:[0-9]+\\.){2,3}[0-9]+)/', string:res[2]);
    if (!empty_or_null(match))
    {
      owaversion = match[1];
    }
  }
}

if (!empty_or_null(owaversion))
{
  owaversion = chomp(owaversion);
  # Save disp_ver to report the full version in plugin output
  var disp_ver = owaversion;
  release = split(owaversion, sep:'.', keep:FALSE);
  # Mapping a CU to a version only requires the first three segments
  owaversion = release[0] + '.' + release[1] + '.' + release[2];
  var ver_bit = release[0] + '.' + release[1];
  # Build number of 2013, 2016, and 2019 all start with 15.x, so correlate release ver based on the first two segments
  if(ver_bit == '15.0')
    release = '15';
  else if(ver_bit == '15.1')
    release = '16';
  else if(ver_bit == '15.2')
    release = '19';
  else release = release[0]; 

  if (!empty_or_null(exchange_vers[release]))
  {
    var i, update_str;
    sp = 0;
    for (i=0; i < max_index(keys(exchange_vers[release]['sp'])); i++)
    {
      if (ver_compare(ver:owaversion, fix:exchange_vers[release]['sp'][i]) >= 0) sp = i;
      else break;
    }
    if (sp)
    {
      product = exchange_vers[release]['product'];
      if (int(release) >= 15) update_str = 'CU';
      else update_str = 'SP';
    }
  }
}
else
{
  url = '/exchange/logon.asp';

  w = http_send_recv3(method:'GET', port: port, item: url, follow_redirect: 1, exit_on_fail:TRUE);
  if (w[0] !~ "^HTTP/1\.[01] (200|403)") exit(0, 'The host returned an unexpected response header.');
  r = w[0] + w[1] + '\r\n' + w[2];

  # permutations that I thought of
  # 200 OK -> sigmatch
  # 302 redirect -> 200 OK -> sigmatch
  # 403 Req SSL -> 200 OK -> sigmatch
  # 302 redirect -> 403 Req SSL -> 200 OK -> sigmatch

  if (w[0] =~ "HTTP/1\.[0-9] 403 Access Forbidden") exit(0, 'Unable to access ' + build_url(port:port, qs:url) + '.');
  # MA 2009-12-11: The old code force the test on port 443. I trashed that part.
  # 443 will be tested if the user scanned it.
 
  if ( (('L_strMailboxPlease_Message' >< r) || ('Outlook (TM) Web Access' >< r)) && 'for Microsoft (R) Exchange Server' >< r )
  {
    # Narrow down the text
    var chunk;
    chunk = strstr(r, 'for Microsoft (R) Exchange Server') - 'for Microsoft (R) Exchange Server';
    chunk = chunk - strstr(chunk, 'Microsoft (R) Outlook (TM) Web Access');

    # Now extract the version number
    sig = strstr(chunk, 'Version ') - 'Version ';
    sig = sig - strstr(sig, '<');

    if (!empty_or_null(sigs[sig]))
    {
      product = sigs[sig]['product'];
      owaversion = sigs[sig]['version'];
      update_str = 'SP';
      sp = sigs[sig]['sp'];
    }
  }
}
if (owaversion)
{
  var product, extra, extra_no_report;
  extra = make_array();
  extra_no_report = make_array();
  if (!empty_or_null(product))
    extra_no_report['RELEASE'] = product;
  if (sp != 0 && !empty_or_null(update_str))
    extra[update_str] = sp;

  register_install(
    vendor:"Microsoft",
    product:"Outlook Web Access",
    app_name:'Outlook Web Access', 
    path:url, 
    version:disp_ver,
    extra:extra,
    extra_no_report:extra_no_report,
    port:port,
    cpe:'cpe:/a:microsoft:outlook_web_access',
    webapp:TRUE
  );

  if (get_kb_item("Settings/PCI_DSS") && get_port_transport(port) == ENCAPS_IP)
  {
    var pci_report = 'Outlook Web Access version ' + owaversion + ' at URL ' + url + ' is not using an encrypted transport.';
    set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
  }

  report_installs(app_name:'Outlook Web Access', port:port);
}
else audit(AUDIT_NOT_DETECT, 'Outlook Web Access', port);
