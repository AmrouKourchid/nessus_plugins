#TRUSTED 9ebb04f764a6a9f2b190f1709024a5af0dcf1bb7ae5417eeb939a170a70423cc9fcfe4810c023d83c6614166375bd4b0e66d247d8ee1d361e9a98f395ebfde2d5a707a640b9e3c7c9d00f792319056ffafac347dcdad26a47e080de1e9e840e3bd695b169364392dbef416ec6ac1c19afcd8b9de042053fd5f2bd00dd6d22d44472f1065b511d2d4912aa44eda198bbff11e9240172470fa13a9259233ac794b30900cefebd7a9bf817117ba32abc8efb25952d07d9ede086b59bde6442c89da581e0402e6bd8fb09c32d9b4b04ab6925da482a9d53be7a0f0769d6392aaf8936bc2a68c57389f08f15358c40bf4d15d88965a98204ab9c9949c6bda1cf00df3a0664602217d6c1f128f7d34d7c73472e958e58c06a5933a799b25db314528b826cae5d6c72301a0f094d5b7af55d9659f1a870e8a69dd0e96ba2c7e2e79dd34bdb49ba34d5711a073299a0173fc3e8f986d2e57a46e4200b67b4254b753377da399beaf5aecb35d6f0d13c1dfb9479ba17c47af0750a8e94d55077a9ad6ff35779fe84ee313ad83da5dc56b763764d9b0c22bdca98f949366fd5585eee1c601ab04331c850cd07ab75699087f2696f915888beaa1cf1e5d98b2c165864a66934855d8ddafa9c26e16bc5d5e9e98c2e6da6d1ccdb179101124b99c1944c4d21b00e6c9a234c1a24a8e255d50c293bb4e748f4755e27c625f9bab533893908df2
#TRUST-RSA-SHA256 3262b3c7d0af6b8fbfb202de813b92b1c2cbbd746645ecea037590f9ee07f4350a3a46931edc4a3940693d3581abee83db4c20fdaa194b8ebe92ec5d88654888f51fa4bbeb963e9b64ab86f22f0fc992a1cabbf5c7bc61d7b5973697c2a00d7c3cc641e27224e1a29a39623db68fabda99de24a8aa23a982ca571079ddbb5be00c8452ba3f4200c4c8b604bf4bceee2adf1eb77bacb9f7ec86d869ce5cdea67cefd9baf80a5a97b2763f20bbc8cbf38c6a5386a0b75a97ce8170aee738a4abb07a5ea3d4eb25e0c73b039f6e47b7033e3844113807c5b6acf3dfe058948ab33477ba24f984626f15e1e058f11f216e313382ccf25b51ed14b8b52371f24ede830480d824d1dd74fd2aabaf8a93fa1c36ad3d8eab73ad09cfcdbc6c94d6bb108a7e1be537b9fe5f083494bea71413be74f7b4efc8fdb90e7e021b59aea21c11ae29cf5e52d00737515e98f1412a64d83233d331ad5c4d8e8c350048bdc357fb193e8ec07a43d54ca9a084f556a51f1689e50fdb2f80b0444684a235277c7189244a2965c6ccc760501de89b1a3c3f912c340c8f6eb20095c4d686a1efbd8c17a22f5733823228b2131626077a0e2e389335fed95cd6dc74fe8dded0deab81d8ad6cebd7727242f1ec1ae1b9e970d54f1723765322e49ecc0b46ba78ad6c3298c966807d4ebb242ff67efeef6f55385b9d3b5c7ddefdd60a94f5e17318d175a53e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17367);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/18");

  script_name(english:"Fortinet FortiGate Web Console Management Detection");
  script_summary(english:"Checks for the Fortinet Fortigate management console.");

  script_set_attribute(attribute:"synopsis", value:
  "A firewall management console is running on the remote host.");
  script_set_attribute(attribute:"description", value:
  "A Fortinet FortiGate Firewall is running on the remote host, and
  connections are allowed to its web-based console management port.

  Letting attackers know that you are using this software will help them
  to focus their attack or will make them change their strategy. In
  addition to this, an attacker may set up a brute-force attack against
  the remote interface.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortinet.com/products/fortigate/");
  script_set_attribute(attribute:"solution", value:
  "Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('webapp_func.inc');
include('gunzip.inc');
include('json2.inc');

# replace_kb_item(name:'global_settings/enable_plugin_debugging', value:1);
# replace_kb_item(name:'global_settings/debug_level', value:2);
function serial_to_model(serial)
{
  var s = substr(serial, 0, 5);
  var models = keys(serial_to_model);
  if (contains_element(var:models, value:s));
    return serial_to_model[s];

  return NULL;
}


# https://www.forticloud.com/help/supportedmodels.html
# only populated with models used by our customers in the past two years (as of Dec 2022) as seen in Snowflake
var serial_to_model = {
  'FGT60E': 'FortiGate-60E',
  'FG310B': 'FortiGate-310B',
  'FG800D': 'FortiGate-800D',
  'FG800C': 'FortiGate-800C',
  'FGT61E': 'FortiGate-61E',
  'FG6H1E': 'FortiGate-601E',
  'FGT6HD': 'FortiGate-600D',
  'FG100D': 'FortiGate-100D',
  'FG200F': 'FortiGate-200F',
  'FG201E': 'FortiGate-201E',
  'FG5H1E': 'FortiGate-501E',
  'FOSVM1': 'FortiOS-VM64'
};

var port = get_http_port(default:443, embedded:TRUE);

var app_name = 'FortiOS Web Interface';
var install_found = FALSE;
var version = NULL;
var cpe = 'cpe:/o:fortinet:fortios';
var image_hash, headers, data, extra, s, m, k, d;

# Legacy check first.
var url = '/system/console?version=1.5';
var pattern = 'Fortigate Console Access';

var res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:FALSE
  );

dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 1st request: ' + obj_rep(res));

if ('200' >< res[0] && preg(string:res[2], pattern:pattern, multiline:TRUE, icase:TRUE))
  install_found = TRUE;

# FortiOS 3.x check next.
if (!install_found)
{
  url = '/images/login_top.gif';
  image_hash = 'f328d4514fe000a673f473e318e862fb';

  res = http_send_recv3(
    method:'GET',
    item:url,
    port:port,
    exit_on_fail:FALSE
    );
  dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 2nd request: ' + obj_rep(res));

  if ('200' >< res[0] && hexstr(MD5(res[2])) == image_hash)
  {
    install_found = TRUE;
    version = '3.0 or earlier';
  }
}

# FortiOS 4.x, 5.x check next.
if (!install_found)
{
  url = '/images/logon_merge.gif';
  image_hash = '3955ddaf1229f63f94f4a20781b3ade4';

  res = http_send_recv3(
    method:'GET',
    item:url,
    port:port,
    exit_on_fail:FALSE
    );
  dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 3rd request: ' + obj_rep(res));

  if ('200' >< res[0] && hexstr(MD5(res[2])) == image_hash)
  {
    install_found = TRUE;
    version = '4.0 or 5.0';
  }
}

# FortiOS 5.x and up
if (!install_found)
{
  url = '/login';
  pattern = '<f-icon class="ftnt-fortinet-grid ';

  res = http_send_recv3(
    method:'GET',
    item:url,
    port:port,
    exit_on_fail:FALSE
  );
  dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 4th request: ' + obj_rep(res));

  if ('200' >< res[0] && preg(string:res[2], pattern:pattern, multiline:TRUE, icase:TRUE))
   {
      install_found = TRUE;
      version = '>= 5.4';
   }
   else
   {
      url = '/431cb5237001e73e794398e4fa3cf660/css/main-green.css';
      pattern = 'fortigate-marketing-';
      headers = {
        'Accept-Encoding': 'gzip, deflate, br'
      };

      res = http_send_recv3(
        method:'GET',
        item:url,
        port:port,
        add_headers:headers,
        exit_on_fail:false
      );

      dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 5th request: ' + obj_rep(res));

      if ('200' >< res[0] && preg(string:gunzip(res[2]), pattern:pattern, multiline:TRUE, icase:TRUE))
      {
        install_found = TRUE;
        version = '>= 6.0';
      }
   }
}

# It's found on some 7.x devices (not verified on < 7.x) that when requesting a non-existent file under the root path
# below response is returned from the device
# curl -k -v https://fortigate.fortidemo.com/robots.txt
# {"status":404,"httpStatus":"error","serial":"FGT2KE3917900165","version":"v7.2.2","build":1255,"api_version":""}
url = '/robots.txt';
res = http_send_recv3(
  method: 'GET',
  item: url,
  port: port,
  fetch404: true,
  exit_on_fail: false
);

dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 6th request: ' + obj_rep(res));

if ('404 Not Found' >< res[0] && 'content-type: application/json' >< tolower(res[1]))
{
  data = json_read(chomp(res[2]));
  d = data[0];
  if (typeof(d) != 'array')
  {
    dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Error occurred while parsing data as JSON: '+obj_rep(d));
  }
  else
  {
    k = keys(d);
    if (
      contains_element(var:k, value:'status') &&
      contains_element(var:k, value:'httpStatus') &&
      contains_element(var:k, value:'serial') &&
      contains_element(var:k, value:'version') &&
      contains_element(var:k, value:'build') &&
      contains_element(var:k, value:'api_version')
    )
    {
      dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Data received: ' + obj_rep(d));
      s = d['serial'];
      m = serial_to_model(serial:s);
      if (m) extra = {'Model': m};
      version = d['version'];
      # remove leading 'v' in 'v7.2.2'
      version = substr(version, 1);
      install_found = true;
    }
  }
}


# Add install to KB and report.
if (install_found)
{
  var installs = add_install(installs:installs, dir:'/', appname:'fortios_ui', ver:version, port:port, cpe:cpe, extra:extra);
  set_kb_item(name:'www/fortios', value:TRUE);

  # Setting fingerprinting KB items to report the OS as being FortiOS
  replace_kb_item(name: 'Host/OS/HTML', value: 'FortiOS on Fortinet FortiGate');
  replace_kb_item(name: 'Host/OS/HTML/Confidence', value: 100);
  replace_kb_item(name: 'Host/OS/HTML/Type', value: 'firewall');
}
else
{
  audit(AUDIT_WEB_APP_NOT_INST, app_name, port);
}

if (report_verbosity > 0)
{
  var report = get_install_report(port:port, installs:installs, item:'/', display_name:app_name);
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
else
{
  security_report_v4(port:port, severity:SECURITY_NOTE);
}
