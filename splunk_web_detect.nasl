#TRUSTED 4d3e018d7b3190acb87ef4e3d8dc4902ef28ef1f1355136b3b6a4c2e6de94b2fbcbd5f2833b46f7b64e71bc8da9d1d0f2c32f031f3b074c606b288a9ddfafbfe3c2605899368a821d9e18df67efe97f595730077f1c50eade71f23c3b519e70c8a2d47cbd3b7c52082b9c712c7c9aa1424477c1e8bfec85e12a68e0e5f9d576a6c77ef352b87c0383763e9e7bcdef3ead82742b832f2a3e1b62d7091a0a433e73022bc714c0e089369ed485b7e96fb99302fb8c0ae5d65928f06c9a5ea42ec9f637179da6db53b44e52f6578dcf8f979ca91161bffc7fd3eb9a5e75cdce6997d2a649988ad55324d35324d867adbd5fcbaf6cb65dec204b94984ec93eb8c80ab19d3c07cfcf7eec9113ff1261bbe26909c4bce6cf49eb1714812030dfce72c0eac51c79400d64df53ea742329d21eabd53cc68031a72ef04afb8c5e37fbd891b8d6cd805d81688dabe83e6055e4dd84c6e0f473c6cff7bb30b92d87f13d74b3bfc0037b72f7d0749f66e6e18dfe0df75dbf5b0cafb847441afbcebf9d567afa0c89bca016f0d5f205fa97a8de0fa5e88c3caebd9cc106e474cf08a4beb1a39817e825be21e9c73fbb5bad72e2355f87f36d23735e7bebc8c1cb3eba70af6aabf2ce0751e227d5f88e4e3de2f96bda7d14dcdfc2b1ca9af8d28ad52b1af3e1a8ac4e116c8c1262c60f48397e6095e0d8fc3f1a1fd598e41a5ad7a212aab0682d9
#TRUST-RSA-SHA256 2446cfdb5ca204cb726bcc96ff2df898ddbfbdec5672237b142ca1d8c1d7a39f95d8013e58ed5e64e6bf15a740ac3faefdb828c9ba0c17cc5fae616b358ee0ef824b9bc199f194bca759bffecbd1cb70e5de7aa9ed24619834efc37eef039202daad111b2e0fefb22c4923070e51f8bd2c33d8560541898508e557a1d989985d02ef632a9cdb0ad6a88deaf4d49d22389ec2941d9823c72bb98183c09f9236e9337c0e72c28795faa61142f7d98c5c35dc78cd3cb580c6786c781494acb579559270784cb5ffeedf366bd369a2f19bb4db7045b0465e8caa6f4f349355fee9367966d56c7b39e21541c36e15e189a064f6fe295404ef290509ab504a47e14955412c6e923aa145a4cbc8df645ffbafd51be29363fc9b987b06b653d816769d0c2cdfdcea63dfa76d311e4bb3fa47790c8b1e75cb51d597dd1ebf0d29dfe68aab560ff96b940376f160946d7c3285a4d0587f21b3e99b1a7856b6b95ca4ecc39963bfe52b4a95f04fec00a8fa57d038e6c6866fd1740b097384f2d022c7b42bff2f3e1426de6963d1088b2530068e3182dd77d64e979775a6833409c4b5db7139f60b4fbf7bff62eb4f10e51a00b89eb22ffe67d6c4ea3302877e71d4d5d932c38cd0fc6d0c5a52f9ccfa335703c0bfd7baba29b0610db66b56775da20f911196431bf9bd1fbf3eaae55c88c5105f8548168966d590e3d33fab777705cc361425

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47619);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_xref(name:"IAVT", value:"0001-T-0723");

  script_name(english:"Splunk Web Detection");
  script_set_attribute(attribute:"synopsis", value:
"An infrastructure monitoring tool is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web interface for Splunk is running on the remote host. Splunk is
a search, monitoring, and reporting tool for system administrators.

Note that HTTP Basic Authentication credentials may be required to retrieve version information
for some recent Splunk releases.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/en_us/software.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}

include("http.inc");
include("install_func.inc");
include("spad_log_func.inc");

var app = "Splunk";
var port = get_http_port(default:8000, embedded:TRUE);
var dir = '/';
var build = FALSE;
var version = UNKNOWN_VER;
var license = FALSE;
var tries, res;

# nb: the service will restart if webmirror.nasl successfully accesses
#     /services/server/control/restart so we try several times waiting
#     for it to come back up.
for (tries=5; tries>0; tries--)
{
  res = http_send_recv3(
    method         : 'GET',
    item           : dir,
    port           : port,
    add_headers    : make_array("User-Agent", "Nessus"),
    follow_redirect: 2
  );
  if (!isnull(res)) break;
  sleep(5);
}

  dbg::detailed_log(
  lvl:1,
  src:SCRIPT_NAME,
  msg:'\n\nHTTP Response ' +
      '\n\nResponse Code: ' + res[0] +
      '\n\nHeaders: ' + res[1] +
      '\n\nBody: ' + res[2] + '\n\n');

if (isnull(res)) audit(AUDIT_RESP_NOT,port,"a HTTP GET request",code:1);

if (
  ('<b>Login to Splunk</b>' >< res[2] && '<h2><b>Welcome to Splunk</b></h2' >< res[2]) ||
  (
    '<meta name="author" content="Splunk Inc."'   >< res[2] &&
    "Splunk.util.normalizeBoolean('"        >< res[2] &&
     pgrep(pattern:"Login *-", string:res[2]) &&
     pgrep(pattern:'<p class="footer">&copy; [0-9-]+ Splunk Inc. Splunk', string:res[2])
  ) ||
  # 3.x
  (
    '<title>Splunk' >< res[2] && 'layerid="splunksMenu"' >< res[2] &&
    'href="http://www.splunk.com">Splunk Inc' >< res[2]
  ) ||
  # 4.0.x
  (
    '<meta name="author" content="Splunk Inc."'   >< res[2] &&
    pgrep(pattern:'<p class="footer">&copy; [0-9-]+ Splunk Inc. Splunk', string:res[2]) &&
    'class="splButton-primary"' >< res[2]
  ) ||
  # 6.2.x-8.x
  (
    '<meta name="author" content="Splunk Inc."' >< res[2] &&
    '<script type="text/json" id="splunkd-partials">' >< res[2]
  )
)
{
  if ('"licenseType": ' >< res[2] || '"license_labels":' >< res[2] || '"product_type":' >< res[2])
  {
    if ('"licenseType": "free"' >< res[2])
      license = "Free";
    else if ('"license_labels":["Splunk Free' >< res[2])
      license = "Free";
    else if ('"licenseType": "pro"' >< res[2])
      license = "Enterprise";
    else if ('"license_labels":["Splunk Enterprise' >< res[2])
      license = "Enterprise";
    else if ('"product_type":"enterprise"' >< res[2])
      license = "Enterprise";
    else if ('"license_labels":["Splunk Light' >< res[2])
      license = "Light";
    else if ('"product_type":"lite' >< res[2])
      license = "Light";
    else if ('"license_labels":["Splunk Forwarder' >< res[2])
      license = "Forwarder";
  }

  # Check if we can get the version...
  var regex = "Login *- *Splunk ([0-9.]+) *(\(([0-9]+)\))?</title>";
  var line = pgrep(pattern:regex,string:res[2]);
  if (line)
  {
    var matches = pregmatch(pattern:regex,string:line);
    if (matches)
    {
      version = matches[1];
      if (matches[3]) build = matches[3];
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = ">&copy; [0-9-]+ Splunk Inc. Splunk ([0-9.]+) *(build ([0-9]+).)?</p>";
    line = pgrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = pregmatch(pattern:regex,string:line);
      if (matches)
      {
        version = matches[1];
        if (matches[3]) build = matches[3];
      }
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = '<div id="footer" versionNumber="([0-9.]+)" *(buildNumber="([0-9]+)")? *installType="prod"';
    line = pgrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = pregmatch(pattern:regex, string:line);
      if (matches)
      {
        version = matches[1];
        if (matches[3]) build = matches[3];
      }
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = '"build":"?([a-f0-9]+)"?,.*,"version":"([0-9.]+)"';
    line = pgrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = pregmatch(pattern:regex, string:line);
      if (matches)
      {
        version = matches[2];
        if (matches[1]) build = matches[1];
      }
    }
  }

  # >6.6.x
  if (version == UNKNOWN_VER)
  {
    regex = '"version":"([0-9.]+)"';
    line = pgrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = pregmatch(pattern:regex, string:line);
      if (matches)
      {
        version = matches[1];
      }
    }
  }

  # 8.x version can be pulled from /en-US/help
  if (version == UNKNOWN_VER)
  {
    res = http_send_recv3(
      port:port,
      method:'GET',
      item:'/en-US/help',
      follow_redirect: 0,
      exit_on_fail:FALSE
    );

    dbg::detailed_log(
    lvl:1,
    src:SCRIPT_NAME,
    msg:'\n\n8.x version can be pulled from /en-US/help' +
        '\n\nResponse Code: ' + res[0] +
        '\n\nHeaders: ' + res[1] +
        '\n\nBody: ' + res[2] + '\n\n');

    matches = pregmatch(string:res[2], pattern:'var args.*?versionNumber": "(\\d+\\.\\d+\\.\\d+).*?product": "([^"]+)"');
    if (!empty_or_null(matches))
    {
      version = matches[1];
      if(!license) license = matches[2];
    }
  }

  # Attempt to authenticate if version is still not found
  if (version == UNKNOWN_VER)
  {
    # try login to get the version
    var username = get_kb_item("http/login");
    var password = get_kb_item("http/password");

    if (!empty_or_null(username) && !empty_or_null(password))
    {

      init_cookiejar();
      res = http_send_recv3(
        port:port,
        method:'GET',
        item:'/',
        follow_redirect:2,
        exit_on_fail:FALSE
      );

      dbg::detailed_log(
      lvl:1,
      src:SCRIPT_NAME,
      msg:'\n\nProduct version not found on the home page "/". Now trying to retrieve it on a page after user authentication.' +
          '\n\nResponse Code: ' + res[0] +
          '\n\nHeaders: ' + res[1] +
          '\n\nBody: ' + res[2] + '\n\n');

      if (res[0] =~ '^HTTP/[0-9.]+ +200')
      {
        var pattern = "Set-Cookie:\s+cval=(\d+)";
        var match = pregmatch(pattern:pattern, string:res[1]);
        if (!empty_or_null(match) && !empty_or_null(match[1]))
        {
          var cval = match[1];
          var data = 'cval=' + cval + '&username=' + username + '&password=' + password + '&return_to=/en-GB/&set_has_logged_in=false';
          res = http_send_recv3(
            port:port,
            method:'POST',
            item:'/en-GB/account/login',
            data:data,
            exit_on_fail:FALSE
            );

          dbg::detailed_log(
          lvl:1,
          src:SCRIPT_NAME,
          msg:'\n\nNow performing user authentication ({"status": 0} indicates a success):' +
              '\n\nResponse Code: ' + res[0] +
              '\n\nHeaders: ' + res[1] +
              '\n\nBody: ' + res[2] + '\n\n');

          if (res[0] =~ '^HTTP/[0-9.]+ +200')
          {
            res = http_send_recv3(
              port:port,
              method:'GET',
              item:'/en-US/app/launcher/home',
              follow_redirect:3,
              exit_on_fail:FALSE
              );

            dbg::detailed_log(
            lvl:1,
            src:SCRIPT_NAME,
            msg:'\n\nUser has successfully autheticated, try to retrieve the product version from response:' +
                '\n\nResponse Code: ' + res[0] +
                '\n\nHeaders: ' + res[1] +
                '\n\nBody: ' + res[2] + '\n\n');

            pattern = '"version":[ ]+"((?:\\d\\.)+\\d)"';
            match = pregmatch(pattern:pattern, string:res[2]);
            if (!empty_or_null(match) && !empty_or_null(match[1]))
            {
              version = match[1];
              dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Product version ' + version + ' found (after user authentication).');
            }
          }
        }
      }
    }
  }

  # Check if the version was found in the Management API
  if (version == UNKNOWN_VER)
  {
    # get_single_install() exits if the app is not installed
    # Make that call conditional so we can still report for installs with UNKNOWN_VER 
    var api_mgt_port = get_kb_item('Splunk/ManagementAPI/port');
    if (!empty_or_null(api_mgt_port))
      var api_install = get_single_install(app_name:"Splunk", port:api_mgt_port, webapp:TRUE);
    if(!empty_or_null(api_install))
      version = api_install['version'];
  }

  if (version !~ "^[0-9.]+$")
    version = UNKNOWN_VER;

  # Normalize version to X.Y.Z, ie : 4.1 denotes 4.1.0
  if(version =~ "^[0-9]+\.[0-9]+$")
    version += ".0";

  var extranp = make_array("isapi", FALSE,"isweb", TRUE);
  var extra = make_array("Web interface", TRUE);
  if (license)
    extra["License"] = license;
  if (build)
    extra["Build"] = build;

  register_install(
    vendor   : "Splunk",
    product  : "Splunk",
    app_name : app,
    port     : port,
    version  : version,
    path     : dir,
    extra    : extra,
    extra_no_report : extranp,
    webapp   : TRUE,
    cpe   : "cpe:/a:splunk:splunk"
  );

  report_installs(app_name:app, port:port);
}
else
{
  audit (AUDIT_WEB_APP_NOT_INST, app, port);
}
