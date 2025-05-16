#TRUSTED 7323b7b96b31012b395b85ed44f755199251eb00fff7e4197714cac2ea388b4bae7e6fcede8f2563831cf8be92f7d706cd51383c17f20b3a36623a116d7de6e1e70f0113fc01f533033ca0a693343d9eac8df178e45f470122ac74b8b1d043195a9d4e9100cb2ac641eccc46d0091b302c1b3ac1d51893749e64501b40e45b7e5d7937528b99fbcf868dfcae8b332d7fed1f9f0df7ca48824aefb4aa863d1aaa38c5c5b291eac93a5c302c4fd5889e82f6f34fbf62fb15c9bd7428b043ab361002a2ee944d37c293aeee36405301b07e3b0d35312f29e6bb9cfbd3c851166eda4ddc16fb3904ba17ed7a877b659d7b92d5f62f00c722c0acfd01af192c74ca21a0bc672d5d706e4ee52d3e98327cc9ec6e4316044d3ceb9a06bc8309ee7d1cb3a7be0b97866057cc73e9d10cbefe05d3e22b8b5960d7dc5797a4f4ea8a7551d499b787b552faa6742a107dfb8133e7575b159bfdb267f767b84b86971e062de34e3d0d8a5af26ef69de50738fd2b17cef3bbc039946c579a252bf0f7b74fe297a5ccbeee6622d02989542aa4d53b497339260c3809c16f3a3ae70bd2a732ee077cf53a0f82e98f0c54ff442c044c23276dae7ece4525283666652f42774db95470ce7b87470b156164a54276cf30ee42163869da96fc2c8c7c3fec014f41a29147a930e211142f7100634e7688cb6543583f5d59f25e3bdd52b8f4108b02d6e1
#TRUST-RSA-SHA256 6dbf477714642701e4fac8b5469d7c78699122642199d95dbb371aae4bb2d2d8bdfd60129b423300e2c5ebad58b26d276e9932d78c3eeb16d5fdd4ac088ecf9cd54c8baed88facbc524d81785bd261ea452c1bc567df17d63672b3252893af186962502844ed66eb0f8de42a6eabba0bb7495dd07e937a4f09381f8cdb7b079f2d576916382c526295fa2bf1def5603c4e3706c2ba6a990b5e35da0a9a7d92114249509a3d5e3e77b12a0b15152ed0e2e09e810abbe3a67662d1869a78dd2fb4ead4c443cd480d9d4c6c0abd8f81e7965fcd750e105b4155ee09b8aecd7c525ae31ad9a6d15d95b341654f3c43b463ce87285a3266c444d57423d2111256698576aae9f1cd426ea1114ad8fb83ae54a37915beb682ec064c936824e8917bd7d3256c7c449124210998e3ea433fb2e7feb4549b50d281efb41a0ffe37f5e5513deb1c22a8e8c276f26a68f7520a7cffdc1ea8fafeedd3671b880183a5f938df939359f48d77e46b8f3149537488d8635b06644af9d065dbf9722a9190de14b9e79abae6ee306c4408d1df98a2b09757baa617249911c9bcbee973ba091669c0f2e3a909aa3467f87f64edefff78de280ef22226741a2b4d7aba8d24b45d91d9a2b6821c63d0feb765f0184ea484b9f4b2f5e6f01949b82594c06efbe2ae86639a7f7591632687554b949f733e71c5a3a464ab33e44f66e536b9210976b19e56fb
##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(69446);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"ArcSight Logger Installed (Linux)");

  script_set_attribute(attribute:"synopsis", value:
"ArcSight Logger is installed on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"ArcSight Logger is installed on the remote host. ArcSight Logger is used to collect and manage logs.");
  # http://www8.hp.com/ca/en/software-solutions/software.html?compURI=1314386#.Ug5u237YUzk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84aa80ae");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_logger");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include('install_func.inc');
include('local_detection_nix.inc');
include('debug.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");
enable_ssh_wrappers();

var app = 'ArcSight Logger';
var cpe = 'cpe:/a:hp:arcsight_logger';

var ver_ui_map = make_array(
  '5.3.1.0',      '5.3 SP1', # Less detail from install-log files
  '5.3.1.6838.0', '5.3 SP1'  # More detail from log files
);

var logger_path = '/opt/current/arcsight/';
var version = UNKNOWN_VER;
var installed = FALSE;

# Use only default install location files for now
var files_and_patterns = make_array(
  logger_path + 'logger/logs/logger_server.out.log', '"\\[INFO \\] Version "',
  logger_path + 'logger/logs/logger_server.log*',     '"\\[INFO \\]\\[Server\\]\\[go\\]\\[main\\] Version "',
  logger_path + 'logger/logs/logger_processor.log*',  '"\\[INFO \\]\\[LoggerProcessors\\]\\[go\\]\\[main\\] Version "',
  logger_path + 'logger/logs/logger_receiver.log*',   '"\\[INFO \\]\\[LoggerReceivers\\]\\[go\\]\\[main\\] Version "'
);

var cmd = 'test -d ' + logger_path + ' && echo OK';
var output = ldnix::run_cmd_template_wrapper(template:cmd);
dbg::log(src:SCRIPT_NAME, msg:'Sending cmd: ' + cmd + '\nResponse: ' + obj_rep(output));
if ('OK' >!< output)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_NOT_INST, app);
}

# Look into each potential data file on the target
var temp_version, res, matches;

# first check the installvariables.properties
cmd = 'grep -h -e "PRODUCT_NAME=" -e "PRODUCT_VERSION_NUMBER=" /opt/UninstallerData/installvariables.properties';
output = ldnix::run_cmd_template_wrapper(template:cmd);
dbg::log(src:SCRIPT_NAME, msg:'Sending cmd: ' + cmd + '\nResponse: ' + obj_rep(output));
matches = pregmatch(string:output, pattern:"PRODUCT_NAME=ArcSight Logger\s.*PRODUCT_VERSION_NUMBER=([0-9.]+)", multiline:TRUE);
if (matches)
{
  version = matches[1];
  installed = TRUE;
}
else
{
  # Check log files 
  foreach var ver_file (keys(files_and_patterns))
  {
    temp_version = '';
    # logger_server.out.log uses a text-based day-of-week and thus, skip sorting date
    # The other files use a fully number-based date and thus, look at them all and sort on date
    if ('.out.' >< ver_file)
      cmd = 'grep -h ' + files_and_patterns[ver_file]  + ' ' + ver_file + ' | tail -n 1';
    else
      cmd = 'grep -h ' + files_and_patterns[ver_file]  + ' ' + ver_file + ' | sort | tail -n 1';
    output = ldnix::run_cmd_template_wrapper(template:cmd);
    dbg::log(src:SCRIPT_NAME, msg:'Sending cmd: ' + cmd + '\nResponse: ' + obj_rep(output));
    res = egrep(string:output, pattern:str_replace(string:files_and_patterns[ver_file], find:'"', replace:''));
    if (empty_or_null(res)) continue;
    installed = TRUE;

    res = chomp(res);
    matches = pregmatch(string:res, pattern:' Version ([0-9.]+)');
    if (!isnull(matches)) temp_version = matches[1];

    # Keep most detailed version number
    if (max_index(split(temp_version, sep:'.')) > max_index(split(version, sep:'.'))) version = temp_version;
  }
}

if(info_t == INFO_SSH) ssh_close_connection();

if (installed)
{
  set_kb_item(name:'hp/arcsight_logger/path', value:logger_path);
  set_kb_item(name:'hp/arcsight_logger/ver', value:version);

  # If we have user-friendly version string, store it
  if (!isnull(ver_ui_map[version])) set_kb_item(name:'hp/arcsight_logger/display_ver', value:display_version);
  else display_version = version;

  register_install(
    app_name:app,
    vendor : 'HP',
    product : 'ArcSight Logger',
    path:logger_path,
    version:version,
    display_version:display_version,
    cpe:cpe)
  ;

  report_installs(app_name:app);
  exit(0);
}
audit(AUDIT_NOT_INST, app);
