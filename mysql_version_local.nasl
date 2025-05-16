#TRUSTED a1cfbedadf1be423facbc89f7df53d5625e8b6c951bb0791c6ef3b2d6e45154deafaf0193399f904b2c70a02b467c29965a79b6bcff457b4bf65f6ab5a1ba6f4e14936595797fc6b9d2fdb3b3295cc9fca0f84f9fc1bd29fdc0b090a5266b0b2ab3e42c7f29644f1faf2151d71ea9641ad376157c8d5186719daf6d86e3ef3eafbaa8d323b95a13d365f5ef1b782716a5b2618cc07317fdb35938057077d82911ec0164208b47b138d282788eb1377625875a26e26935b5ab039f00e382af5b071d6b7b92eb92843d1061e4eba53ffc165c648bc9f178d8de0e3a8591316cdd4b2c6e0f5a229af4d5e93d976441e4f63c118c141b1cdda166dfb7ddb800b2df4e16818f77aaae70bb7d9a5d283d568e1c83704a79775d8311126d986c0406611ad2b0e371099ae79ffb78dee34d43fc65f75a8692f03ce146df48c29654fbaa5ecf6706d545f1330430aa62a648c86fa649a208a3b65b87db687b0abaa67d79237ee010d23e70592fecc7daac8556efc60255fd4722602b10d280a1430deb73e2a68dedda36ec7aba812fcc7753e4fbe30f5e90130865a17370fc13d6350664639dd027fa84f3e7633468ea8866dc1fe14a5e4bcf0d13ef902abaaf17e91682daa3e653a1d30025315865f81424191a7761f5f0039f380495e13b9dffd48b79751657438d58c3c51b003e3978a4e2d0baaaa32e4edb6eb1ea4d3f1ee17fbac2a
#TRUST-RSA-SHA256 96c4ec4fdb373b4f09ca9c5e64a9377bf0989cb4fde9125d6809205521e777b441534e4e3c8bff435bce7b4647c418b120754236c3b9a0f5ddfc7e813f86be03e29ddf8f717ab59192b2191a45c56cd8b777a96b30b67e386d0e523dd6b36fbe8feb704619e279f94ce65e889fbe3f9a8dd7a01a290789db973cd4afee459a33240990660b35b32e6e81a2168533a07854a97ed88f6655c172ea403f0cbe2c298734d4f2741aee8ec7d7f0f02bd2cfdc1e973eb967c01df93f6fb747be4e483a607a5dc1875f48e45b308c60d5944f2a1ecf33346ed22e2482b8f13226929efbf0e43ee374d43fcf6ee68d33afa837c2e54a2e752580138693e5b6e07e8323726539d4df09dc59e1bd91b50c3ed8d789091858d504937ba972d500b9386de11418020f620b845219bb4268bd848f515164d5bc7f41394725ee4a6971c8713fa14948ca84e05a1d7e3ab8ff919d542c6e1d8ab0a1fdcbd9b41efc9e7d77539c866c8df5f886a82c0ebbf688359396da2eacc7f9d7542795cebec9a71e847c8ce94bea69564518b6675d8a4c417408e0e664d57904ee4125cd9929ed46dfbc9b4ef2ec9cfe4571840c6dd5a158ec3c1b5d91dd49d7f1b6bcd839f389c50e092cd1cde8c463af49bfb2af1ca01c766dbe8f7078a8e1d269ea60087c7f0c079cc74f1ce9daf3b3c7ea0c5daf4e475803967d8abf57de36b811c4ab2bc554bd79a337
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129468);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_name(english:"MySQL Server Installed (Linux)");
  script_summary(english:"Checks for MySQL Server on Linux");

  script_set_attribute(attribute:"synopsis", value:
"MySQL Server is installed on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"MySQL Server is installed on the remote Linux host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Host/RedHat/release", "Host/CentOS/release", "Host/Debian/release", "Host/Ubuntu/release", "Host/RockyLinux/release");

  exit(0);
}

include('install_func.inc');
include('local_detection_nix.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

ldnix::init_plugin();
info_connect(exit_on_fail:TRUE);

var release, packages, keys, os, regex;
var rpm = FALSE;
var cpe='cpe:/a:mysql:mysql';
var timeout, depth=10, res, path, buf;
var exclude_dirs = ['/bin', '/boot', '/dev', '/etc', '/lib', '/media', '/mnt', '/proc', '/run',
    '/sbin', '/srv', '/sys', '/tmp'];

# Determine OS and installed packages
packages= get_kb_list("Host/*/rpm-list");
keys = keys(packages);
if(!isnull(keys))
   packages = packages[keys[0]];

if(!isnull(packages))
{
  #see link for package names, looking for Database server and related tools
  #https://dev.mysql.com/doc/refman/8.0/en/linux-installation-rpm.html
  regex = "^(mysql(-community|-commercial|)-server-([0-9\\.]+-?[0-9])[^\|]+).*$";
  rpm = TRUE;
}
else
{
  # Get package list
  packages = get_kb_list("Host/*/dpkg-l");
  keys = keys(packages);
  if(!isnull(keys))
    packages = packages[keys[0]];


  if (empty_or_null(packages))
    audit(AUDIT_PACKAGE_LIST_MISSING);

  regex = "^ii +(mysql-server-core-[0-9\\.]+ +([0-9\\.]+-[0-9][\+]?[a-z]+[0-9\\.].*? ).*)$";
  rpm = FALSE;
}

# Determine if MySql Server is installed and attempt to get version
var app = 'MySQL Server';

var matches = pgrep(pattern:regex, string:packages);
if (empty_or_null(matches)) dbg::detailed_log(lvl:1, msg:'MySQL Server does not seem to be installed via System Package Manager.');

foreach var package (split(matches, sep:'\n'))
{
  matches = pregmatch(pattern:regex, string:package);
  if (empty_or_null(matches)) continue;

  var extra = {};
  extra["Package"] = matches[1];

  var version = UNKNOWN_VER;
  if(!rpm)
  {
    if (!empty_or_null(matches[2]))
      version = matches[2];
  }
  else #for rpm, there is distinction between commercial and community so the version is in the 3rd block
  {
    if (!empty_or_null(matches[3]))
      version = matches[3];
  }
  # All detections for this block will be via pkg mgr
  var extra_no_report = make_array( 'Detection', 'Local', 'Managed by OS', 'True', 'Managed', '1');

  register_install(
    app_name : app,
    vendor : 'MySQL',
    product : 'MySQL',
    path     : '/usr/sbin/mysqld',
    version  : version,
    extra_no_report:extra_no_report,
    cpe      : cpe
  );
}

###
# Search MySQL Server instances distributed via self-contained tarball
###

if (thorough_tests)
{
  timeout = 1800;
  depth = 99;
}

# the config file for package installed mysql-server is /etc/my.cnf
var mysql_config_files = ldnix::find_executable(paths:'/', bin:'mysql_config', timeout:timeout, depth:depth, excluded:exclude_dirs);
if (isnull(res)) dbg::detailed_log(lvl:1, msg:'No MySQL Server found on this server.');

# check the existence of some other files to ensure it's a complete install instead of just a file
var pattern = "version='([0-9.]+)'";
var match;
foreach var mysql_config_file (mysql_config_files)
{
  path = mysql_config_file - 'mysql_config';
  if ( ldnix::file_exists(file:path+'mysqld') &&
      ldnix::file_exists(file:path+'mysql') &&
      ldnix::file_exists(file:path+'mysqlcheck')
  )
  {
    buf = ldnix::run_cmd_template_wrapper(template:strcat('grep -E "', pattern, '" $1$'), args:[mysql_config_file]);
    if (empty_or_null(buf))
    {
      version = UNKNOWN_VER;
    }
    else
    {
      match = pregmatch(string:buf, pattern:pattern);
      if(match)
        version = match[1];
    }

    register_install(
      app_name : app,
      vendor  : 'MySQL',
      product : 'MySQL',
      path    : path,
      version : version,
      extra_no_report:make_array( 'Detection', 'Local'),
      cpe      : cpe
    );
  }
}
if (info_t == INFO_SSH) ssh_close_connection();
get_install_count(app_name:app, exit_if_zero:true);

report_installs(app_name:app);
