#TRUSTED 47bcd6843708055f2f1bd761c294a834fe5259f508304ca573131251fc052879a59348316891a741b5af4f5182f343f1425e615ac72f735986e4ae7c08f9c865a4ad9598aa189dfd03beba9fd2215dc6f9394a95736fcc5574eb7adf38bb7fb495cb0aae584fa429dc3bc5d53c9c7634622a8a960e70d720bd42b2bba4f45ff108e3ab49e2468ca71559703328a9e94de93f6bc9d227a7418ee6bed14cbc3e7407a9682102bf28bc50ccfa4356102f74f06be22de16c39a3a34c6b33bce3bdc693dfae3b8295593da488ec69ea2add262dba082f6fb0ce9faac2f62d9fafc485b278f91c430975c2320b128b484bc0a1238e421e4ff47033c936c04e97c1940d134ed4d1f98342c7207fd6589fdaa6ef4842d4e532ce50c95573e8bbd4b02b416f68778004ccb3b5de75f2dcb7399c6960ce84a40477b83462366477ca6753fd20787382881cdf8a7ca521e0b7bb5b8d141e59c5db7aae7014bbe38ee811cd4dc52f2c02c5fa4c002370d358e32c2ad55c7541be070d51328f774f6007ff98f18f4fd6a9fc21d7c67563f25ef0e593c9fec5cbfe3f7cfc18fbb577c8e28a8a225a48da987d749ae41331d28f855ebd0a092f353f7b8201d33368eeaa5f7bcb6641f2fa2e81919e13641f9c13fb043fcb09072f0766b6e102b70abe4000f07fc8b3c0a23750f356ac5452fb5bfdd64585b97fbcb7bea2e7eaafd1c769e9dcc917
#TRUST-RSA-SHA256 a2cc413c9fe53ad79f98f62ba7cb02f39924ba266a0ec42c5b3cf19f2d0e2376397cd706f740f6d5869bd4b12dc6e28c16330dc08cfac68997f1c6f6f89d3a3ff47203665bfd3c2cc599db54319f4ed9b6cd7538239c122356264af3dc01345a2d110efea5fcfdccbf541e85cf9db0a56ca0e0fa592001def4a9fe658a64eb1bb1d91e15ea8dd24f66a6b7b9b83e503045674b2499781c640f90c3cbab3710836d194b4bd282fa6039ece24ad443fbbdf43d8b46db71e12b718d7afd039ab2a95d32d217ff173e92ce9d79498d96acb9c90a6dfcb60627a2e26c0d0175b43eb06632d979f75a6c748306f0994dbeabc3b5247a7ba43bebf23f94ef5eb59a0e7981c318aabfbb4f7e63afc3399792ed1b9babf8a3e193a7bc077d0bc3c64e91d0abf929310f7d9f5eed316839ca2c76b972e2d0c8a508f5da05150b6a9f65fdd0ca5dff23edd0e90ca71975063b2932e7365e04643d758da22cc4d8d6a676c02f24f156a2b08f4054d1840ebeb1c26201c71a249983086705a0eec883645c0f5546817f684cf2a01cad6280ab59a0ad8e2590d573b95545fc994c7531de4c96e236ee472df79f3f1d5536063faa4dbe5e866f1097b8e032088e1f836a4324ae2d7d0cfa79eb798ef470d6666e4c80765f2d4337b87289267595df32c99da52ed9ae0d5aa79a0e1a04c00ddbb31a39a46fa497a7e6d7d68e16785f7b9a8a118ac4
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179139);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_name(english:"Package Manager Packages Report (nix)");

  script_set_attribute(attribute:"synopsis", value:"Reports details about packages installed via package managers.");
  script_set_attribute(attribute:"description", value:"Reports details about packages installed via package managers");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/01");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("unix_enum_sw.nasl", "set_source_package_mapping.nasl");
  script_require_ports("Host/uname");

  exit(0);
}

include('linux_kb_parse_func.inc');
include('inventory_agent.inc');
include('structured_data.inc');
include('debug.inc');
include('package_manager_utils.inc');


get_kb_item_or_exit('Host/local_checks_enabled');
var uname_kb = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname_kb)
{
  audit(AUDIT_OS_NOT, "Linux");
}

var distro = get_distro();

dbg::detailed_log(lvl:2, msg:'Determined Linux distribution to be ' + distro + '.');

if(isnull(distro))
{
  exit(1, 'Unable to determine Linux distribution.');
}

var package_data = package_manager_utils::get_package_data(get_source_mapping:TRUE);
if(isnull(package_data) || empty_or_null(package_data['packages']))
{
  exit(1, 'Unable to determine installed packages.');
}

dbg::detailed_log(lvl:2, msg:'Retrieved package data.');
dbg::detailed_log(lvl:4, msg:'Package data:\n' + serialize(package_data));

var installed_sw_packages = new structured_data_installed_sw();
inventory_agent::populate_install_sw_packages(distro: distro, installed_sw_packages:installed_sw_packages, package_data:package_data);
installed_sw_packages.report_internal();

dbg::detailed_log(lvl:2, msg:'Saved installed software packages tag data.');
dbg::detailed_log(lvl:4, msg:'Tag data:\n' + installed_sw_packages.json_serialize());

security_report_v4(port:0, extra:'Successfully retrieved and stored package data.', severity:SECURITY_NOTE);
