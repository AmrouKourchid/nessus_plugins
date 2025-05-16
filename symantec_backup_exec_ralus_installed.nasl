#TRUSTED abb1438d99e560c918b0f9ccd0001f4e3ff78d3e50ec3cc2b581437e2634598187014770d0207eec313de9efac86e1cdedc914e5873c4f997d50a0abbce648c22b5b57bcaf2945aae57785c4e20b4eb3f470de5db47a328535cb53f31d6b32b5e071764f550e1e8ce7ad5121fa624e11b3577f52727f71b4c7d2db6193a11804bf1ae198147002529d3b773a09c6832e1634351bf6e2bf7899ce43225f8f4195718dc08e3f3cc99bbbc2d1e8a915ecb44186341962aad328af22cb676b2b88e2d7ec14b58942954158b0976b700c22ae2fe561c0cfabd4752b30bf7b7acfea790e03787a99e9c9e1319434325f28f9d806920a74d9bfe8e1de727de972bf770f92df643c9899161c621c45144751a66bd3aed3b5ded1dd2fe2609c060374bb5ecae386ebe5a36a22f259d7c3e711f28debe4a5c06ee017c1151c77a1b460e244076f18cd58f01f0dbaad3fe1f979cf5c89e57c0b81d3c3386b2e0a8abc0dfbc2667d1f308456beaff5788c56a0119fa6577692c074dc2407332b6cdb5f48f286426569b384f09e152beb1b8c279b7343af005ad10bce18d17877a10c15667ad1f11b7768994f312610814350246753ec4b6190367e821cf45fbcf45aa43bdb09f85a82a46acc2bccc509903a06775ffb5ce72f89be59cf16cb68c7b469e3e46d56f8d770df93c3283e5a7721084486cf860ac4743ba7f2514dc446896ab24b91
#TRUST-RSA-SHA256 89d8251740b5563bede2c378c48905e1b4f37e7d625d56493751bcfdead97c98f40835583d2f9fc75d7a9296667c04b5779d74428c77433e3ecf24f6fc4a0ff262287948be27629fe5b24a7963c14c4783606c3b68ef21625e7e6d2a94d40f78be6be6aca78e25fd55ad399dba1ded4f72a2677979fcc43c5611376bf23aea670f42152dbc254582ef1f975eb79937cfe75cb3965c3efeed21f28e4b4b4df1116dc8c1093518e116033a3f05b6b72c3413c41fd824558f0ec1c1f347043a2ac755463f7de29b257ea667ac6b9fb90be6edf5f672dd990d8841f8d01fa5135d4968b70122a49e5c227aed73cc49faf76cc4d90534dd58e04fa2d0e591fa61ccb6fcea7322811801fafbd308277b0da80c30da566c30f60205895f9c2cdeda531ee76e8858036b68abdcd5531db54e31059d91c29e11f4befaa6e0d3537417081a508e74f9f5d3803291c228ae7258b5435d330a29be7f41d04829a6e3beddfe381b5dcebf5ccc23bb82a950ec0746ae0fb8450720b69ca01cee6480c8e37e5318a03a5f0ebe9a86125f2d8e29cf766af8968bdd78db9d41cf3f1e8f7d7bf845f172acf400ad90f1e1ec5a5bd08643904079dbf6ccd2203fea51cbe0b15d47f528798e896361c1be7c3e8762e3c75efa291b8b8bc63b7fba80f4ae252dbc9ed9be5050639368a2bf4a07f5277900ce857d20ff74b4a724df4f572b0573346409ad
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69261);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_name(english:"Symantec Backup Exec Remote Agent for Linux and UNIX Servers (RALUS) Installed");
  script_summary(english:"Gets RALUS version from beremote");

  script_set_attribute(attribute:"synopsis", value:"The remote host contains a backup agent.");
  script_set_attribute(attribute:"description", value:
"Symantec Backup Exec Remote Agent for Linux and UNIX Servers (RALUS),
a backup agent for Linux and UNIX servers, is installed on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/products/data-backup-software");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("ssh_lib.inc");
include("install_func.inc");
include('local_detection_nix.inc');

ldnix::init_plugin();

var app = 'Symantec Backup Exec RALUS';

var port = sshlib::kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

var ret = info_connect();
if (!ret) exit(1, 'ssh_open_connection() failed.');

var path = '/opt/VRTSralus/bin/beremote';
var cmd = "perl -pe 's/[^ -~]/\n/g' < " + path + ' | grep Version';
var version = info_send_cmd(cmd:cmd);

if (!version)
{
  # Older versions can be fingerprinted via agent.be
  path = '/etc/bkupexec/agent.be';
  cmd = "perl -pe 's/[^ -~]/\n/g' <" + path + ' | grep Version';
  version = info_send_cmd(cmd:cmd);
}
if (info_t == INFO_SSH)
  ssh_close_connection();
if (!version) audit(AUDIT_NOT_INST, app);

if ('VERITAS_Backup_Exec_File_Version=' >< version)
{
  version = strstr(version, 'VERITAS_Backup_Exec_File_Version=') - 'VERITAS_Backup_Exec_File_Version=';
  version = chomp(version);
}
else if ('Backup Exec -- Unix Agent' >< version)
{
  version = strstr(version, 'Backup Exec -- Unix Agent') - 'Backup Exec -- Unix Agent, Version ';
  version = chomp(version);
}
else exit(1, 'Failed to get the version number from ' + path + '.');

set_kb_item(name:"SSH/Symantec Backup Exec RALUS/Version", value:version);

register_install(
  app_name:app,
  vendor : 'Symantec',
  product : 'Veritas Backup Exec',
  path:path,
  version:version,
  cpe:"cpe:/a:symantec:veritas_backup_exec");

report_installs(app_name:app, port:port);
