#TRUSTED a0b7a8d5828f916827eaf61ada102055a719079f57baff90d9b07a208b2bb26e17c9c6fb7d853c784b85c091de621d71d6f2f348f484204adad1415c57134f23c75772d8bcb51b15e7bb38d1ec75ed6bc7f207501a68a913a8a52dc7990f63537afc63efd6d6e9deff52f39b004b7316d4264b7443f963ff103112b584f5a0cf943c767910aba57a64e87627255c4ffc08c78308bbaff7dad5875b911196a46c4d90379761298bda89436579f03aaaecf1707781394263b44d4a9440348be5ac786ba4ce943c40a8de03d1ecd89e5ee00c7ea749ff729e393886a103a550c62a2a878d3cdccfc321e2459f98eb1534c367a134c0e5d917c147fdc48346b393e2342a3a6c271377806c5cdae40de7299c503b95ddc541a85a138aa391cd2a6b4f14ed25765144eaf60453ca19f46317b447111b28b8cefba842752f377614cec6643d52a7befe75d064209fdcadd533edf0288817ae883acf91e50ace79cacc07255dd7ede522fe7b422c68748e39db81e9f7b91764e79bf09f2703d4a67ec50f55f0f34fc0288facdfad7dc7ecd540b37ff2937e906e928122576eb870ea89138fc52e1700189d372a3d4cf7fa3c543447d783bef38443e7d71505da225d4d96fe3e4f197cd45fb0b7ce75c31e24a7bec0e21355cbb1f3ec8b345a887fceb2c24ee48c7815b3d9913f2c92f8d3671646836bc6aa6c3fb0d2cfaa9848c6dee911
#TRUST-RSA-SHA256 76d30701c532d42ef57da02047ef97f263f4a0a33607a0f347d0cdaac3328565a4d6599fd4ab0cfcad3e38d0576f1c7e4ef5db997d5e27f632be731aded9347850594bab965a13d2faef4227517995a2faf7cf367b9467adc5fb39f905e5be4ab0d2ed6fd89731a4e97d1f9ac5e814713bf7c53a597a3864f736015ab350ce09419746953c4aacddbfa1ae0d8337aff57e7d310a695573ed640f3dffa3e02475af12c926644f040519bb373e22caa28aea8b0ebb8d90079220a6227ac21e09742cef7b10231dd008bdc928c684021a63ee31ccfad3d66b9358b6fb3b29495e82a605aa4241f72c3d8126e6ad65aeeff3734eeef5dd5e33bfdbcd5e2b95b1a88331e28ffde8554dee7aa7e99cfa402f056801f873d68ed1335464fe36ff9112f37f08ca6b87161b8081f221847f71c1fdd8e2fd29c428f2680639e1ea01d593e76ce65e413e2e1c78917dd6c243ef8d2d70850f241d14b0042aeabf39380155316fb2b71a8ddbcebb779a2bf7f692fb147d3c3a603d2665dbb769a48db9cb80cd58a7af3b0f11181e5e6a675a0643de3e0d391e43f492b5b3cc8881789ad55021feb70b3a4641b230c1bc9408accd70242674e4fed9b3f124e682176c2ca55a91857ff958cfe0c4ac7b6c959e878978fac5c0cf8faab1bcf3df4cfc5eb17c81863ad7ba715a2f7b0720c1f98235de83e15e0f92141c807718722682a0cf1166af
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105255);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"ESET NOD32 Antivirus for Linux Installed");
  script_summary(english:"Gets ESET NOD32 Antivirus version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an antivirus installed.");
  script_set_attribute(attribute:"description", value:
"ESET NOD32 Antivirus for Linux is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.eset.com/us/home/antivirus-linux/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:eset:nod32_linux");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("telnet_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if ("Linux" >!< get_kb_item_or_exit("Host/uname")) audit(AUDIT_OS_NOT, "Linux");

app = "ESET NOD32 Antivirus for Linux";
version = UNKNOWN_VER;
virus_sig_ver = UNKNOWN_VER;

enable_ssh_wrappers();

info_connect(exit_on_fail:TRUE);

# first get the program version
exe_path = '/opt/eset/esets/sbin/esets_scan';
cmd = "perl -pe 's/[^ -~]/\n/g' < " + exe_path + " | grep 'ESET Command-line scanner, version %s' -A2 | tail -1";
output = info_send_cmd(cmd:cmd);

if (empty_or_null(output))
{
  #Effectively nop on localhost (agent), so no need to check if ssh is used
  ssh_close_connection();
  audit(AUDIT_NOT_INST, app);
}

if (output =~ "^[0-9]+\.[0-9]+\.[0-9]+$")
{
  matches = pregmatch(pattern:"^([0-9]+\.[0-9]+\.[0-9]+)$", string:output);
  if (!isnull(matches) && !isnull(matches[1]))
    version = matches[1];
}
else
{
  ssh_close_connection();
  exit(1, 'Failed to get the version number from ' + exe_path + '.');
}

# then get the antivirus definition version
path = '/var/opt/eset/esets/lib/data/updfiles/nodA409.nup';
cmd = "perl -pe 's/[^ -~]/\n/g' < " + path + " | grep 'versionid='";
output = info_send_cmd(cmd:cmd);
ssh_close_connection();

if (output =~ "^versionid=[0-9]+$")
{
  matches = pregmatch(pattern:"^versionid=([0-9]+)$", string:output);
  if (!isnull(matches) && !isnull(matches[1]))
    virus_sig_ver = matches[1];
}

register_install(
  vendor:"ESET",
  product:"NOD32 Linux",
  app_name:app,
  path:exe_path,
  version:version,
  extra:make_array("Virus signature database", virus_sig_ver),
  cpe:"x-cpe:/a:eset:nod32_linux");

report_installs(app_name:app);
