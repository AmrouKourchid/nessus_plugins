#TRUSTED 3f078c0bd5f3c4ef69ab6d8d01a91360eb0ab86b6f1f84b56fc16e0ee4041ab3b506de9fff2cad8be6eca398ad5d173c1e909b6e57c303dce69e78e99b314769c81581a2af3a4174b84e2a0ae7187404bc71d5d0913afc86d2fe7d0274fb851498cb7ddebf4d61b45408c2a299d6c3cbd217f1c538b035328aaa425ac722bd523b6c42851f4e505ed229fc009eb4fb25695644433be9bb277eec62ce6f679deb4761afe8fefb33e48afc27590fc550905764d37032be4204c0c91192b962b45ec2c86868f66c5bc5c2a2175da060234a68fba1829358343bf19d70afb4014f19c0517d67fbf0386d968d4d7d13d175af65c8a2cd5db8b88120a8ad2cfef609039ee2c01cfa26977b80a294bb83f713ca21ca114b0e1d58c935d1d89e0b027e33e8f06379e79bf68b13697ebd25b690bc61a9a669df7b31c94b72c011b5c27d137c93f4498b423ea45d097442c978d0f4eff98b021c62c9a7c509e2da25a476cd459df3c028743d52560da9937e07b19ee52750fc7d3282b70fae8158e44d6cbb663f558238a7d8d0bfdf4a6174d2a5bcf4c6d3b23e4e5703cbcf326d79323d828cb22c6d3a135c015b9f79e8b8d312ec5ddb5bc195a102e19ca9523cb25ae213ef4ef6ebd3fc2f4838bebbe953d641264481a32a80a4015c7909f5096b1fef266e4363aa89c88f00917ef4f69c358c6300845069eff3ab2f9f268cef29ffd6ae
#TRUST-RSA-SHA256 6e1f12e939a894c968162ec1d6ff0bdd8d6ac04ec3ecff5b81e1d0c0f75108da741cf7bc6189d10e9b36f67be4bf75fceaa3a9f89513e5e1e8f8869a00ef45212e6281eb7027ba8357c18f029fda038a5a97fd735d71816302f1557a30da89b3300c88f9ed308d88e10214c57382119aaa66c4bf060ba428d2e094eeb2dc220feb9ff800176f7b09e10324fd1da5779e770e5863e34b1b9d33c968db8328642deefdc7ba04af147b3014eb13af6773eac44a1ac2efc17f964df67e5635497692dc910b84a979c023fc70c45817eddb4e4222a92d3a902cd38c058868b2d330db833c891c6672fc403df950bc063cbdc842dea04265c02d5229befbfebd7491c1d7fdc61966737f1b5932d9c01a9fd182e6102c2baa23a6017e9bbf0bcc5fee4e4b19b7042e4c5c3e402c1efe0b9006dd7cc77001982810ccd483e89eecaaef4387bc73f552e04de1b091d52855b53882b7b533252d6020cc96f89ebc8f5674a04c7743107e2be84f1a8f27097009210b40cac219bebbfe9b5bb06aa2e49a71f7e0251f2c5b01734919449a33343cd1bef9b9df4bbb37088b425383204eabf90b5496371f5b7e43ae22458d388fcbb158d52041caf0ae854702015c5e6f173f06df37dcb36389fa4854e74428c3f8710cbdb668fd7dc09773238f3bf9d4d2cbfeab8e822e9f586202f7afe3a9ebbe30419ab2927bb178a3e9eacaac5274a10716
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69788);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Cisco Network Admission Control (NAC) Version");
  script_summary(english:"Obtains the version of the remote NAC");

  script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the NAC version of the remote Cisco device.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Cisco Network Admission Control (NAC) Manager.

It is possible to read the NAC version by connecting to the switch using
SSH.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:network_admission_control_manager_and_server_system_software");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

enable_ssh_wrappers();

##
# Saves the provided NAC version number in the KB, generates plugin output,
# and exits.
#
# @anonparam ver NAC version number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, model, source)
{
  local_var report;

  set_kb_item(name:"Host/Cisco/NAC/Version", value:ver);

  replace_kb_item(name:"Host/Cisco/NAC", value:TRUE);

  register_install(
    vendor:"Cisco",
    product:"Network Admission Control Manager & Server System Software",
    app_name:model,
    path:'/',
    version:ver,
    cpe:"cpe:/a:cisco:network_admission_control_manager_and_server_system_software"
  );

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH
# setup ssh tunnel
uname = get_kb_item_or_exit("Host/uname");
if ( "Linux" >!< uname ) exit(1, "The remote OS is not Linux-based");

sock_g = ssh_open_connection();
if (! sock_g) exit(1, "ssh_open_connection() failed.");
# issue command
nac_ssh = ssh_cmd(cmd:"cat /perfigo/build");
ssh_close_connection();

if (
  "Clean Access Manager" >< nac_ssh ||
  "Clean Access Server" >< nac_ssh ||
  "Network Admission Control" >< nac_ssh
)
{
  version = pregmatch(string:nac_ssh, pattern:"VERSION=([0-9][0-9.]+)");

  if (!isnull(version))
  {
    report_and_exit(ver:version[1], source:'SSH');
    # never reached
  }
}
exit(0, 'The Cisco NAC version is not available (the remote host may not be Cisco NAC).');
