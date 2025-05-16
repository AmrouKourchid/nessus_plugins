#TRUSTED 0dcc81e7efbdf9472a95c40901a42d046cac1d552244639976194ad9adb3c1583b65078b4f131d7a95ddaf93c3783277970543dd7d08517a172e014939eed749fc2cdbc7fd1fb64cc8a5365bfab46a49322063d27c5baec523e5a6cd9ce0fbe398fa57096f0f0cf9d3c64606eb20f1d9a4b26f9e2377c732320ea29709076537d70abf77233c2cc7407f89a706d22abfc742424a73fd2fdfe3a49a2f20b87d5a125d2b5dbb6da0a62a81e9f45880149b220e4bfd513c768849fb005e0730022a281f619eddf1fdd1be7ecdb17c017783db6635844c32585882811d11c7ca1b9c20442603619315067b21dd8cdc05ec7ab0b30c949d9809d51356fd27b8db90a9f288ba82f9338031fc297d6344c1fb4407a13686265100368b175ab589f74d011e16bd23ca913a322a4f8daa71874eb647510d9efb20a4465b8da5fef76c02b36921b88c39c483e2dc3104d98fcb2e1dff38cc02b845bb98589b87d5041aa724e33e28a8bc961eaf07484d719eba3dae3d56c79cc356e620373cda1d2f8ab89f728c0dc0c4fdd6e125d10eebdf85e2a102458ff07a3c434bd70e0244cc2e754eb94d9bf5437733e9c1130a3cb4cd629351b71373e2ecd7fb1390ea35eb3e95b1350cedf4f3a665fb3da9c3b2ea0350a3617873c6ab4c8789d39189a36ce3108b58e8f6375ca25d307ca4ee3470c4e65d2739f82a9f7b3634c7dd1afc1ba76bdd
#TRUST-RSA-SHA256 587ec4193090f221dba28e79858f33f50e7631e8b121b83b4ff2fbdd5a8177e0f8effe241d8cf75e5f13396f57ad141ae65cda8f244b9aea6438e661296d3cccd80aed23d96e7da7b857255a3363ceba890e401a3835dee0a7b9a53095fe9f81337faea47475a4c6aa0ad6006070a6b8e9b08461de9c8f0a1b07c0ece9995814e06bf332079ec80640e0659c1a99b934ae9dd708b846786ce225735416abc8aaa3f78165931127265d9004f28c35eabed105d7f6c241a479ca892659d6a62771758af6f4506a3b9309f0d3f3022fb77252cc9b50d11da20f5ab649f6d0c8b75705b91a6b98fc2d87d2dd3ff2014a66c50efdac085d4a0be3a9c3bf25c00be33fce9d9d2d9e6c60143cc6871043912329c9fdb8e6043733fe8e3bc1e3bd97a1950b87d55cd9d4630cf862c52625e20cc758acda2ed420a494c85b2bbc0ee15e2cbbc63473109264489dfd27439015fbed6998e0433693ec90f861d1aa95a16fd213b1f2040d8b2f2dfb8746d96e6d7639d4310e2a2e13f7fb540b0daab75b0e8f1ff4de9b728b8b42ef406c67147b61b4ebb9bcb3ea952f532820fdb4b44648ce8399f9e96be17165c3a6f8b2ccffb939678ba654dfd17ac8905bb3997262298a0f4f00dce34347f978ad9411b82ff851fdd8a911af9e4953bafa31cd2222035e36e0fbb61b949ec0cd2326c2c782e2bd3330efe56a0d3a611995fc6456707d1b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69922);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Cisco Firewall Services Module (FWSM) Version");
  script_summary(english:"Obtains the version of the remote FWSM");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the FWSM version of the remote Cisco
device.");
  script_set_attribute(attribute:"description", value:
"The remote host has a Cisco Firewall Services Module (FWSM). 

It is possible to read the FWSM version by connecting to the switch
using SSH.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");


enable_ssh_wrappers();

##
# Saves the provided FWSM version number in the KB, generates plugin output,
# and exits.
#
# @anonparam ver FWSM version number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, source)
{
  local_var report;

  set_kb_item(name:"Host/Cisco/FWSM/Version", value:ver);

  replace_kb_item(name:"Host/Cisco/FWSM", value:TRUE);

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

# verify that the target system is a cisco IOS
get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Require local checks be enabled
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Try to extract the FWSM version from the "show module" command
sock_g = ssh_open_connection();
if (!sock_g) exit(1, "Failed to open an SSH connection.");
fwsm_ssh1 = ssh_cmd(cmd:"show module", nosudo:TRUE, nosh:TRUE, cisco:TRUE);
ssh_close_connection();

if (!isnull(fwsm_ssh1) && "Firewall Module" >< fwsm_ssh1)
{
  # 4    6    Firewall Module                        WS-SVC-FWM-1      SAxxxxxxxxx
  module = eregmatch(string:fwsm_ssh1, pattern:"(\d+)\s+\d+\s*Firewall Module");

  if (!isnull(module))
  {
    # now execute the "show module #" command where # is the FWSM module number
    sock_g = ssh_open_connection();
    if (!sock_g) exit(1, "Failed to open an SSH connection.");
    fwsm_ssh2 = ssh_cmd(cmd:"show module " + module[1], nosudo:TRUE, nosh:TRUE, cisco:TRUE);
    ssh_close_connection();

    if (!isnull(fwsm_ssh2) && "Firewall Module" >< fwsm_ssh2)
    {
      # Mod MAC addresses                     Hw     Fw           Sw           Status
      # --- --------------------------------- ------ ------------ ------------ -------
      # 4   0003.e4xx.xxxx to 0003.e4xx.xxxx  3.0    7.2(1)       3.2(3)       Ok
      version = eregmatch(string:fwsm_ssh2, pattern:"[\r\n][^\r\n]+\s+([0-9][0-9\.\(\)]+)\s+Ok");

      if (!isnull(version))
      {
        report_and_exit(ver:version[1], source:'SSH');
        # never reached
      }
    }
  }
}

exit(0, 'The Cisco FWSM version is not available (the remote host may not be Cisco FWSM).');
