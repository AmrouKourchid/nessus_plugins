#TRUSTED 5eea36f1852c03bae42c70d4641d47dd676de4b801b0ce7102f36597980302fb5a31bf6c1114f0037fd3ea34a854ecdf9d8d971bf336cd25a88a6255a834515065b9c48a49596f6fdba7c792e794256ddbf8799aab3269b45a3e9607babdf9c22549438a9fe9a563c01689916d9ed96aaf8dd4028aa37ab29a35673b5fd980d18bb789e635d4bdcf88027dd12d271856775d0f0eaf762ae2be6ad52f138939d26300756d59651f219bb0dbfbb501258897ced62ae191049c7f62f0e00e04929db3450ba5adb96667d3238d35a933ae07a300b371512786d8aaa6a95255b769801a1a3035d1f0e1f751d8da88ef91daa24af754aafd2dc742bc7caeb667f2913a87787eea65cf65dc9a0f903020c19846c521ecd7b20ebb09c32212f02bc9d93a06e71457b4c50098a3147bce861c4e5fb6f018438a3078d57842bf8dca1c140b894e7af2eaf76468551b9c6b526e73ea9e7f6da8e0f0e90a918b6bd3227a60b193c936e51477efdf1d298882c9f9bf839d7f48fae48d64ac77237c35d265b21fbd2cd2b9984037ea9689f898991158340daede209f5686e4590402c35f7066a1d8d5f83d199287c16e9d4f49fe9072eeade2361b4f8a7c9c93a545995c472a9c2e509b08b15a9f777ba22264483994b6dd90e138f0d4e2585c325a028b211ff5a1f48ddc05fbd0598b79075d69d093e6e901a8ba16068424fdb36b07e433fb6f
#TRUST-RSA-SHA256 44c584650b3bdb1acf2e3ddba8c6e9cbba2ff5c0a4284b6dae04d63bc70a1f3b611c4e25d63147d1cf126a80f303bbfee922f9eaab705c551e67510c01ce6c6e6b3427861f7bf21460b23b069ceeca9455e56c477264e97bd0a15a272c4eec0cb7ae4e6232d2e474a92dd2f1c7a78b886a8142b0ee444da3b7229c04e3b5be364efbe534d84f8643fa7c3de5550264a62d99b87f24a0509ed70e6d20dac7185e7e97036cc70d4f07d2ea4a046418bf983e7b598bb46bcb4aa4dad50f1a8836c302769297d82ddc0a0cb89066bd466b664ae1e89abcdfd3c6fe8151a5d48de406171a0489ba6eee045ae22ee1aa51a8497aeea8ec9c4a8f7f03af66aa1f651607ad3bd5f0216e3684a11db59124ea8a448cd5d016837be2ba823c19e60a973de078f4f47dda1ba0ed6f93f8a38822b23e09648a5c9f528aed46c022c7a4ca29551529e676dfe8cc46498952df264b82ed2f6f5d9494efa7b2b0ebbe82e8b07ed0b6917a26b6b978295be1fdf822ed12ebfb2a6cc74efc0b75c81bf99ad7eb89356c981c0ee1d6d0ce8353c5d73babd4491cc29968873c3be68593457c4be6a524f923b89b71e126403df422d3283c1a1b01ba253d1cfc6f0cff28d9742129ae7c73105fbfcb1d2c2187b345e9efd4908a0bcaa22afb262840625c8add20aea412d5501817860d1cd346ceb77adde64a89468034031e23332dca993e379ea71b53
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56299);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Linux /proc/cpuinfo");
  script_summary(english:"Read /proc/cpuinfo");

  script_set_attribute(attribute:"synopsis", value:
"The processor's type and features can be read.");
  script_set_attribute(attribute:"description", value:
"/proc/cpuinfo could be read.  This file provides information on the
processor's type and features on Linux systems.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
  script_require_keys('HostLevelChecks/proto');
  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


enable_ssh_wrappers();

if (!get_kb_item('HostLevelChecks/proto')) exit(0, "Local checks are not enabled for the remote host.");

uname = get_kb_item("Host/uname");
if ("Linux" >!< uname) exit(0, 'The remote host is not running Linux.');

# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(1, "ssh_open_connection() failed.");
 info_t = INFO_SSH;
}

cmd = 'LC_ALL=C cat /proc/cpuinfo';
buf = info_send_cmd(cmd: cmd);
if (info_t == INFO_SSH) ssh_close_connection();

if (egrep(string:buf, pattern:'^processor[ \t]*:'))
{
  set_kb_item(name:'Host/proc/cpuinfo', value: buf);
  m = eregmatch(string: buf, pattern:'\nmodel name[ \t]*:[ \t]*(.*[^ \t])[ \t]*\n');
  if (! isnull(m))
    set_kb_item(name:'Host/proc/cpu_model_name', value: m[1]);
  exit(0);
}
else exit(1, "/proc/cpuinfo could not be read.");
