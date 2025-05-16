#TRUSTED 4fe113bb550bb850e0986898bdcc8074e99774509a7906f7c5d1c7257dfce88dc8dd20ddeb84430c887532c97a6046bd637e5241a5ec9f45e9b64a9b86a922c760d6e6d0a62f9dd847de83cfb4c03b908cec75daf65c83eed1eb815974c48239dfa9f0027b062425c4f703c744561ebc14c1488767153ff78550a473b40c04998a6c1e717d1ff0c61249dab3b78cf2a92eaa422e4b1ae402a7896c913453a849588691cdb37f436f7644a415d1de65708fe8345536af85edbfb2bf0ad7240013f197307c3686633a2ea4ad5b4a6a38ceda773630a080508645b7523fc7171c87a3ddcdc536744768d6542f8b1e1b1cffd3caacd3138fb227f2dbe103ec7bb8d32dbc44069591bfdedf75eae6af6d42fd31d0082a7b5b7de63952b1b290411afcacc400721a3a0c1e6c2ae329a65f7552e787910e394c7759540db0a4d3ecc7cde8cd9175c0ea24f72b787b536a55db7b06c5b8c2e1eb52ec3a9bb753deda88a519bceabe582a37878b26c67c584ccecdad6eef878f604a9082ad905a52beac76214975eafbe80647db2b57329c1644f21ac5b377a13c8ee90752159be7d3aec8d4e7e7083a7943cbaaac61ad6da2ed1d07c47e214dc1feec36e2155f8b8b263765b45decbfbffcb2b81d5a1da0c4d09ccbc466025f6164040589a0164171f614c75a9718ad1a17c2f77a64050a083d93659a91812815a4f4ee53192bb91299ee
#TRUST-RSA-SHA256 3c1099ef2e08ad9a2c4e74fdece7c4bae0500d4be80a16ebd742becbbe85187703451dcdb96e90346dca0976375c172a1d26555c675f0c7d187fa19860ff7ce5acfec04a3836f4a50daa52cd3153427afe86f84de79aeddfcb096a777ea91cb1ccd82fd74bd5521c699e8242986407d071efa7d524c710e10782b664f24dbcedf6add8cba6f844ad67aa08fd9a3b34659b38ca2323106bf9d5ab4d54852a71961ef6f387555ef1ba5f064ee8bca7763f342c39e5e163eed4d755de6e34e25200d568d7e4ec817808d7a396a627aeaa7b3f0aa7c2abdbb46b88892631481e46b763e8d856c9f6906f5385cbfa4c6c4ea8b9f4e55d28e6cc84cae13afc0273791a726450168f27fab00c57066ca521a015e7c4402866995d9f2385375442c13cb71c67e83b62e3cd9455f4d2f74112e015dcc995b808c4718445cb7f569e0b97861af3b1f009c6ecc001e1b328ff186236d41e249b08396e6c0c2b3fd9a403efb04ca79d5936600241ae945e3765ea051225d61c182c2ec60989b29e4aad53d8ddea5a810ec362bc84744a1a6d27b08ff3d380d903acbf4aa58029b92747f134dd1e09de374e6f787180a93844712106eecd593aae36321a471433e4d86801e3e39c7b7137cb6920efc2ac9b443b7d7f9cd6e548411522b0759bfb32d5ee174310929df7b93ec70eb542add85655d84bcc3c4e2e9cdbcd3a93bc3c4f843959f1e9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(152684);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_name(english:"SSH Cisco Wireless LAN Controller (WLC) Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is a Cisco Wireless LAN Controller (WLC).");
  script_set_attribute(attribute:"description", value:
"The remote device is a Cisco Wireless LAN Controller (WLC).");
  # https://www.cisco.com/c/en/us/products/wireless/wireless-lan-controller/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2102cd2");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCve45024");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_rate_limiting.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('ssh_lib.inc');

var app_name = 'Cisco WLC';
if(islocalhost()) info_t = INFO_LOCAL;
else info_t = INFO_SSH;

enable_ssh_wrappers();

# check if none_auth Cisco WLC via ssh banner
var port22 = sshlib::kb_ssh_transport();
if ( port22 && get_port_state(port22) )
{
 _ssh_socket = open_sock_tcp(port22);
 if ( _ssh_socket )
 {
   ssh_banner = ssh_exchange_identification();
   ssh_close_connection();

   if ('-CISCO_WLC' >!< ssh_banner) audit(AUDIT_NOT_DETECT, app_name);
   set_kb_item(name:'Host/' + port22 + '/Cisco_WLC_banner/', value:ssh_banner);
   set_kb_item(name:'Host/Cisco/WLC/none_auth', value:TRUE);
 }
}

# try loggin in using the none_auth via sshlib::try_ssh_kb_settings()
var session = new('sshlib::session');
var channel = TRUE;
var login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:TRUE, rate_limit:FALSE, new_channel:channel, force_none_auth:TRUE);

if(!login_res)
{
  # remove the failure so that plugins down the chain can verify after service detection
  rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed");
  dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Login via sshlib::try_ssh_kb_settings_login has failed.');
  audit(AUDIT_FN_FAIL, 'sshlib::try_ssh_kb_settings_login');
}

# show run-config
channel.clear_data_buf();
channel.window_send_data(data:'show run-config\n\n\n\n\x1a');
session.sshrecv_until(
  end_states : make_list('SOC_CLOSED'),
  channel: channel,
  check_callback : @cisco_wlc_cmd_prompt_cb,
  cmd_timeout: 40
);
if (channel.data_buf) set_kb_item(name:"Host/Cisco/show run-config", value:substr(channel.data_buf, 15));

# confirm if this is a wlc buy looking for Cisco Controller in the product name
if (!preg(pattern:"Product Name\.+ Cisco Controller[\r\n]", string:channel.data_buf, multiline:TRUE))
{
  channel.close();
  session.close_connection();
  audit(AUDIT_NOT_DETECT, app_name);
}

# config paging disable
channel.clear_data_buf();
channel.window_send_data(data:'config paging disable\n');
session.sshrecv_until(
  end_states : make_list('SOC_CLOSED'),
  channel: channel,
  check_callback : @cisco_wlc_cmd_prompt_cb,
  cmd_timeout: 40
);

# show sysinfo
channel.clear_data_buf();
channel.window_send_data(data:'show sysinfo\n');
session.sshrecv_until(
  end_states : make_list('SOC_CLOSED'),
  channel: channel,
  check_callback : @cisco_wlc_cmd_prompt_cb,
  cmd_timeout: 40
);
if (channel.data_buf) set_kb_item(name:"Host/Cisco/show sysinfo", value:substr(channel.data_buf, 12));

# show inventory
channel.clear_data_buf();
channel.window_send_data(data:'show inventory\n');
session.sshrecv_until(
  end_states : make_list('SOC_CLOSED'),
  channel: channel,
  check_callback : @cisco_wlc_cmd_prompt_cb,
  cmd_timeout: 40
);
if (channel.data_buf) set_kb_item(name:"Host/Cisco/show inventory", value:substr(channel.data_buf, 14));

channel.close();
session.close_connection();

# Enable local checks only after login was successful and we are sure this is a Cisco WLC device
sshlib::enable_local_checks();
replace_kb_item(name:'debug/Host/local_checks_enabled_source/plugins/Misc/s/ssh_cisco_wlc_enumeration.nasl', value: 141);
set_kb_item(name:'Host/OS/Cisco_WLC', value:TRUE);

var report = 'The remote host has has been identified as a Cisco Wireless LAN Controller (WLC) device that does NOT\n' +
             'directly put the user into the device user CLI when login in through an SSH terminal session but ends\n' +
             'up at a username prompt and requires re-entry of credentials (Cisco Bug: CSCve45024).\n\n' +
             'Nessus has managed to run commands in support of OS fingerprinting';

security_report_v4(port:port22, severity:SECURITY_NOTE, extra:report);

##
# Callback function for Cisco Wireless LAN Controller (WLC) devices. Check if we are at a Cisco Controller prompt. 
# Used in sshlib::try_ssh_kb_settings_login(). By the time this runs we already know the device is a Cisco WLC. This 
# is run when sending commands to the device, to determine when the command has completed. 
# 
# @param session  An sshlib::session object
# @param channel  An sshlib::channel object
# @return Returns TRUE if the channel data buffer ends with a Cisco Controller prompt, else returns FALSE.
# @category SSH 
##
function cisco_wlc_cmd_prompt_cb(session, channel)
{
  return (channel.data_buf =~ "\n\(Cisco Controller\) >$");
}
