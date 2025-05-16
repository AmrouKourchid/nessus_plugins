#TRUSTED 2bdca130b0de84c4ef356fdf6c1a8c82f171b8620a7a5ed837e3f9ea7dcc7eacf46f81153a30e9f7cf4cdbb497456e5c2dc8e03d00fde6b3113422597283ca1797bdf7511891dc84ffb0db150753245294703261c39de54430fca4a86f9f44a07e6b393c6e647cd0f9b1c84ec484044af5b370d4449cee971fd437b0e145a2c5d1e586b55bc0fb196eb61e729d46a15a008d36426f8880fdbd5dc861b4bd93ceefbe15e483ec7ece9ed5f03621700e1b1886a2b1a39ce2a82d43ca23817174c72e390cffddec0a4e2016ac961090e12ea327fa6ee3311d5e434f208d5ef51eb002674af5606ca36ed080bcdec5c55c834dc4c174a8e7105519d5e99dc2ad734c07eef115aad4b21ace6dd54aef30e201ea293e845cbe4fcdbc56eef5490df813ddbc24b3925419886291596636bd0b296b8f63fb03cee58f984daeeda9ae22947f8e034832bdc3d58999f2ca4a52ca84547e428ae6e112861b0bd03ad15ab2d1351fabae84b9f287c788420d114027f82df9020122c174d1b3798be67d6ff9533041d38183f0966f177f58e7407edac52295451e53b050159540a28d748d3b5d2b89039e976493fc7c2106f795b18ee28ce6db5480754a52af9fb6b4a9342d9683b6624d7e00bdfb1dfbb5f77b721b16675b5b822ac679b4978cb78c10c96e09af83d10e1360f0d0be3a64c6f443ab91f0f4c71b786ffc06e83b25ff3d03e9fc
#TRUST-RSA-SHA256 8e3f0444aeed4348c7997e1488cc38513cdcf0838981ac3323711edffc9d7509945a28ceed3ecf9157160cb820bcf11b3c06082c91b99ec59a5d312e0c6ef47f9843489999762276d9348513f66df2da857ef4f75aef000b8615e7233b1906483d0472cb163f5a57675d55576581b5ebbbc13c80b740a8df9c5f923850aa86e4e57d53d3f692f6ef596f9268e640f534a66650a61282192098a0b661f68fdd4550764e44c5993066e057d26370ceb1ba586881fefbda1f28917e98238750471789321a4e37bc14ea2296b79b2371916d558f215bfc88d8236eb42274fb04ec49e3a96b72ff2c3a349cfe702cd18a2de706f9608f2a56bf72e6d291eb78e74065bfe131da3c4cec9e4c10564516c9df1df1a24342db87c43839cf9184aa52a8abfd3ce876208fa28afe389356faff71e3ddbe63d1567b393a812ef39d90481fb475c54458d25d3bad2a7b48f76a9c2974963c280142faf9f856db7992a074f9f2725623c1386dadf95a2c789cba122e2414e4e2aba7805cad17d35afc9d9377871bc45d52d62b5282c6cb9efd329653fcf10436322ea6c817af5b6ec7f2866bb877e34be6ef11976b62d0cd36cb309f7e8f2533f243b0d8bf8535745b320c134405930695a66f7160c5fee0b46c6bd288f271ef1af2d5779e81d9581252c299634fa9c2ea01ecb925a1f14351f46e35326055657b1ef1d0eaf1e25e79b74de3cc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104411);
  script_version("1.11");

  script_name(english:"SSH Compression Error Checking");
  script_summary(english:"Attempts to see if ssh channels can be opened with compression.");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_set_attribute(attribute:"synopsis", value:
"The remote host supports ssh compression, but actually using ssh
compression causes errors.");
  script_set_attribute(attribute:"description", value:
"The remote host supports algorithms that can use compression. But
when ssh attempts to use compression for that communication, the
connections do not succeed.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/06");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_settings.nasl", "clrtxt_proto_settings.nasl", "ssh_rate_limiting.nasl");

  exit(0);
}

include("datetime.inc");
include("string.inc");
include("byte_func.inc");

include("ssh_func.inc");
include("ssh_lib.inc");
include("structured_data.inc");

USE_SSH_WRAPPERS = TRUE;

#start_time = gettimeofday();

enable_ssh_wrappers();

var session = new("sshlib::session");
var sd_auth_info = new structured_data_authentication_status_information();
var login_res = sshlib::try_ssh_kb_settings_login(
  session          : session,
  accept_none_auth : TRUE,
  force_none_auth  : TRUE,
  sd_auth_info     : sd_auth_info
);
delete(sd_auth_info);

if(!login_res)
{
  session.close_connection();
  exit(0, "The remote host is not responding to or permitting an ssh connection with the supplied credentials.");
}

if (session.compression_enabled_c_to_s == FALSE && session.compression_enabled_s_to_c == FALSE)
{
  session.close_connection();
  exit(0, "The remote host is not using an ssh connection with compression enabled.");
}

session.get_channel();
if (session.cur_state.val != "SOC_CLOSED")
{
  session.close_connection();
  exit(0, "The remote host is not experiencing any difficulty with getting a channel while ssh compression is enabled.");
}
session.close_connection();

sshlib::KEX_SUPPORTED_NAME_LISTS["compression_algorithms_server_to_client"] = "none";
sshlib::KEX_SUPPORTED_NAME_LISTS["compression_algorithms_client_to_server"] = "none";

session = new("sshlib::session");
session.open_connection(port:get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "verified_login_port"));
session.login();
session.get_channel();

if (session.cur_state.val != "SOC_CLOSED")
{
  session.close_connection();
  set_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "disable_compression", value:1);
  var report = 'Remote host determined to support ssh algorithms that support\ncompression, but in practice cannot successfully utilize compression.\nCompression will be disabled for ssh connections to this system.';
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}
else
{
  session.close_connection();
  exit(0, "The remote host is not handling ssh connections any better with compression disabled.");
}

