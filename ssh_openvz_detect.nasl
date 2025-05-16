#TRUSTED 7ed7a6a8425a58fb1d51066b7032acb76e5640ed3b7b9d645366e084333532d7b42f08747cbbbf6db64c2d9910f2d2c0ebd49ed04dc3e7ba2647e3b9bc271831e7d7a39e9d7fcd9a01ba3cb08cd3ae9ce1f63d2e61ce4017c7688bab0f3cdf06422adec11073b6238c1a892423eeee2996b7cf332071c343314314c4c5744d0200a5d73686b69049a37a1ac60c9255110379aa8c33442038808422c2f24baeb22fceff1d5dd17fa3fd4fcf2f8bdc1d648a5a98c96f3ae4e4446dfa5adc37522521f0537d206c28039f48d534a108ed86c2ea6a95db17da0a9698598ad2345d4fc4b0b16de5fa1931f30ebf99ea75c0677611642ffb57a63894d520a9f81252f0f2b3800c7aa4cc0353fd1b188e84d56c09500ecb185e9669d9374bffd48a4c0ecfcb18ae13ea0273605f8696f69d4854c000aac85472072c3a0e7064135f8c6541246e3f7fc7d9894555506cab10fbdbb4fe8e7bd5e08029bf438e806f9df29b5ee1188ef7eb33037a9f9dad6011f59cadc9defeff42007c152632d5c7c883336a69ce6d997719b41175a8b78d4bb7ebcb1bf144f2a4e888a9f4e05804bcc350e88dfbc2301e85a546f5039a45b6aacc16b8c4979a6a0cc12e32ddc94b7c6a95a17e3b5d62588cec69eca21a47d7c83b0c187eb1725ef48cd103d061a4421542c6125bb395ca4279d0a4dfed8e61c5d216cd1219275e6347235f2f457db270a2
#TRUST-RSA-SHA256 75bab2434432a857238bc1f78fd5f96b72b52e1f207831b3b2376809e30b5492f359696ce172701f8e24c87a6b1e52ea0a5d56d9d1e2ddf11518747e851a8d5600149a7b8f683d6036e5143345a3dd4da8ee88f0d6e08c5b52d32aa31377f4045116124c96a49805fdd423a62bca6287d0372d0ea25a7741a9a9d8336c3930720287c4ce7516a049c651cdf70f9463d5eae7c83143522577be62838597c72f1b1172dc3ebc0ccb041e8e48b564e0b73267694b122009ad1f36dbaa0f93c0d31fc39298b9d10f96193658ba9d56532db76d0bb556cb38edb54b42caf258528e633fd9eb4e20c80386bb9248a53ca7b838087e4e5d01c4ad4c7b118f7b8e3cfdc33979083ff81fc86105308760f08f50f0e5a658feb497bae62fd4b0843e712bb3fc6bd8ede1b1f5f431a0ee4fd88f30dbdecd5ae59b9ef93abd1d23720426f6d35cbf5d392ae4811470f195b2bd2a1c0ca0ee782a0ee1c15f896bbfea4d3b5d9988f0d4e8303c031aa6be83d3b57b7d35162c632a58229709d4e8257f8394b637f6144f61f5f9235e319a6682ab57ec4382c0b20d721beee07cbad7757f7346346f6024d5ea48c710652d878d1e8d351de535d942e7d82000b9faaff055fcee0fb056562a94e6ec1ab936144714a7a00a4c4fdd73d32f3dc5a2b050684eeab4b53c553017fd22674455ca6239d6d68c70fa89e6ece216f1355add72b1cfbe8883
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(51092);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

 script_name(english:"OpenVZ Guest Detection");
 script_summary(english:"Determines if the remote OS is running in an OpenVZ container");

 script_set_attribute(attribute:"synopsis", value:
"The remote host seems to be an OpenVZ virtual machine." );
 script_set_attribute(attribute:"description", value:
"/proc/user_beancounters could be read.  This file provides
information to the guest operating system in OpenVZ containers." );
 script_set_attribute(attribute:"see_also", value: "http://wiki.openvz.org/Proc/user_beancounters");
 script_set_attribute(attribute:"see_also", value: "https://en.wikipedia.org/wiki/OpenVZ");
 script_set_attribute(attribute:"solution", value:
"Ensure that the host's configuration is in agreement with your
organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:openvz:vzkernel");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Misc.");
 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


enable_ssh_wrappers();

if ( ! get_kb_item('HostLevelChecks/proto' ) ) exit(0, "No credentials to log into the remote host");


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

cmd = 'LC_ALL=C cat /proc/user_beancounters';
buf = info_send_cmd(cmd: cmd);
if (info_t == INFO_SSH) ssh_close_connection();

if ('uid' >< buf && 'resource' >< buf && 'held' >< buf && 'maxheld' >< buf &&
    egrep(string: buf, pattern: 
 '^[ \t]+uid[ \t]+resource[ \t]+held[ \t]+maxheld[ \t]+barrier[ \t]'))
{
  if ( strlen(buf) < 8192 &&
       "Verbose" >< get_kb_item("global_settings/report_verbosity") )
    security_note(port: 0, extra: '\n/proc/user_beancounters contains :\n\n' + buf);
  else
    security_note(port: 0);  
  exit(0);
}
else exit(0, "The host does not appear to be an OpenVZ Guest.");
