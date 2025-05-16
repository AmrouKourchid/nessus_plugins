#TRUSTED 2e65f279944b8419bad0c0534337a83521a4df281eba86a8b15b957b818f0bcecc970991925e94ad9219a8fc5a5d728e02dcf4bd77f9f69d5de160c4e4c7a649f82c69fead67ae7cbda3aeb45fd1f4b17db53c5777a0d1fe8eb03225c0905dd0ccef0118b8f8bc77a702e470dcadd0bb47e64cd63dda422f4124c9c675effce58864954214c05fefb6e919d46d6e6e92a650cc10eedeeac0291d635360523d0bef636a6ecc8c0b9ed570bae31781f4acd193520817aa43df24f3d413a827aa971ea4c4da5539621c25c2ac7b52413855c5d78f4903e490bbda71cc66537f9b81156643a39e002139d049af5467b27e7804c74ffd761a37062dafb1ff4b008ee3cfe141bb29ec37eb8fcfb5db9fe7346abe2ada43c6fb2aa968df26d88e187a281e3a331ddef3d67b8be12af98299df13ed9173e900bf4e455b3e41fd21c4c0a2c521e4caf9286e42bdcf2847809f35139af2f836f2263994915c97c9de184191d95a7e4d01fd1d53faf7abdb4fd18e34765803d16bb3786920574f9722b2fc4fc52fbc08f7d8c0bae74db83b43c0cb063d1934f16ba0e207a1f14af0b68659592123699a2b92e71cd892d07009964812756af1476d9190b8ee0b0f66de36fce7eb442607f3c7496f14591a969f76bfc826a1b888ba1b7c733defeff1ca61b69ab90d13aae02e748afa65c00ca1210b9770cfd18f9bd6f52a578b2777ba506020
#TRUST-RSA-SHA256 23fb45c94cb98f630ddd1e0f70543785065dcc3d678570d8786987c577bfd23063d238a8358f4e990bb1158005669ae8d64bd9da5630ebabac6c35e4a71b404c9088c631bd0f2fb2b881d067099d6c1197e0b90b5af27e4afcf284edb37a1be6b6e858bef43751cf113f848e5fa45b69a01fcbe88b5fdeb3ed4480fb4052e0257d7fc5a5491796629c32fc93ea13741247b1753f6af4eaeba39220e78f75b942e7e4d5d30bd538276be6e57c6af9a5ea5441d2d1bb043d0ebc0f3e240aa683541aa05a7e862e9956131d733ca5a7e1011fce09508c0677886fc01a157dc8560f66314b9a135476634f6c93f2c9f3558e008d82f082502b261a10c1718e47b084ff0230b7176a35d899e4f04d004d2f36fb3fea73f7f81bfa236a6988d9620f5234e6a47727eed495231bec0a278046624761810b53570c6098b88497744ba80da5b5184e32bc930624ead5447399bf6291c67bbf352fb96a2f9fe746dded3ea7abd15d92ca8191925f228ee6cbd930068d2453eb126269e13074dc704c137fa1c9681d0328a11c9d474ae0e39ae85ec31e336176c4b60188203b4a0e9112353fd42f16bda13d218c94ae605d5695037a31ed984f10c0538dfc3c85f24d5d95fd5364d9b17aaec1e7e0211883f05f10f817985c81f844c2ea8b7bbad8b7d96fc6ead972e59b2db1ed529ae08fe15503d00d18918711e4895a63a65599a67f3c01
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99234);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_name(english:"Cisco IOS XE Smart Install Protocol Misuse (cisco-sr-20170214-smi)");
  script_summary(english:"Checks the IOS XE configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The Smart Install feature is enabled on the remote Cisco IOS XE
device.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device has the Smart Install Feature enabled.
The Smart Install (SMI) protocol does not require authentication by
design. The absence of an authorization or authentication mechanism in
the SMI protocol between the integrated branch clients (IBC) and the
director can allow a client to process crafted SMI protocol messages
as if these messages were from the Smart Install director. An
unauthenticated, remote attacker can exploit this to perform the
following actions :

  - Change the TFTP server address on the IBC.

  - Copy arbitrary files from the IBC to an
    attacker-controlled TFTP server.

  - Substitute the client's startup-config file with a file
    that the attacker prepared and force a reload of the IBC
    after a defined time interval.

  - Load an attacker-supplied IOS XE image onto the IBC.
  
  - Execute high-privilege configuration mode CLI commands
    on an IBC, including do-exec CLI commands.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc0b0179");
  script_set_attribute(attribute:"solution", value:
"Disable the Smart Install feature.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

cmds = make_list();

buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
if (check_cisco_result(buf))
{
  if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
       (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) )
  {
    cmds = make_list(cmds, "show vstack config");
    flag = 1;
  }
}
else if (cisco_needs_enable(buf))
{
  flag = 1;
  override = 1;
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_NOTE,
    override : override,
    version  : ver,
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
