#TRUSTED 1952c636c8ec368105606298a307ca21ff994500fa1048ce631a4d3bb9945d2d9855edeeaa9ff8dfb73fdc102a0469df2ae4a7bd2015a9cb37f28f71ab41d211d27739d6798a7904c94ad9a9a88ed0f6308ece2272d56a6fb0dfde8ff954f17cf687ac3ebe99392386870d313f09155e559dd2f9aa7e8c222b33e03a1faa33d37e19e24ac105b366f2ecc17478b426e71a65c13fdb7478a9fd6168c68f8090797c9d79fadb5b33db988e5f411c111e0918214ea6ad564b126887adcb5d8bf55132234733b8e4620d37036dba1623a35752812662c02d378f176cd094930ce6491a1fa5dcc0636fc09511b7681052f02b7dfcc54f2b2516368ed0c8e01fb55a54fe58d373a6c1d75947af260b90a5b1bbeb3be3e4693639955e8823749f7c40365a59ecb64779c1b7b151bc522680ed457efa0f999206661a34510ac8db01e938ba19d52642d620734df3779c169d5ddf1c93021aaef5cead322cfeb009b083639704c0494787772b0c46c2a2c83eb934afb5abbdb20a571ffe8deb644b65effff0ee7ac290dff97918b5fe6e506198b826938de2144c128e647e4dd5a11cae8ff1155649941dac4615d47c2d2ddb6ad8103b4d251f2176b9d20e282dd0a3864d84b4a826ab7d140086d2018b2e7817b88f5e139b4b86a61e9d4ab7192f0ca39defad1a06480c0bf26a74efba286e7fe63f9340e4343aa0d629b3486d4cf0d8ae
#TRUST-RSA-SHA256 2f3d376681a8bce403adebff540ec08df3923289877ef81ef27ca4df5d9f4c35e3a77704f87cc9136a2dac678cae198d14472b2a496ad057d12e7206a5b6f8c37d028c6d7ec703e13248d31eac7701a843eb5fd4fe3c73662b50b4edccae7bdd9cdc387f24e0c25d16aa89eb45e4aacbc403f09f066346602ea61328e1493bdd2c10c66fa394953cee48ce8923813e463c2614e0068e1dca8e97f23f3d47720685a6b0ac2245df8b46e48d29a7972ea9917244d0130d0a75553fc21d3d262ebf883a00cb314e0338f3c6769433aee4a98c30716780c5608bc4cb09a65186c8dba195b0fdacb89ca362702dadda3c9c9dcaafb47ec2b9e6d363b71f8d5a2cbda982db818b50516d689c058cc919c180ada448580b8e89bc9c108acc9fedad8cd40b02a0b1dce329931a1badc3388bf7fdecef9d1765bbea050cfad33c9a85ef975486ccb5b69f3633a68fc5f2780a61b58bd344826c39214d5cc6deb24d93de3bcb7eaf08664ef1a3999a52ada903587a988860c5cba4a0630882f162b8addbf4b94c3769116ac0408811c53a73e4053dc61d391a350676dace711326699d7680897d936ae5f3ee297f37f5fa6b6824c55292d0f56055666cdcee46e8cdd7eae708b35aefef56784d97c84cac445bc71340fa8ab752c21d14c0b4a4caa59f64eb7003fccb3a1b2f86f22e7b227f546f518235dede55eab408c132fccf001f1da6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73343);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-2113");
  script_bugtraq_id(66467);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui59540");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ipv6");

  script_name(english:"Cisco IOS XE Software IPv6 Denial of Service (cisco-sa-20140326-ipv6");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the IPv6 protocol stack. This issue exists due to
improper handling of certain, unspecified types of IPv6 packets. An
unauthenticated, remote attacker could potentially exploit this issue
by sending a specially crafted IPv6 packet resulting in a denial of
service.

Note that this issue only affects hosts with IPv6 enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ffd6d00");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33351");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}


include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report = "";
fixed_ver = "";
cbi = "CSCui59540";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# 3.7xS
if (ver == '3.7.0S' || ver == '3.7.1S' || ver == '3.7.2S' || ver == '3.7.3S' || ver == '3.7.4S')
         fixed_ver = '3.7.5S';

# 3.5xE
else if (ver == '3.5.0E' || ver == '3.5.1E')
         fixed_ver = '3.5.2E';

# 3.3xXO
else if (ver == '3.3.0XO)')
         fixed_ver = '3.6.0E';

# 3.8xS
else if (ver == '3.8.0S' || ver == '3.8.1S' || ver == '3.8.2S')
         fixed_ver = '3.10.2S';
# 3.9xS
else if (ver == '3.9.0S' || ver == '3.9.1S')
         fixed_ver = '3.10.2S';
# 3.10xS
else if (ver == '3.10.0S' || ver == '3.10.1S')
         fixed_ver = '3.10.2S';



if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline: TRUE, pattern:"IPv6\s+is\s+enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
