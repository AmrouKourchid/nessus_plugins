#TRUSTED 480f672ed8525a4a74e1a105a739d37c3188c123468c40b90770bc591c34778d1135c74c07650400844b12966be0b02d11079265fe35217b34aef307e9e32e33fcdbef228d37ac9ffe134433f143872db5e4ec86a5896ba4342ec74dfcc39e812790e079b91a408f1ec123cac51ebfc1fe780d31b1323411df13015bc34f7650eeed5d45510cb4b977154fd713bd7fc5ca7cbf512573b75a77f46b826e76e1143dd7284d60f8d2bce5bb5dc3990751883ff0cc139ad37f33384405c709ae96f5c1c1da54db6afe7d8a9828829c42262091c60820fa21001da3206ecd25508532f254ae2fdf7f0ad1ad2162d363673e67e3c0564646373a2051c66940edb1ecd8d989b471c319bf722b89ec7dabcd89505eb2ef541070610d79432a385d5b87a8a743dc5fe41ca119e534990f3fa92c429136f450cf6eafe335973b8580e4fc57f5e3aaf93930785e4a2ddf2e0593e1204efef61a3700714692bba832b13eccd5d3c9f70b257872a586f6623bf3026d8d40dfd819c9fd14926ac4b780345a6c2e43bc4419d7ccaf864fcd6a55442ae01e3302c22e6a02683803acad7065b346a30008abb9bd787e9bf0ecb07c8b9183b03347b67cfb330ba908fad367d7b49c18984476a2e2edb8ad5008e49d9d8d5bc2888676388e6234c43e728413d86fe3b42bd1ebf73f6bba6c7c3a5a661aefa5952c96c0541c8fa70d85c8284eea28468d
#TRUST-RSA-SHA256 af8b031f90e48c19cc3cc168861ea3fe93a8d4dc8915c360b10783a3c75a7aa9180eb6be6c9bec271ad3f61ab5b42458490b94b7664b04e21fbba851dfbef1193e0d3a07c45c8bf8b95cf4755d6324d7264b33aadd63c023b18e8ab113429067cfac71024e3a74bfe98a007cc17d7eb8d3c9e0d25ae86fa4e34487b4cf323e96cfe15434bf4481a6723588831de912ebe3c1cbda9128e771ce01f771855ef83509f70bee004c2416f7a20aa5ad1a9f4fd79a6cc542ba94822decea8ae5fb3ab9274cb3953f38372b61fe6b4eec0cc674092150b2983f239e88e6b379fd60f157e560b9d29b9d769805a19ba7cbb86e7b7a4637c6fa46e6a48bea204f5db8c205bc9735da5af20980d64ed48a4f1acb6c6b425e57a5e4390b7adc9e4b2b17c7f9e4375460963769281ee48743f73ea38f1c6b79573678bcff55e806705c27c5fb4cfe9576205ead4ca35488705159ec5a108052d10f155390a6e7885dd8077cd8af50d733810bbee76974662f0dd79f555fb717278d219ee92837d48b29fe04b72c6362182a600b1f78fc3e492ebc8638c83d1314331f22ff5a49833dcf119fef139fa4c43045ac71afadfcc4330dec5b566790d788a6c317598382c10fbb312e9f5a20a4af68d6dee1978e04ef0b9efa2d2ff711184b51cf87b12e84a858adeaf16efd770e0a2c615b5f9105c4c61fdd78259a19a6f2603619fa782ae6de689e
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-dhcp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70315);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2013-5475");
  script_bugtraq_id(62644);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug31561");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-dhcp");

  script_name(english:"Cisco IOS XE Software DHCP Denial of Service Vulnerability (cisco-sa-20130925-dhcp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the DHCP implementation of Cisco IOS XE Software
allows an unauthenticated, remote attacker to cause a denial of
service (DoS) condition. The vulnerability occurs during the parsing
of crafted DHCP packets. An attacker can exploit this vulnerability by
sending crafted DHCP packets to an affected device that has the DHCP
server or DHCP relay feature enabled. An exploit allows the attacker
to cause a reload of an affected device. Cisco has released free
software updates that address this vulnerability. There are no
workarounds to mitigate this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-dhcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6378bd7b");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-dhcp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");
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

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if(version =~ '^2\\.1([^0-9]|$)') flag++;
else if(version =~ '^2\\.2([^0-9]|$)') flag++;
else if(version =~ '^2\\.3([^0-9]|$)') flag++;
else if(version =~ '^2\\.4([^0-9]|$)') flag++;
else if(version =~ '^2\\.5([^0-9]|$)') flag++;
else if(version =~ '^2\\.6([^0-9]|$)') flag++;
else if(version =~ '^3\\.1(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.1(\\.[0-9]+)?SG$') flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.2(\\.[0-9]+)?SE$') && (cisco_gen_ver_compare(a:version,b:'3.2.3SE') == -1)) flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?SG$') flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?XO$') flag++;
else if(version =~ '^3\\.3(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.3(\\.[0-9]+)?SG$') flag++;
else if((version =~ '^3\\.4(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.4.6S') == -1)) flag++;
else if((version =~ '^3\\.4(\\.[0-9]+)?SG$') && (cisco_gen_ver_compare(a:version,b:'3.4.1SG') == -1)) flag++;
else if(version =~ '^3\\.5(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.6(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.7(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.7.2tS') == -1)) flag++;
else if(version =~ '^3\\.8(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.9(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
  flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_dhcp_pool", "show ip dhcp pool");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"[Aa]ddresses", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip helper-address", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip dhcp pool", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
