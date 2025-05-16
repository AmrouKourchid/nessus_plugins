#TRUSTED 46e6ffd6c7d15c1befc29e231e1ef8a9c8d63a7975bbd83edfd42320f6b3c9f2da420991dca5fd9de6dd5ca8b8277fa8ad56a59dfba692507e14dc95d86735d063bd0c5f1399be1ce4f4a9ed1f92d68529617cefedec0f0182da05d13dcbad02224110113d19cfa8408269ace1f7fda8d9be20b4067232f56b6f0b4ef320397241a129ef29080888d65309365e285eaeea61abff057b7b755b557fda63d359949ff9bcdf31f06d13de38798598e04865c3db28494aed6708f65320b44a6161cee3db3cbf501d409ea240f7498e0ee443b161cb4aa21b6dcde4c9e29e4c185cfd0098f4f36e67b42addc8b1edc3c8e3e62e58974987b8ddb98c56eeaab056563ca68de34709df762aa29e3d572531dd1e7cb037b7833453c7805eb0d1b1d2b62838fe032b9f0ffcc120bdd62ecdfa37e499963bf02501b61a664d5a20cfe9af5a4ba91b88c50fde0f3d08e059afd6b19def877881bf75561b8ac403a1d21340692b5cb5f22d6c61a0d94978209b78ddf0a65704f760b47b0becb56aeb027943517b7e1914f8a7def0a87ab8de5ee64fcf01bdaed399b10411839ba363811965014948d6b74a78127efaa0c57da37e86e3da93de25779c2df5aea6c8fb9438783e4b2be55eb38fecfcaecf056895b9398f00e2347e17b4ee3243f20c5cd1980c138793219bbbcad9e5c38eac746219062bd1c5c7724213e7a0570445a5136aa0a7
#TRUST-RSA-SHA256 6c4af782c62c498f0dfb33cc176482993e508a7f915ae5cd95f2029076360eb23af088be4df4155a539b33e29656eb074e45087cfc2106643693af4ec61781e11b2df884fca5a29186d5377523d89e3dc72c9fe81d92182fa2ca81a187d31018d6462e688777f4cde628f796cfb71877583ad2fc5364e4a226539c1d38c6361b75e04b7879c7cd0f931c1de1b78ce025e8040864193421a9f9473008d696a758548e2a291b9a92b8bdfbf7c36911b3abf1bc0506182806da8a496307cc1b951f34fd328cc3857d432322d5709d8ad83be6646ca59e6e0dc7e5dcef9ec4f776fcd834ce7f70577d094c2f0018f6463867fa156b783d7e3045d56555d0c4f3714c8092fb2cb617d4d29d31a8fa0ca246879cb21d021195e6e9e1d3d498f0caedd8a3717d7792baa297b1e6fcca679d6c2af35ecc18aad944c667b560e36c36244644bcd89e81e520488e620f9380e41d87cb48b8a7c640b89c11939a5a67218a7ad5659c2c114e351e8ce686745eca67aca64460d62a24907c407e99cb7044fc6ad1f72756e562365dc4256f7bca80141c40fafb9eb0c761f63a43f37334e7dc62f4efb0228ca184f8c7d71fc5f8e61a3ffcbb4fe98598bd0c9f7e62b51252d59dab44ea08e3406a36ad172a6793e39d351afba74d08bcd02537b9d9bcefd220794b0c611a20a3af370a030342882801f8689087ed008893e1343cc45c97923347
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-ntp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70321);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2013-5472");
  script_bugtraq_id(62640);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc81226");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-ntp");

  script_name(english:"Cisco IOS XE Software Multicast Network Time Protocol Denial of Service Vulnerability (cisco-sa-20130925-ntp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the implementation of the Network Time Protocol
(NTP) feature in Cisco IOS XE Software allows an unauthenticated,
remote attacker to cause an affected device to reload, resulting in a
denial of service (DoS) condition. The vulnerability is due to
improper handling of multicast NTP packets that are sent to an
affected device encapsulated in a Multicast Source Discovery Protocol
(MSDP) Source-Active (SA) message from a configured MSDP peer. An
attacker can exploit this vulnerability by sending multicast NTP
packets to an affected device. Repeated exploitation can result in a
sustained DoS condition. Cisco has released free software updates that
address this vulnerability. A workaround is available to mitigate this
vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-ntp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c1eb72e");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-ntp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/25");
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
if ( version =~ '^2\\.1([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.2([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.3([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.4([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.5([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.6([^0-9]|$)' ) flag++;
else if ( version =~ '^3\\.1(\\.[0-9]+)?S$' ) flag++;
else if ( version =~ '^3\\.1(\\.[0-9]+)?SG$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?S$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?SG$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?XO$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?SQ$' ) flag++;
else if (( version =~ '^3\\.3(\\.[0-9]+)?S$' ) && (cisco_gen_ver_compare(a:version,b:'3.3.0S') == -1)) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ntp multicast", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    if (flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_msdp_summary", "show ip msdp summary");
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .* Up", multiline:TRUE, string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
    else { flag = 0; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
