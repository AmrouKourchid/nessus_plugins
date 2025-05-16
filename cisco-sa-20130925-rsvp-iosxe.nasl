#TRUSTED 7d17cc5b20a7cdd42c63178773f1fd5e8904ccbfca25674bb6a4d0d32c844d608c47032bc16827ac4cdb30805c926025c39a4221176a2eae977a5ceba3560ad132c4679273c3ed43c5c9ef47429b7d1b1c3be14a68ae100cc99cf45f7029f8295a7749e2116e8656efbc3d21790aa88d9cbf88d55fcc9570fccc5d92d42be49037a4cbf07843492b46b3c53f3d760f5f15657b795eb7a56e01db4322273669ca8c481aba1584c5ce5a1962969dfef37e273525a12b2fa4d6e56c474f55125ff497660290b1c7f0ced9fc99f3deaca80338483597c55e493d88dc441bff6d59526c7da9160c35d7ea59b33af1494ca907605b8338a8a079f91fe304ac4a8c1ba476b40ef9b3c50f4395a72b37b28e627ed7e118e12e016da060da0f5d35868df294c0d660227a0c6c520afa4e3c28597388d407adc4889e45eb7fdf2b471107b4177456393bfdf468ebac13a6d354d2eca17ca8920c54b09a00df8499cb1abd99e1703e07febd6c5558a50d24ecce14b1964741976c09a56a833492d54209f919386f74cc62d1b7b3e559c94fbc7a3259ece09694e3bab391c73549fc29fa755cd9c57967ee97a9a595412efe866eb4f825f40f3850b49b998cb70f9d233e2a2f02f643b8cc99a08925361a8f6cc265aed4fc033228df4e47fc5708a98a7cdc9926c756a504964c255f003cd6bf8a3fda33fd6eaa1af4f10e013b498063700372
#TRUST-RSA-SHA256 1742e48965044cfe9544727d166e9d6a9af48494afcfec6397e1aaff15b9b31e1dad6a5ff0686e8211408c9522000d2afd3b848363e164309c9896f586c56df5de215bf4c4fb484ace8595338d26a65c9c5b2ae2bee8af68c9e077d323270b6dd76fe36a70eb3a6974f457c59eca948bacc46564ced638d3d97f92efb3738b71ba064912a80daa065b749f952480df0bc30004e3f8e9e457cfe7f826fdf07e4e10536cf71426576ffa8b2fbde7d2821f1792a032a33348217205b4ea64fd93a3d7f57aab0a56e15920bac56e0348d1aa641a872e8d600ccff6865adb67e3a13dbd496f2b26e1373c69ed6306f3ac5765414083ea706a70c4c0af40d64c845bca2b77af6775b381e7971be0b7ae7c6e08473a2761aae07338ecaec00e088ab8e64aa2b86414b999d035026c17d03f9000eeb8078fc6cddb00327a722c6993964ebc3fcee10888ba26ca677c911b0b550c707b9269d853785119bfa027e128a9e4da852f88eded7babc1ed450080f19fadb9691b8cdc3af1e083b75c6ccf875c9260402649876cc1c1188cfd3392096ed4dabfe26e1558a85c1e97e45b0119be1a706e454d9240df320499e19bccce3c84796f4f22ca642484ef7f58d25c3fea82bfbabc2f7597fbc0501fd669412807b9137588f8586576148a7e90fef131cb122892a7660b79641ab747673f87bf76f9254c056f78dfcf8ad3e2bafd45357bab
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-rsvp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70312);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2013-5478");
  script_bugtraq_id(62646);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf17023");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-rsvp");

  script_name(english:"Cisco IOS XE Software Resource Reservation Protocol Interface Queue Wedge Vulnerability (cisco-sa-20130925-rsvp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Resource Reservation Protocol (RSVP) feature
of Cisco IOS XE Software allows an unauthenticated, remote attacker to
trigger an interface queue wedge on the affected device. The
vulnerability is due to improper parsing of UDP RSVP packets. An
attacker can exploit this vulnerability by sending UDP port 1698 RSVP
packets to the vulnerable device. An exploit can cause Cisco IOS XE
software to incorrectly process incoming packets, resulting in an
interface queue wedge, which can lead to loss of connectivity, loss
of routing protocol adjacency, and other denial of service (DoS)
conditions. Cisco has released free software updates that address this
vulnerability. Workarounds that mitigate this vulnerability are
available.

Note that this plugin checks for an affected IOS XE version and does
not attempt to perform any additional validity checks.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe2616f7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-rsvp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ((version =~ '^3\\.[2-4](\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.4.6S') == -1)) fix = '3.4.6S';
else if ((version =~ '^3\\.[5-7](\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.7.4S') == -1)) fix = '3.7.4S';
else if ((version =~ '^3\\.[9](\\.[0-9]+)?S$') &&(cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) fix = '3.9.2S';

if (fix && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_rsvp", "show ip rsvp");
  if (check_cisco_result(buf))
  {
    if ("RSVP: enabled" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  if(flag == 0) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", version);
}

if (fix || flag)
{
  security_report_cisco(port:0, severity:SECURITY_HOLE, version:version, override:override, bug_id:'CSCuf17023', fix:fix);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
