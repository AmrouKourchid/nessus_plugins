#TRUSTED 6ed6269ffcd891a7ece00d947b5211c1081cc4e5d9723f03efa42bb860367fbcaa55ae4b49218670424b6c90bebbf1bdeac7ae363f7efcf2d036b686f7b0f3f4dc6bee1165c842605d885fc451d4e33c9d619d3ac662b3fb66c06de1c33137905de064d637a0634442cdcb0a6224080bc7944c474473fc26b59d1565d91a91066d8986b8aaf9094ed3b34f6680f0aaae8d25f13effaea877421adec74f5a3323b5d2b708066d7951316892d0786b814044ad6a1c0806850815de54624fb35f89586d0a1a265ab52b7cd93b48e8c23498221f55b7a2a9325f66e1230193f207c3ffcd20539f1f596b64f04dfefe649f3634d01e2b4332bb9a2139b679e205db2814b21fb609515a922b8893f56a61a6f5ed99e23d1b41c32163f7ffee2dd8ae3fa03b1e62557cefbcf6f798eb4fa603faaa1748c0973df737272f4c135074aee85ff7be93831d7adbfe98b9a2556f39b36f04f4248e46ad69006d5ff75acbfeceb6be101a05508140103ad54fd860e76812187582912c34a1885d39f82bd7c64f4e3fc4ae3398f5af0940abeaf96fe64131012fecbb2a68bac8a690e1a49e3c8be9b88fc462fd69d6120929719e52b822a35caa12af372e158d675e7f798e911f6e5d3b95cb551da4d93b39f028c798e392af77e6939228c8a044c898b1ace3143b6c363e274e97b297047e7787d88ccb2fccdf05dc2470fe68036037b4bfa352
#TRUST-RSA-SHA256 3b90b5d77254e7daccb49855134868ebe9051eb367d90a1250e444678973dfb52b8169410f8d5be0672cc9ee3d52340a70c7042d45dcce41bbced5df04a070123bd4e59e9d11dce49facdf0c542ac03f08159ab093560ede2d4e082f8ed6c86ceb3450f634a161ab03c5d23bf767a0077bd07ba2e6699c90143d6537283ff871fc1d64c6675f65513173c0dbaa2361120e6a1eb0d0a7c22f1f8fa778122883daf6c443825377b073f8ba2c6c215b38b6b5bb2805182adfa424834469518449e94a3e91fa803fe8fc8de03c8942d37070451bbd83b1c0130ec0a644fee61db146cf41552e5fd59f600496b770e176b9982ecfe0c122494948c976aacc4dbabed29f7a0f0869f50b1d32a0111ec35499e2e1dfd504605261a16d3a845700ed6f0bdc545dae3f2f6047c8603d4cfd13345cd41973fef1eb88d8c978dd54186058c138db893fdb67cfd2a2ceb187d0ca6201931ca86f82de8db39bb66ae5c9b97df8fa6a677666bb2c6cede7f2618c3b53d2bc3eeda34283daddcf6d0771741c43943705b635873e21f65eacd7141b344e6a81a354dd51ada4274b1cbb7e413875bee287ec928dec768654b90969d6bdeb845a7b29bdc7195f3d9d2ab3ff81240f854cb329ea2646b93cf805feacd3221d7ebf36e0e39dfcc39561cb656efdd22af26bae68ff2805b27c47a81ba830180b1ddb8004a8f8074812654c928f1c04dd00
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78028);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3359");
  script_bugtraq_id(70140);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum90081");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-dhcpv6");

  script_name(english:"Cisco IOS XE Software DHCPv6 DoS (cisco-sa-20140924-dhcpv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the DHCP version 6 (DHCPv6) implementation due to
improper handling of DHCPv6 packets. A remote attacker can exploit
this issue by sending specially crafted DHCPv6 packets to the
link-scoped multicast address (ff02::1:2) and the IPv6 unicast
address.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?942aeed1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35609");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum90081");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-dhcpv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCum90081";
fixed_ver = NULL;


if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-3]SG$"
)
  fixed_ver = "3.4.4SG";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (ver =~ "^3\.5\.[01]E$")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver =~ "^3\.10\.(0|0a)S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# DHCPv6 check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    # DHCPv6
    if (preg(multiline:TRUE, pattern:"^Using pool: DHCPv6-stateful", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCPv6 is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
