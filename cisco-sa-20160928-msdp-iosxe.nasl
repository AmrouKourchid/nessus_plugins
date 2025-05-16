#TRUSTED afa23c941d376d7aa5e8801cea5cc32ea629086b5057842cae6c109e43db36be703732edf8a6c44a1df7b395bb0ba5f714d4e4d498554049e245588b9b0ee8b52408a07cfbcdd98bee77a90d185c7a47032019ab4f1f5401e5727810a89ad22e5643a5163a3a683379e5e0d54aba51802aa186f2fff2fc140b6e78523b4eb3193d0c4aa5b06dfdd24be4981add79f1036a1a4a938ac34583c2f2784bf0f4c1e85a6de859207a86b0cb1ae34763ae06fb0d1257e68e79396a1f974bc50692dd62c171672aa954784c552b36bfbc38c947b5fbc8b417edfb2b3b44ab6dbd1486f90fc73d056caf0d1ae955b500ee0948aef810b42aaaa9728dc4be3591369d9cd799bb6c4dcde4fa92e916803bc8e87b785e422b9ef3f6ab76e0d543010e3e89159d5f593d8da64d28f527c30f86f33941ff2d898f20bc5089d50c85564f1cf4ac9719333f20b026e66dc88c495853f6a10066b0b6b82588787de9b6444dc0b78780a393574f37da057b388610c16831b18cbd00110f5a69e985c135c053a513ab35551e28251bf5c29ab7adac8c3190ddbd229d5c19faec73b37ed298297536d0b7a76cfcdbc6351bacbfdaf4ebcc09d31da4d4f2effe438d10793dee27c68671cb5730778f34864edac1a5ddff8c5454be8fc7a253684fbd2c26bcd08f926776ad53123577a286205b5d76ca3d795f0044864475a83bee38c774d5567e3749ba
#TRUST-RSA-SHA256 8623e9f13fde5884dd2491489f68608d711a41e61a88cebb6d1d859a89ceb89ec7265e75df5199e34420b3ddf0acfc1f0e125c28bcffe6a0a1f15b0ed5db577637f7a62886040f49f9600a32a3801b9678a48f7a319c4c6060e9a0983d1e42ea5fbbec96b2b233da65713ad3cca204178ba554902ea12e42e4830d7130dd4351b6fe70c9336d8686f3162549931ec36ca9d47fdc97bce0af9f0993048a8d2ac45955f7ea8edb42e87ea3405a3cc6b4b2d35f607fec9ffa9407e4ee6c5945e168c1a18b6477b35b63f8a35e987bb65c4b935fc2734519f12359956a6f38ca148b52a5b0d4d1198129727d2bc4e7f65db6b8d804de34573a52d6afb9e72815bdb62aefc567e29831956fcb3d3b0eddc319f042b26b74568d62979309508e55235fdb9f8562346e154cda79224e8e7796aab63bbfa7de0ea0d61c5bd7347ee3a2054b8dedb53681d2c5784a4fe650e4f6ae0813aa333f9aa83de602d44128df11ff05aa65d21cf20e0c16aec849c148676314f0f4cb832acaa50828559fef8ae2a68100c6ac7f9f1990f4f51e424e95331135bdb7769548741abc90265f3ddd3658be4c020a370c2ae75d95b2c7dfdff9ab6e39a9a993f171945eddfebf5ea19fdd726c91d9b148411ebae8604f3dd68435ad44e10d589882c5927db84d674f104d80b4105a05334bcc0f72c0cd7d7142fe3cfac557eef87f61b9a402e9885beb62
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93898);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-6382", "CVE-2016-6392");
  script_bugtraq_id(93211);
  script_xref(name:"CISCO-BUG-ID", value:"CSCud36767");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy16399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-msdp");

  script_name(english:"Cisco IOS XE Multicast Routing Multiple DoS (cisco-sa-20160928-msdp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Cisco IOS XE device is affected by multiple denial of service
vulnerabilities :

  - A denial of service vulnerability exists due to improper
    validation of packets encapsulated in a PIM register
    message. An unauthenticated, remote attacker can exploit
    this, by sending an IPv6 PIM register packet to a PIM
    rendezvous point (RP), to cause the device to restart.
    (CVE-2016-6382)

  - A denial of service vulnerability exists in the IPv4
    Multicast Source Discovery Protocol (MSDP)
    implementation due to improper validation of
    Source-Active (SA) messages received from a configured
    MSDP peer. An unauthenticated, remote attacker can
    exploit this to cause the device to restart.
    (CVE-2016-6392)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-msdp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72b1793a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCud36767");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy16399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20160928-msdp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

if (version == "3.2.0JA") flag = 1;
else if (version == "3.8.0E") flag = 1;
else if (version == "3.8.1E") flag = 1;
else if (version == "3.1.3aS") flag = 1;
else if (version == "3.1.0S") flag = 1;
else if (version == "3.1.1S") flag = 1;
else if (version == "3.1.2S") flag = 1;
else if (version == "3.1.4S") flag = 1;
else if (version == "3.1.4aS") flag = 1;
else if (version == "3.2.1S") flag = 1;
else if (version == "3.2.2S") flag = 1;
else if (version == "3.2.0SE") flag = 1;
else if (version == "3.2.1SE") flag = 1;
else if (version == "3.2.2SE") flag = 1;
else if (version == "3.2.3SE") flag = 1;
else if (version == "3.3.0S") flag = 1;
else if (version == "3.3.1S") flag = 1;
else if (version == "3.3.2S") flag = 1;
else if (version == "3.3.0SE") flag = 1;
else if (version == "3.3.1SE") flag = 1;
else if (version == "3.3.2SE") flag = 1;
else if (version == "3.3.3SE") flag = 1;
else if (version == "3.3.4SE") flag = 1;
else if (version == "3.3.5SE") flag = 1;
else if (version == "3.3.0SG") flag = 1;
else if (version == "3.3.1SG") flag = 1;
else if (version == "3.3.2SG") flag = 1;
else if (version == "3.3.0XO") flag = 1;
else if (version == "3.3.1XO") flag = 1;
else if (version == "3.3.2XO") flag = 1;
else if (version == "3.4.0S") flag = 1;
else if (version == "3.4.0aS") flag = 1;
else if (version == "3.4.1S") flag = 1;
else if (version == "3.4.2S") flag = 1;
else if (version == "3.4.3S") flag = 1;
else if (version == "3.4.4S") flag = 1;
else if (version == "3.4.5S") flag = 1;
else if (version == "3.4.6S") flag = 1;
else if (version == "3.4.0SG") flag = 1;
else if (version == "3.4.1SG") flag = 1;
else if (version == "3.4.2SG") flag = 1;
else if (version == "3.4.3SG") flag = 1;
else if (version == "3.4.4SG") flag = 1;
else if (version == "3.4.5SG") flag = 1;
else if (version == "3.4.6SG") flag = 1;
else if (version == "3.4.7SG") flag = 1;
else if (version == "3.5.0E") flag = 1;
else if (version == "3.5.1E") flag = 1;
else if (version == "3.5.2E") flag = 1;
else if (version == "3.5.3E") flag = 1;
else if (version == "3.5.0S") flag = 1;
else if (version == "3.5.1S") flag = 1;
else if (version == "3.5.2S") flag = 1;
else if (version == "3.6.4E") flag = 1;
else if (version == "3.6.0E") flag = 1;
else if (version == "3.6.1E") flag = 1;
else if (version == "3.6.2aE") flag = 1;
else if (version == "3.6.2E") flag = 1;
else if (version == "3.6.3E") flag = 1;
else if (version == "3.6.0S") flag = 1;
else if (version == "3.6.1S") flag = 1;
else if (version == "3.6.2S") flag = 1;
else if (version == "3.7.3E") flag = 1;
else if (version == "3.7.0E") flag = 1;
else if (version == "3.7.1E") flag = 1;
else if (version == "3.7.2E") flag = 1;
else if (version == "3.7.0S") flag = 1;
else if (version == "3.7.1S") flag = 1;
else if (version == "3.7.2S") flag = 1;
else if (version == "3.7.2tS") flag = 1;
else if (version == "3.7.3S") flag = 1;
else if (version == "3.7.4S") flag = 1;
else if (version == "3.7.4aS") flag = 1;
else if (version == "3.7.5S") flag = 1;
else if (version == "3.7.6S") flag = 1;
else if (version == "3.7.7S") flag = 1;
else if (version == "3.8.0S") flag = 1;
else if (version == "3.8.1S") flag = 1;
else if (version == "3.8.2S") flag = 1;
else if (version == "3.9.0S") flag = 1;
else if (version == "3.9.0aS") flag = 1;
else if (version == "3.9.1S") flag = 1;
else if (version == "3.9.1aS") flag = 1;
else if (version == "3.9.2S") flag = 1;
else if (version == "3.10.0S") flag = 1;
else if (version == "3.10.1S") flag = 1;
else if (version == "3.10.1xbS") flag = 1;
else if (version == "3.10.2S") flag = 1;
else if (version == "3.10.2tS") flag = 1;
else if (version == "3.10.3S") flag = 1;
else if (version == "3.10.4S") flag = 1;
else if (version == "3.10.5S") flag = 1;
else if (version == "3.10.6S") flag = 1;
else if (version == "3.10.7S") flag = 1;
else if (version == "3.11.0S") flag = 1;
else if (version == "3.11.1S") flag = 1;
else if (version == "3.11.2S") flag = 1;
else if (version == "3.11.3S") flag = 1;
else if (version == "3.11.4S") flag = 1;
else if (version == "3.12.0S") flag = 1;
else if (version == "3.12.0aS") flag = 1;
else if (version == "3.12.1S") flag = 1;
else if (version == "3.12.4S") flag = 1;
else if (version == "3.12.2S") flag = 1;
else if (version == "3.12.3S") flag = 1;
else if (version == "3.13.2aS") flag = 1;
else if (version == "3.13.5aS") flag = 1;
else if (version == "3.13.5S") flag = 1;
else if (version == "3.13.0S") flag = 1;
else if (version == "3.13.0aS") flag = 1;
else if (version == "3.13.1S") flag = 1;
else if (version == "3.13.2S") flag = 1;
else if (version == "3.13.3S") flag = 1;
else if (version == "3.13.4S") flag = 1;
else if (version == "3.14.0S") flag = 1;
else if (version == "3.14.1S") flag = 1;
else if (version == "3.14.2S") flag = 1;
else if (version == "3.14.3S") flag = 1;
else if (version == "3.15.1cS") flag = 1;
else if (version == "3.15.0S") flag = 1;
else if (version == "3.15.1S") flag = 1;
else if (version == "3.15.2S") flag = 1;
else if (version == "3.17.1aS") flag = 1;
else if (version == "3.17.0S") flag = 1;
else if (version == "3.17.1S") flag = 1;
else if (version == "16.1.1") flag = 1;
else if (version == "16.1.2") flag = 1;
else if (version == "3.16.2bS") flag = 1;
else if (version == "3.16.0S") flag = 1;
else if (version == "3.16.0cS") flag = 1;
else if (version == "3.16.1S") flag = 1;
else if (version == "3.16.1aS") flag = 1;
else if (version == "3.16.2S") flag = 1;
else if (version == "3.16.2aS") flag = 1;

cmds = make_list();
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config | include ip msdp peer", "show running-config | include ip msdp peer");
    if (check_cisco_result(buf))
    {
      # Vulnerable if msdp enabled
      if (preg(pattern:"\s*ip\s*msdp\s*peer\s*[0-9]{1,3}(\.[0-9]{1,3}){3}", multiline:TRUE, string:buf))
      {
        flag = 1;
        cmds = make_list(cmds, "show running-config | include ip msdp peer");
      }

      buf2 = cisco_command_kb_item("Host/Cisco/Config/show_running-config | include include ipv6 multicast-routing", "show running-config | include ipv6 multicast-routing");
      if (check_cisco_result(buf2))
      {
        # Vulnerable if ipv6 multicast routing enabled
        if (preg(pattern:"\s*ipv6\s*multicast-routing", multiline:TRUE, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, "show running-config | include ipv6 multicast-routing");
        }
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCud36767, CSCuy16399",
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
