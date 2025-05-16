#TRUSTED aa8c2f4ea389117d9b71fd69fee7eea89c6db7e1c8f91b0d3a02f34d97cf709fd43b7fc23fc694ea96d04c4d7fa0a6a5bc57fa47ae3b1306f0d708fd7ec73fa95a59a588bbfa73cf97705ca9f5b66b2c95809bf08430b7cc58e043ce03838d7f1c60fad99e7edab05da04ae2aab9f5d5842c3eca3446a73be83c958c6599f761c9036f49db4b9464c4f08b4fb1d5950a07ca45c68078ea4eaec760119dd7032178d6f611918908b5ad1be7a60a400a68e11a8e04a26e74381be2f6fe4d489756777a4ab19b191fa08cc98ce17da53eab150558e541d30664b6e5962c64d176bfeb86776d4350c7183866d0f364c4b8cab4192d544d93de464324c1df51ac803a8d70a5d4a93d49c7f6179bcca59f6a452dc03315ef916b7fc7cbedbe89d35bce274a261e95a1f53e3d362cdae840a59bc997649f7d6101d0a90cd6d38e35d606e14581853334f85bd1445a61ee492a356f1aeb23a2ce34f10a9cbfcfc28a94c7f8e7207d23cb560fb53e0532a0a6952144da00a69ec0ae8aeb650f974f564ddd2ed0bde9f8a8239317c8d9d944c868a3f5564e621325312815354352ada6be0805f1d192cbf7c3d65fc83e447983bff34b4ba98b70b42beff1f2da751ee67a0ea27058598e2d34dd252f13fe46b46f3ef51d8b41d09685a166d66b817f9f759bc5f925063d1e6b21809ffb2454b930efaa30ac4c8a699d8dab7c6bb5326e25d3
#TRUST-RSA-SHA256 6625806acd10b2dd72cd23b9e62fc7048da9093b540f7750d88cfc79223a02b3854f16f3334f168b2bb1ed61b82dc4481133cea9707bdbfb0fca8d5ea930c630f38a8ddc35a8684b3764406a3b7459df41a08160ac9b67002fe8223288a2e6fb764ac0fbd075e635cba3b7116996dc18ac1200d269a2876570c40d4690177a7e21c0a52420fc4bdc74018651dcc3ea4bc95ce5c68a0bb06bbb1f1f7d1ee20f150dd3c2c7c31c45d17767cd99be1d29c0fe8ee32c3a06784521c52826596d34dac57048adc1610cad783fee4a1bdd80e6ab85a71a7bf8191e2428cab45888eeb47141138d4b5def1d18cdb1a4596e051c3b30ae309afb4e13001ac988cb2506d8f6d61345b051fcc5cc9a02c484c35491fe07c6fcdbd6a9b74973a9a5f2a9fcf52bb71ffd6d90a7f9fe001e1142339bb027b8d26a667ef888f316f77680625a5b92f555de57e8f1852720baf56c6feab867b99d19de4795028c992d2864afd2fa1884bc85092df120eb63dee40dd28662e2290093a37862445eb2f4ada03cb57858cee8bc67b8737cbd8e3fa1192c004ab3a78c2dcc4caaa91e33ef72610bdec5c58fa3d3c7358bb002abc2081e8a4b4673d0601aa453323e0b05aa48d268dd9df6e541ff28e56e073ccff9af4c6a1b0ad1388ed533dda9d1cb1e946ac7da0aa8b88ec4e69fab4300fa807eb40e3b8cb6664231311d96f243b00f9fcedfe681ad
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99027);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-3864");
  script_bugtraq_id(97012);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu43892");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-dhcpc");

  script_name(english:"Cisco IOS XE DHCP Client DoS (cisco-sa-20170322-dhcpc)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the DHCP client implementation when parsing DHCP
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted DHCP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-dhcpc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d54a2ce");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu43892");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu43892.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;

if (
  ver == '3.3.0SE' ||
  ver == '3.3.0XO' ||
  ver == '3.3.1SE' ||
  ver == '3.3.1XO' ||
  ver == '3.3.2SE' ||
  ver == '3.3.2XO' ||
  ver == '3.3.3SE' ||
  ver == '3.3.4SE' ||
  ver == '3.3.5SE' ||
  ver == '3.5.0E' ||
  ver == '3.5.1E' ||
  ver == '3.5.2E' ||
  ver == '3.5.3E' ||
  ver == '3.6.0E' ||
  ver == '3.6.1E' ||
  ver == '3.6.2aE' ||
  ver == '3.6.2E' ||
  ver == '3.6.3E' ||
  ver == '3.6.4E' ||
  ver == '3.7.0E' ||
  ver == '3.7.1E' ||
  ver == '3.7.2E' ||
  ver == '3.7.3E'
)
{
  flag++;
}

cmds = make_list();
# Check that device is configured as a DHCP client
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include dhcp", "show running-config | include dhcp");
  if (check_cisco_result(buf))
  {
    if ("ip address dhcp" >< buf)
    {
      cmds = make_list(cmds, "show running-config | include dhcp");
      # Check if device is configured as a DHCP server or DHCP relay agent
      buf2 =  cisco_command_kb_item("Host/Cisco/Config/show running-config | include helper|(ip dhcp pool)", "show running-config | include helper|(ip dhcp pool)");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"ip helper-address [0-9\.]+", string:buf2))
        {
          cmds = make_list(cmds,"show running-config | include helper|(ip dhcp pool)");
          # Check if device is configured to send DHCP Inform/Discover messages
          # If device is confiured to send DHCP Inform and Discover messages
          # then not vuln
          buf3 = cisco_command_kb_item("Host/Cisco/Config/show running-config | include (ip dhcp-client network-discovery)", "show running-config | include (ip dhcp-client network-discovery)");
          if (check_cisco_result(buf3))
          {
            if (preg(multiline:TRUE, pattern:"ip dhcp-client network-discovery informs .* discovers .*", string:buf3))
            {
              flag = 0;
            }
            else
            {
              flag = 1;
              cmds = make_list(cmds,"show running-config | include (ip dhcp-client network-discovery)");
            }
          }
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuu43892",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
