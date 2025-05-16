#TRUSTED 08d13d96cc22a0e63fc8ee96502f9e8c1affc84e7699a72097365e54b9a269ec1b97198d6456509d273466eada2ae70db3d515bae50bd102ee2f2367d096f5ece4afa0bcf9e685b5482009e9a7eb769130622390d0d36c66f1203b981ceffaefeee3864b6c88adb6ea696be1e0b40728684ab6f2d0aba00270073dc537979d316609728b4701d54977da89738858d997b903cc10368407c8e835884f7c086d39aac352c9c26f5ad535cfd1b74fabcf68a9319ba5889b74b226cb43c29786c4aaa8b3690508a5440e6d99dce519244b77773b3610cf6533ec85c6e1640f1c59adae0764c29d1c855b6b35c254715d619f0024b21474e7f7ef5f16ad3df8b3f08be02a4a32c3f2af0d745a356c7933b7456f1c7eb3697070beb4d2850583407c8f30941386281e56471c5da6026d152f72878e314799eb45b49bdbefb9db49ef4216f879372ef37d10eb65800f751deae7712b471b954f1e0eaf8d67d9da32b2aeda9ac1166b0b49fa1b17c5370e576b43452914124ee41b3794b843c871d78ade2ddefd35f45d59c304810782f7cb1915f28280457b74c0a87a14d85d390f1d4075ef44d1c9ce0b0188a55770e94cef9203f1f7c96a138a982160bfa856901b20fc2c6c81fb8bff51a3faf77414d2444bc41678c17705fdf9eccfa71dabf6f0cfcc2dc5d6ae15fcb6c63dc5b74b4b884d0eb5f2afdd8922e1e3c7959947f832f8
#TRUST-RSA-SHA256 471d5ac416f010ec60a8d4830079894e5318e1642d4a2e6c3c348557fc131a113f05c7fa40cdc1c2236d1faffb89049f73c4b8ab6b316681629467cece1c0aff888a9112ab65f1dccfa90e5fc42952326f0e2a67f2a5468135534c50037ab71498956b23d997908bab90ff4c0f2d4f5e2924d6e015f584b4f2ea1ae196d53778a1580b6df4f00e41c67351eee27d75cd37ebd35a107bea3f950e192c7f9770a8de5a34c777ef441fbacc086043517c85994f74cb7c7c4dc5446ea49788545e8dda57bfadc4884d426e47af412ec995de5170ef14b870d57d030b448f8d912557dbe70f57ffa221c7cf97e1be979b374e8c8d8ad921b5f82a504eb2b24467bfa3a86e361c79c18d0303f6b60cce5692a384357373e8e2b6a6f9fd69e90bcbe435602ca67b5ddba222b9c9f056b8d6ac5d69fbfed1fe29d71674bc2585374931b582d3f87e3790ca0ed44128da761957224a658169fa9548fb93a4f818f317811cd6417ae897f38eade16d1f2edc8d38f8572243e0a145324bacc23796fd44030961e29907e5f5d263eab6e01cdd5d37a5d498148283058aa7343eef0fb6752ede226e1ee24554e2bc31b0520bf177fdedf2c798757431675cffa39243d860f74cc90f558e045e9c6de29c9dd0ee87a13fdbe215ce6c9b0b8a3db301f9472af1cce08996ff74483b5bf8e78475eb398a8f7f4eddb0c0b1523586bf89c02a1f2c2c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93737);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-6415");
  script_bugtraq_id(93003);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb29204");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160916-ikev1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/09");

  script_name(english:"Cisco IOS XE IKEv1 Packet Handling Remote Information Disclosure (cisco-sa-20160916-ikev1) (BENIGNCERTAIN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by an
information disclosure vulnerability, known as BENIGNCERTAIN, in the
Internet Key Exchange version 1 (IKEv1) subsystem due to improper
handling of IKEv1 security negotiation requests. An unauthenticated,
remote attacker can exploit this issue, via a specially crafted IKEv1
packet, to disclose memory contents, resulting in the disclosure of
confidential information including credentials and configuration
settings.

BENIGNCERTAIN is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7f2c76c");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"see_also", value:"https://blogs.cisco.com/security/shadow-brokers");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb29204.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6415");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/27");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

# Check for vuln version
if ( ver == "3.1.0S" ) flag++;
else if ( ver == "3.1.1S" ) flag++;
else if ( ver == "3.1.2S" ) flag++;
else if ( ver == "3.1.3aS" ) flag++;
else if ( ver == "3.1.4aS" ) flag++;
else if ( ver == "3.1.4S" ) flag++;
else if ( ver == "3.2.1S" ) flag++;
else if ( ver == "3.2.2S" ) flag++;
else if ( ver == "3.3.0S" ) flag++;
else if ( ver == "3.3.0SG" ) flag++;
else if ( ver == "3.3.1S" ) flag++;
else if ( ver == "3.3.1SG" ) flag++;
else if ( ver == "3.3.2S" ) flag++;
else if ( ver == "3.3.2SG" ) flag++;
else if ( ver == "3.4.0aS" ) flag++;
else if ( ver == "3.4.0S" ) flag++;
else if ( ver == "3.4.0SG" ) flag++;
else if ( ver == "3.4.1S" ) flag++;
else if ( ver == "3.4.1SG" ) flag++;
else if ( ver == "3.4.2S" ) flag++;
else if ( ver == "3.4.2SG" ) flag++;
else if ( ver == "3.4.3S" ) flag++;
else if ( ver == "3.4.3SG" ) flag++;
else if ( ver == "3.4.4S" ) flag++;
else if ( ver == "3.4.4SG" ) flag++;
else if ( ver == "3.4.5S" ) flag++;
else if ( ver == "3.4.5SG" ) flag++;
else if ( ver == "3.4.6S" ) flag++;
else if ( ver == "3.4.6SG" ) flag++;
else if ( ver == "3.4.7SG" ) flag++;
else if ( ver == "3.5.0E" ) flag++;
else if ( ver == "3.5.0S" ) flag++;
else if ( ver == "3.5.1E" ) flag++;
else if ( ver == "3.5.1S" ) flag++;
else if ( ver == "3.5.2E" ) flag++;
else if ( ver == "3.5.2S" ) flag++;
else if ( ver == "3.5.3E" ) flag++;
else if ( ver == "3.6.0E" ) flag++;
else if ( ver == "3.6.0S" ) flag++;
else if ( ver == "3.6.1E" ) flag++;
else if ( ver == "3.6.1S" ) flag++;
else if ( ver == "3.6.2aE" ) flag++;
else if ( ver == "3.6.2E" ) flag++;
else if ( ver == "3.6.2S" ) flag++;
else if ( ver == "3.6.4E" ) flag++;
else if ( ver == "3.6.5E" ) flag++;
else if ( ver == "3.7.0E" ) flag++;
else if ( ver == "3.7.0S" ) flag++;
else if ( ver == "3.7.1E" ) flag++;
else if ( ver == "3.7.1S" ) flag++;
else if ( ver == "3.7.2E" ) flag++;
else if ( ver == "3.7.2S" ) flag++;
else if ( ver == "3.7.2tS" ) flag++;
else if ( ver == "3.7.3E" ) flag++;
else if ( ver == "3.7.3S" ) flag++;
else if ( ver == "3.7.4aS" ) flag++;
else if ( ver == "3.7.4S" ) flag++;
else if ( ver == "3.7.5E" ) flag++;
else if ( ver == "3.7.5S" ) flag++;
else if ( ver == "3.7.6S" ) flag++;
else if ( ver == "3.7.7S" ) flag++;
else if ( ver == "3.8.0E" ) flag++;
else if ( ver == "3.8.0S" ) flag++;
else if ( ver == "3.8.1E" ) flag++;
else if ( ver == "3.8.1S" ) flag++;
else if ( ver == "3.8.2E" ) flag++;
else if ( ver == "3.8.2S" ) flag++;
else if ( ver == "3.9.0aS" ) flag++;
else if ( ver == "3.9.0E" ) flag++;
else if ( ver == "3.9.0S" ) flag++;
else if ( ver == "3.9.1aS" ) flag++;
else if ( ver == "3.9.1S" ) flag++;
else if ( ver == "3.9.2S" ) flag++;
else if ( ver == "3.10.0S" ) flag++;
else if ( ver == "3.10.1S" ) flag++;
else if ( ver == "3.10.1xbS" ) flag++;
else if ( ver == "3.10.2S" ) flag++;
else if ( ver == "3.10.2tS" ) flag++;
else if ( ver == "3.10.3S" ) flag++;
else if ( ver == "3.10.4S" ) flag++;
else if ( ver == "3.10.5S" ) flag++;
else if ( ver == "3.10.6S" ) flag++;
else if ( ver == "3.10.7S" ) flag++;
else if ( ver == "3.11.0S" ) flag++;
else if ( ver == "3.11.1S" ) flag++;
else if ( ver == "3.11.2S" ) flag++;
else if ( ver == "3.11.3S" ) flag++;
else if ( ver == "3.11.4S" ) flag++;
else if ( ver == "3.12.0aS" ) flag++;
else if ( ver == "3.12.0S" ) flag++;
else if ( ver == "3.12.1S" ) flag++;
else if ( ver == "3.12.2S" ) flag++;
else if ( ver == "3.12.3S" ) flag++;
else if ( ver == "3.12.4S" ) flag++;
else if ( ver == "3.13.0aS" ) flag++;
else if ( ver == "3.13.0S" ) flag++;
else if ( ver == "3.13.1S" ) flag++;
else if ( ver == "3.13.2aS" ) flag++;
else if ( ver == "3.13.2S" ) flag++;
else if ( ver == "3.13.3S" ) flag++;
else if ( ver == "3.13.4S" ) flag++;
else if ( ver == "3.13.5aS" ) flag++;
else if ( ver == "3.13.5S" ) flag++;
else if ( ver == "3.13.6aS" ) flag++;
else if ( ver == "3.13.6S" ) flag++;
else if ( ver == "3.14.0S" ) flag++;
else if ( ver == "3.14.1S" ) flag++;
else if ( ver == "3.14.2S" ) flag++;
else if ( ver == "3.14.3S" ) flag++;
else if ( ver == "3.14.4S" ) flag++;
else if ( ver == "3.15.0S" ) flag++;
else if ( ver == "3.15.1cS" ) flag++;
else if ( ver == "3.15.1S" ) flag++;
else if ( ver == "3.15.2S" ) flag++;
else if ( ver == "3.15.3S" ) flag++;
else if ( ver == "3.16.0cS" ) flag++;
else if ( ver == "3.16.0S" ) flag++;
else if ( ver == "3.16.1aS" ) flag++;
else if ( ver == "3.16.1S" ) flag++;
else if ( ver == "3.16.2aS" ) flag++;
else if ( ver == "3.16.2S" ) flag++;
else if ( ver == "3.17.0S" ) flag++;
else if ( ver == "3.17.1S" ) flag++;
else if ( ver == "3.17.2S" ) flag++;
else if ( ver == "3.18.0S" ) flag++;
else if ( ver == "3.18.1S" ) flag++;
else if ( ver == "3.18.2S" ) flag++;

# Check that IKEv1 config or IKEv1 is running
cmd_list = make_list();
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv1 config
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if (
      "crypto gdoi" >< buf
      ||
      "crypto map" >< buf
      ||
      "tunnel protection ipsec" >< buf
    )
    {
      flag = 1;
      cmd_list = make_list("show running-config");
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv1 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500|4848)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        )
        {
          flag = 1;
          cmd_list = make_list(cmd_list, "show ip sockets");
        }
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }

    if (!flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        )
        {
          flag = 1;
          cmd_list = make_list(cmd_list, "show udp");
        }
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : ver,
    bug_id   : 'CSCvb29204',
    cmds     : cmd_list
  );
}
else audit(AUDIT_HOST_NOT, "affected");
