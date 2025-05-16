#TRUSTED 983bc3323f61c2040494cc2d6dbb2d8bd955d84489d281570446b3ec8e95514626a6c96d4b91efe0b92d946552731f5804106bd28ea151e33f99b606882aa33d0f89a0c5fc11957e920a68950ecd2bce80f4f4192d8a56b52b494d2d2487a50cdcdfbd2452e3440cd50c5e8ea0573bd06f2ad2c05680d8ad586b44d7f02caa0012109fb7d8a3ff334b1079330e8cb598ec9491795f9d8775b3285fd4b3cf89aa080a92deb2b5c93a1f82862ec007244dcbb8ecc44831f8168a3bfff62af57eb7ac344254ea61ae4d0ca8ba455162ac35c968789806a78451af4cca41080ee5f5273cdf58097c660da14549721e79024edc80d242d2bf9c99d3a73c1f942d7644d8949670ef9090b08868076b16efcf28a6b1f4aabd9567f2226376aa108dd5a1957cf1239f05af935723d83cccbe39223563494f37f458f87a5a13b0da22b98f0b5ed65e2e2ea7d93f76ff8c5237d1c737932d8b6a740abc90db8eec5264a76cb75cc8b864e8fc1131e1ffc26c91d277f5c1b7481f91b44e60016d48bc5717049fa3ce3e41f74c0314bc45f47858434e2a8f8d3d5746dafefcc24b5cc8e2340b3d275d9bd1d9440caa2adb9ea33a53fed4cb3317814a08a1d69e924ef24481af7a11efb8fb035dbe6f2936c97c10e1ee8033aebf6db04d8310638c78451633c10eafddde38b68fecb0c6840b2a6c6d82f859fa56dcdad412d25a549615991311
#TRUST-RSA-SHA256 3786a46df73b7fe2d36ddc4391f21d7d7c390348d533ae000b52b045921dcaa817e42b992fdcec9cd4ca4c0204d246166714be2cfda209de82e803024de4c6b92275f23eab7bad91d5d9bcf4ebe6792c9631f90a9f0f3d42ed8ef13784c967f3b4e7e5c5a480aaacf4d6e760bcc54e58550cae2687e11c05d8e67f6797482ffaed7352d060e76f63542e35a71c1dfc978d1bd4879f4c4cc859c46823930b9cbeb6701f3d8e59b016418a570e671e5415c48db97724167edacd55162dd0d8e4f4d370cfe565499eed89532a599ab38b720f5b75b668ed97a98e2719d5b01c718c61ed68d4f207a44286f8b2321b89b73cf80163e5b353e2dd0110b23993ecd26e876be2bb549c3430e7feff1c4ae9a64cee841dc5889c2c8e4a8369f9711b7fa306083e2becac0a20b08c64e4bc00b2a1f531c0dec174126a9afcf2eb633c1503afa0bd3b8707bc7ef06a27da0be9f5d83606c596db0f82c98349652a99b5662d4c94d1ba731d7b640eb77751d7d9ff4e69316454176cc13a2a682906402372d1653ed34ef86abaebe3c50a8defa4268b5a85c65ab1b3d488d3713d1b04ba8e64942e900e6270d1d0b9d2fb568afccc25eaa20124362c3467929fc3b4b2ab61db3b4fbe6d580f2d357f0e2dd33b4728c288579c09941114a526288ad2611cef5c3e6b06e7ba06116d97f38d3871b47e0a872b6b7a484ff23c129a27f24a924dbd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90356);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2016-1344");
  script_xref(name:"TRA", value:"TRA-2016-06");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux38417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-ios-ikev2");

  script_name(english:"Cisco IOS XE IKEv2 Fragmentation DoS (cisco-sa-20160323-ios-ikev2)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Internet Key Exchange version 2 (IKEv2) subsystem
due to improper handling of fragmented IKEv2 packets. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted UDP packets, to cause the device to reload.

Note that this issue only affects devices with IKEv2 fragmentation
enabled and is configured for any VPN type based on IKEv2.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ios-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9feec3b3");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux38417. Alternatively, apply the workaround as referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1344");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

fix = '';
flag = 0;

# Check for vuln version
if ( ver == '3.8.0E' ) flag++;
if ( ver == '3.8.1E' ) flag++;
if ( ver == '3.3.0S' ) flag++;
if ( ver == '3.3.1S' ) flag++;
if ( ver == '3.3.2S' ) flag++;
if ( ver == '3.3.0SG' ) flag++;
if ( ver == '3.3.1SG' ) flag++;
if ( ver == '3.3.2SG' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.4.0S' ) flag++;
if ( ver == '3.4.0aS' ) flag++;
if ( ver == '3.4.1S' ) flag++;
if ( ver == '3.4.2S' ) flag++;
if ( ver == '3.4.3S' ) flag++;
if ( ver == '3.4.4S' ) flag++;
if ( ver == '3.4.5S' ) flag++;
if ( ver == '3.4.6S' ) flag++;
if ( ver == '3.4.0SG' ) flag++;
if ( ver == '3.4.1SG' ) flag++;
if ( ver == '3.4.2SG' ) flag++;
if ( ver == '3.4.3SG' ) flag++;
if ( ver == '3.4.4SG' ) flag++;
if ( ver == '3.4.5SG' ) flag++;
if ( ver == '3.4.6SG' ) flag++;
if ( ver == '3.4.7SG' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.5.0S' ) flag++;
if ( ver == '3.5.1S' ) flag++;
if ( ver == '3.5.2S' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.6.3E' ) flag++;
if ( ver == '3.6.0S' ) flag++;
if ( ver == '3.6.1S' ) flag++;
if ( ver == '3.6.2S' ) flag++;
if ( ver == '3.7.3E' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;
if ( ver == '3.7.0S' ) flag++;
if ( ver == '3.7.1S' ) flag++;
if ( ver == '3.7.2S' ) flag++;
if ( ver == '3.7.2tS' ) flag++;
if ( ver == '3.7.3S' ) flag++;
if ( ver == '3.7.4S' ) flag++;
if ( ver == '3.7.4aS' ) flag++;
if ( ver == '3.7.5S' ) flag++;
if ( ver == '3.7.6S' ) flag++;
if ( ver == '3.7.7S' ) flag++;
if ( ver == '3.8.0S' ) flag++;
if ( ver == '3.8.1S' ) flag++;
if ( ver == '3.8.2S' ) flag++;
if ( ver == '3.9.0S' ) flag++;
if ( ver == '3.9.0aS' ) flag++;
if ( ver == '3.9.1S' ) flag++;
if ( ver == '3.9.1aS' ) flag++;
if ( ver == '3.9.2S' ) flag++;
if ( ver == '3.10.0S' ) flag++;
if ( ver == '3.10.1S' ) flag++;
if ( ver == '3.10.1xbS' ) flag++;
if ( ver == '3.10.2S' ) flag++;
if ( ver == '3.10.3S' ) flag++;
if ( ver == '3.10.4S' ) flag++;
if ( ver == '3.10.5S' ) flag++;
if ( ver == '3.10.6S' ) flag++;
if ( ver == '3.11.0S' ) flag++;
if ( ver == '3.11.1S' ) flag++;
if ( ver == '3.11.2S' ) flag++;
if ( ver == '3.11.3S' ) flag++;
if ( ver == '3.11.4S' ) flag++;
if ( ver == '3.12.0S' ) flag++;
if ( ver == '3.12.1S' ) flag++;
if ( ver == '3.12.4S' ) flag++;
if ( ver == '3.12.2S' ) flag++;
if ( ver == '3.12.3S' ) flag++;
if ( ver == '3.13.2aS' ) flag++;
if ( ver == '3.13.0S' ) flag++;
if ( ver == '3.13.0aS' ) flag++;
if ( ver == '3.13.1S' ) flag++;
if ( ver == '3.13.2S' ) flag++;
if ( ver == '3.13.3S' ) flag++;
if ( ver == '3.13.4S' ) flag++;
if ( ver == '3.14.0S' ) flag++;
if ( ver == '3.14.1S' ) flag++;
if ( ver == '3.14.2S' ) flag++;
if ( ver == '3.14.3S' ) flag++;
if ( ver == '3.15.1cS' ) flag++;
if ( ver == '3.15.0S' ) flag++;
if ( ver == '3.15.1S' ) flag++;
if ( ver == '3.15.2S' ) flag++;
if ( ver == '3.17.0S' ) flag++;
if ( ver == '3.16.0S' ) flag++;
if ( ver == '3.16.0cS' ) flag++;
if ( ver == '3.16.1S' ) flag++;
if ( ver == '3.16.1aS' ) flag++;

# Check that IKEv2 fragmentation or IKEv2 is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv2 fragmentation
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if ("crypto ikev2 fragmentation" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv2 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        ) flag = 1;
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
        ) flag = 1;
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
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux38417' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
