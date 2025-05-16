#TRUSTED 9c92461fc34c87da70f739e1ebee2d6d0bb54beb49a8872e496ac2f4d1cc43757291509c5c6c7c71db77c2ae7249f3b4916e55ca5c7e5ea1eafe1af44c649fb80816ca9fa2a20728c1ac309af6cdc255ec82144d8af3200ea4802ed1c34165eb9939a99fdb22c61c69ce19aa0e9cb024f8357af7707aa86aad6d014c3ea10f9c370bea303973b8d06cdb9e69ada61e9f3ea15294ba5a2652f2e108e47aa10313f841e274a399f406a272530b7fe1d85c4c630324a4f899eadcec9a73ae38a620292e664dff86e7b3f30614521217e16bbdebb5e4316e2e414f0ecd1c8d88dc04ec7028217a0dd22c21c56ceb58328d7a4ece8491b6e66faf10ae55ffdf5056aee764e68e5909d843d64b9ffe6b85f265db71e6780008b297bbd5421ac5cb90ffe3021c76001084f4aaa4cd871364e85b26dc650a8b2a243cebe94c815ccf5e39ef26f9c2c5fd161c99451b407a94ae357d2a1c130853abefec7070b253a0c12bde0eb02f450116b0a35cd7b7a4cf3955fbb28ac94e08d9f38b2a6b47350a3f96e67601c1b58edf027c466a17a62100947d6dd0a71faf74d54f35d7feef1d6b45bebec0d7c9e445df70dd70fd4dc92a75f85ac5835efb5b78fa74abfee2e271d40b86a08175cb21ac9af760bfab6fa6d2d610b89e59f339694c0ff8d543e35a4b629a54d8a3103152c1234becdeb70989b84e435d07e77498197e3a01c841e07b
#TRUST-RSA-SHA256 33dad10d8295536245a4d7aea913eb3b982c136f06ffe6d64e3dbeecb251bf01f6f1131b6babd30ab33d6daf14cde82023a6b0a5774ccd9bf1e6a9afa0775d6e4f086c21579f5c10ccb4939ce92e7c0448a89520523b0d01a102da5fd40d2b3d2697e669f97db76af22b51bb20ff0be463e473b3398a727efb84bf3b0b27962995212be9622443a275190f0a6477b2f500e1e4a543a41019c82bc605be6715fb450d6c81c0b27d361724d66ac43b45685414befce55b4639e2a72d1cbb29adb93a8e091d97b7a6af83035b5c7ec06a3fba7fde0b339521b2d85a31ee7f2fbe8bfccffaba0987704452b73bd6111b6532e03a87fdf1ef37d3a66b03b562bd11bdd764a294098655b61baa30375f2dd42115579e5981c521060cb978f22abbd53a1115b9ed0bea734e43082d07c435f598eba0f445aac731704068c76f91357494394bb0c35c276cd876281b6d2a2807f2535822fc30e502244f492037d955d50a22f40d57ee7c6ad17b6dc0a856362bc25a83903174b430a2581765745ed217cb0c0980a09a54b5e1bd48c82ffa16a28c2daaf3193f737d64d86f12d4245f484c8c34e83bf89aa2fcc25b97820f57d761b56be05c665ac5cb3185c923708e20b9d7d8353015126ab9d174e947a9e7c70a2a5d189e5ecbbea76a6bf93811c3648f9f1b947d5f8f3dc4b1ef81dc3a907ca65966698f0558dba233172e6acf6277cb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94763);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-6381");
  script_bugtraq_id(93195);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy47382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-ios-ikev1");

  script_name(english:"Cisco IOS XE IKEv1 Fragmentation DoS (cisco-sa-20160928-ikev1)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by a denial
of service vulnerability in the Internet Key Exchange version 1
(IKEv1) subsystem due to improper handling of fragmented IKEv1
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted IKEv1 packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ios-ikev1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30c88959");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy47382. Alternatively, as a workaround, IKEv2 fragmentation can be
disabled by using the 'no crypto isakmp fragmentation' command.
However, if IKEv1 fragmentation is needed, there is no workaround that
addresses this vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/14");

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
cmds = make_list();

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
else if ( ver == "3.3.0XO" ) flag++;
else if ( ver == "3.3.1S" ) flag++;
else if ( ver == "3.3.1SG" ) flag++;
else if ( ver == "3.3.1XO" ) flag++;
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
else if ( ver == "3.6.3E" ) flag++;
else if ( ver == "3.6.4E" ) flag++;
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
else if ( ver == "3.7.5S" ) flag++;
else if ( ver == "3.7.6S" ) flag++;
else if ( ver == "3.7.7S" ) flag++;
else if ( ver == "3.8.0E" ) flag++;
else if ( ver == "3.8.0S" ) flag++;
else if ( ver == "3.8.1E" ) flag++;
else if ( ver == "3.8.1S" ) flag++;
else if ( ver == "3.8.2S" ) flag++;
else if ( ver == "3.9.0aS" ) flag++;
else if ( ver == "3.9.0S" ) flag++;
else if ( ver == "3.9.1aS" ) flag++;
else if ( ver == "3.9.1S" ) flag++;
else if ( ver == "3.9.2S" ) flag++;
else if ( ver == "3.10.0S" ) flag++;
else if ( ver == "3.10.1S" ) flag++;
else if ( ver == "3.10.1xbS" ) flag++;
else if ( ver == "3.10.2S" ) flag++;
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
else if ( ver == "3.13.5S" ) flag++;
else if ( ver == "3.14.0S" ) flag++;
else if ( ver == "3.14.1S" ) flag++;
else if ( ver == "3.14.2S" ) flag++;
else if ( ver == "3.14.3S" ) flag++;
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
else if ( ver == "3.18.0S" ) flag++;
else if ( ver == "16.1.1" ) flag++;
else if ( ver == "16.1.2" ) flag++;

if(!flag)
  audit(AUDIT_INST_VER_NOT_VULN, ver);

# Check that IKEv1 config or IKEv1 is running
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv1 config
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if ( "crypto isakmp fragmentation" >< buf )
    {
      flag = 1;
      cmds = make_list('show running-config');
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

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|4500)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:pat, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, 'show ip sockets');
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
        if (preg(multiline:TRUE, pattern:pat, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, 'show udp');
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
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCuy47382',
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
