#TRUSTED 471f233ed7b1df88d21016b9a36240690c568e76628444b047644f67a187aa4e4d5b4d4fec2ec72934d7cf1d11048301481d3905ef6e946795f430334541c5687853d0ab6e5ff561bef379737ceb60ac05735aa7bac9e92f6a7815cf6e4a7a9ae6733e72e3649011795a838ddf3b6c4c02819f23deb031af208f0d9d7b158c5eab2078f07d8e33bdc741cece9cda59c088830fb5098d4cba8d44dc338e9006a7190d122060da845d56abb10b32cb38322e5db17be58d420c0199ec09a5e791c236f6a872aaec12d2fcfe91a318dd4a6bc53ae1dd8be67020e5ac294b7bebe988841f3c3205ead88bdf5ef147231518eb3d26bc7ab6687fcb6cd8c8cbe64f1c53783a560da7b7587c0837c39c2da6c146295e1481f3d2c6611d9e3409a2a9d01ea51158a4a65f2f0280e848226b00808b53e48ce9f20296d141775b561576a8d0f61133df075fb4205fd62959a361878d175a9e45061c431ec4b86d4125a836549323703ee42e935bd185f944dc59808056cbf03e1b97674a05a47e20cb4081d03a269463de1322ca3bd4f07573f0732b87a90b531cc6e813d48c9322c54f66f778ccbf01fbadf642560a322e65990d10b250f490ff529fee0e13d8b01406bf18ca823f7aa6dabcd3bfb32cbfe2b469e577550cb9370420e9fd22b362a23600da7059c81814e963b6fcecafb170be1d31b0f4f57165f69ea76ba75df4580db18f
#TRUST-RSA-SHA256 6f8a20ba62a2bdf22fafd3194080d74ac3e449b20e786c4fa9a488baa75be95b3950fa9e9a9ca93dd3a04abfa09490cfe25a3a41e29653883ac4b0a88b374cd75c64ba604f4c15042018775aa2772e7ef170ecd036ade9a20af9e6797ac86ca32477a9af74c0b7e084bef1128c73d372c6e9a1e1506f7899decb73533ce621d37bd918b2b81ce1a440ea75cc04490e94b152be8ba51326e66b4d73b16a0f54a175f3865cd7576722e1d20bcd68475676e4da16c51aae90ef57493df6941ae7bf95c9ab0b4465d058b89f79ac4ffde3cfe09781ab06d07116e170f6ac6faacd785f61cf2cbf02e0ca9e4ee364e728e2e8dab1a517d744e3c33abcb80a76f6d2ad7d8152586460abbaebdb6c2c39bb4455bf4ff01ce8102f2b77170cf7220eeeaeaf6bdc9dad4047283f117229b6663c05b66cd7611482b8ea92016db34933bebd43cf6cb753665f6ae60e1d0799fdac2345eeaa9533d78cd5b5cce3731fefae1019a14d8e44dc7a31d25e0e4b94c40513ef08860efe710f41c7fff7218b725196f3f768999a12c078ab8f1e35d79772bf0ef376d0f596c7d918f29d217dfdfa1ddfd53601be731ea202f706503afe65a987385008133c750d1e0d9415d64d9493066213a5f70147be9b9b3abcf7d61c0de026f153319adc3d50a223211c65c552fb6c15e61396574009f30e4049dfd78e58f7883a9cb82afd6988930851f263bd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90354);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-1348");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus55821");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-dhcpv6");

  script_name(english:"Cisco IOS XE DHCPv6 Relay Message Handling DoS (cisco-sa-20160323-dhcpv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the DHCPv6 Relay feature due to improper validation
of DHCPv6 relay messages. An unauthenticated, remote attacker can
exploit this issue, via a crafted DHCPv6 relay message, to cause the
device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?239272f7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus55821.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1348");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

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

fix = '';
flag = 0;

# Check for vuln version
if ( ver == '3.8.0E' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
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
if ( ver == '3.16.0S' ) flag++;
if ( ver == '3.16.0cS' ) flag++;
if ( ver == '3.16.1S' ) flag++;
if ( ver == '3.16.1aS' ) flag++;

# Check DHCPv6 Relay
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    if ("is in relay mode" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCus55821' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
