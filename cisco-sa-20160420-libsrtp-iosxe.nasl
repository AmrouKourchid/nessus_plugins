#TRUSTED 72175bdd7d4b90b905928d9e8101d505e084a1b99c5f290a942c48ce3d85e2bd2a98fe87a7adb1d7c05cc2f9d164c5f4562bdd01aef660828c75ef8e07d8d2a5df789719d7e5aa969262ed8d8a3b45fa72b3699ffe199b6be5f3814d3417b8e4fec7d468d77d87888de1f15e8bd0fa149711c45aa2b2fd5bf90abc9d6744e24b78e70623d74ad51bda4e68076a2f000b55e8bc389f827a9d48674a22dc2240aacd3c2de289d034d92eec518dd7ceb816e8aa95b954cf6eae350b016d5d95b57ad4ad8be3b74a4f78ec24c022bc15b826301194049f3cb802db484b387b238c82f09b0ffc0a3b39c9298eea9eb9d53d35281f8269d3ceef2df42c181edd9c61e2b025b1435fc9360fe967dd7067c0f97d8eaf95662143d0c910f2c7ca7428bdc3e439d6d5364eeecfc21276f024602aabc3d83b06a75f29f2490c1aca36d4149253cb95061517b8c5de5fd28210fdbb49014db882d2df2e25b0248fad40e8c3bccfb24be49825666999e57f48e27db6fdd51db43c50af18353595949c1663b17dc1e00da0dd3064ef7c5cf3f77d54f4e8206c9d8a1471a15b31331bdac20d75ff249f29efdcfbefb37352a7c8eed2119fc54f371a6a4a3b709f86ad2d503a0329526a0d618666ddc4d5879c1330eb3afb6a038e17d338ed1eca372bea0253188431c06e5a1701ccd8df5c68925de43f5652632dcc1197915ed9b57a1d062bbe3a
#TRUST-RSA-SHA256 456970b0fc9cda1230b1adc957e02ff8ce6f3a76ac5be42eb0316389a31ca21a54325f5f40e4f195a2f4e5a8394eb0ba2f51ab5c924b6785d75e9257cad35c25e54f78732415fadb6a530609e98d7de783e3408a477a870b60fb6281fbdb6124f9479a6cd8a4e82ac9ea8295eb89275edad7af211ccf4b6f1cc32fd485c98f13a7d871129fdc0dc66368ad910c4fcba62f617eaf44fcc9e07e9d09c8bbff441ae7b12e69da14c92bc2a0a93f720334548eb7f655109b943d2ce6218e7a0ea63430041e49afc65e64d5b535b2237685aa0b626f9afd56de8e2178d27d1a74e3dc0e24ebf118b86bb35289a432030d9d8ca4256b10d64242ac7a8e12d062b4a959784b5ba06945b919fe541be66d1595b6cfc160ed4472fb20a14f6885f09186a12d1d466da4bbb1d9913640d2936dde752acdf80be542ba10d5e2402500846d06e4120c42db988e69f45220df3ee8c44ee01ee64e6ec5a3697c40b072c1f93dfc051e042d596e73512cd73bbc0f67fc7b0bf1bb9d0acc06fed88bdd0e0cc1345d574d7ed6391461267bb9f0f6420619cd159d0c3667e14ea29e29eba97c525dfc6c8305f40241604c2ab38aad0b37ae63d13133393b2133e2176ca8cdfc86e28ce5f4b39a5ce4359936ddd3f4660c81ee7f871163ef66dd7303d8c59bbe991ddb51eef8a354ca2a41facc9778228ad6d89c617c3aefb915dba3f6f8898d5e4e22
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91760);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-6360");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux04317");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-libsrtp");

  script_name(english:"Cisco IOS XE libsrtp DoS (CSCux04317)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and it is configured to use the Cisco Unified Border Element
(CUBE) or Session Border Controller (SBC) features. It is, therefore,
affected by an integer underflow condition in the Secure Real-Time
Transport Protocol (SRTP) library due to improper validation of
certain fields of SRTP packets. An unauthenticated, remote attacker
can exploit this, via specially crafted SRTP packets, to cause packet
decryption to fail, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-libsrtp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2658d700");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20160420-libsrtp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

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

flag = FALSE;
override = FALSE;

# Fixed: 3.14.3S, 3.13.5S, 3.16.2S, 3.10.7S, 3.17.1S, 3.15.3S
# Check for vuln version

if ( ver == "3.10.01S" ) flag = TRUE;
if ( ver == "3.10.0S" ) flag = TRUE;
if ( ver == "3.10.0aS" ) flag = TRUE;
if ( ver == "3.10.1S" ) flag = TRUE;
if ( ver == "3.10.1xbS" ) flag = TRUE;
if ( ver == "3.10.2S" ) flag = TRUE;
if ( ver == "3.10.2aS" ) flag = TRUE;
if ( ver == "3.10.2tS" ) flag = TRUE;
if ( ver == "3.10.3S" ) flag = TRUE;
if ( ver == "3.10.4S" ) flag = TRUE;
if ( ver == "3.10.5S" ) flag = TRUE;
if ( ver == "3.10.6S" ) flag = TRUE;
if ( ver == "3.13.0S" ) flag = TRUE;
if ( ver == "3.13.0aS" ) flag = TRUE;
if ( ver == "3.13.1S" ) flag = TRUE;
if ( ver == "3.13.2S" ) flag = TRUE;
if ( ver == "3.13.2aS" ) flag = TRUE;
if ( ver == "3.13.3S" ) flag = TRUE;
if ( ver == "3.13.4S" ) flag = TRUE;
if ( ver == "3.14.0S" ) flag = TRUE;
if ( ver == "3.14.1S" ) flag = TRUE;
if ( ver == "3.14.2S" ) flag = TRUE;
if ( ver == "3.15.0S" ) flag = TRUE;
if ( ver == "3.15.1S" ) flag = TRUE;
if ( ver == "3.15.1cS" ) flag = TRUE;
if ( ver == "3.15.2S" ) flag = TRUE;
if ( ver == "3.16.0S" ) flag = TRUE;
if ( ver == "3.16.0aS" ) flag = TRUE;
if ( ver == "3.16.0bS" ) flag = TRUE;
if ( ver == "3.16.0cS" ) flag = TRUE;
if ( ver == "3.16.1S" ) flag = TRUE;
if ( ver == "3.16.1aS" ) flag = TRUE;
if ( ver == "3.17.0S" ) flag = TRUE;

# Check for Smart Install client feature or support of archive download-sw
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_sbc", "show running-config | include sbc");
  if (check_cisco_result(buf))
  {
    if (preg(string:buf, pattern:"^\s*sbc [^\s]+", multiline:TRUE)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = TRUE;
    override = TRUE;
  }

  if(!flag)
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_srtp-auth", "show running-config | include srtp-auth");
    if (check_cisco_result(buf))
    {
      if (preg(string:buf, pattern:"^\s*(|voice-class sip )srtp-auth( [^\s]+|$)", multiline:TRUE)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf))
    {
      flag = TRUE;
      override = TRUE;
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux04317' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
