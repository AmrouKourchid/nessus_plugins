#TRUSTED 6e04aeee40b8a049bc2bcc5d4edaa62b6e90adf9210c4e2f837e335ce7c0be784b56b362688c9aab0dc9faf98b3294b50a22ad280c0d96d76489c83f5ece8d48dc86e3475379cbf57be93aab022de58ea5f56c212d886beb2a6a2b3ccd456c24ca7eff99dfc2a1096e1d383cbaf82d2fbccee8a8134fda9d56d7ba2b995cbaae3402cca3d6ee5ec7318c12f6e0ab42e83c7dab9a81e5c6e445fdc289f80ecd7bb1f9d69b6b4c76fda85b6d372ca1e48be82d3aa1fa4109ecc1acb7964e4326b340323a7b7e92d3fc14050a488c5c37d534c1cae58151a7b93ba7152a6bfaccafa13fe01c4a49a9ebf1ea7e5f080b2c6c24c6a98da804508afcf8c204942f75f23db0b5924e4d0abf8f94d7b4f7a5b00fbe3ea2df3439d0cf3e4ce7acec46e975f9545ac98167c3b2889aae3ac28eb8e9efeb65d62cadd7d6a8f64155ea123b6baabec9deb8632e1a70e12d9329a7fa8479fa295c43488e5402e33fac2fc2bb4bec7a4a2e3cfc0f58ed137ab55b90cd7aa7fbe7c6d195d61bc8ba522c11858bad5f5b25a640071c0ad811fe0556b48d7393f48afa3d8f8b4cf733dceca4a341b70cda46e7c6d27de61cb9ce3e5c8f88cd9c71e9132d0044da7fcd3ef8905d90e3e3d2f2521a23f540d42aba3a3c8a581f2df49954ed996bfbf3aabe6a0aad40330482f555ff01237ad7923e8d2167dfcedb61b4d695aada8ec741207914c05e18
#TRUST-RSA-SHA256 6b6ff4525e440c143cb5524eccd958f6903ccf4173f4dc9afff8d26c486333799703b45b3f56373c2bad1f4d23fdcb02a109863cece1ea18c9008f8aea27f0905c313f3329e74368c0d5728a8b56a2dbb7a41d2d2cc1a13e8d18029e8d60403de573dadfccd3c3ee7cb5e997a340974af5a52b416e0931cebd10d7b2b68ea94f5e86957b2d8c8b738ee21240ddff5424397293aa23f104c8038f6c297b47028d71edec74024489a5eed814dcc35726f91bdc3f1db09eb9a391d7990f3440b1ae7c2534b45d1a11047d1a87ff2d27fd54c9ecfe546c4ed832527c39e45bf20c8d8260cf4e83fe962dc72cfdf29e2eaf4e6044a16e4e42c35cf5c4fcf234d18d9053369e5fc592969623cee16728f5537e7a2c989284724940b5b517b94c05de95b9c228e12e49b13cc8a256e4594609c2abf09d0802fa98a0c8f103d1294b6ef3aa515f923f39a27ec7c6e8be1057ff7b0130bb73ba524e9a0a345a34cad3b368064c9f2fb846ef8351c5964339fb5f8f0bb758b41ba51d2cd002d4c0632a16b731eaab70e65bf68d8048e122b13a1273ea7716506ccf0091b65bdc82cb691cfbdb711d632f29434d4949c4fa9582109f96de3e8024494b65b2ee3f9fd8c0fa9be8296180a24306d6a6d4ddfa8498011f3751aed78b31f5c1d306bd892aa206aeee80a9951191579b8b93a399b2aa2aa97f69f8f126dcab729c76369e54fd9f21
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90355);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2016-1344");
  script_xref(name:"TRA", value:"TRA-2016-06");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux38417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-ios-ikev2");

  script_name(english:"Cisco IOS IKEv2 Fragmentation DoS (cisco-sa-20160323-ios-ikev2)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Internet Key Exchange version 2 (IKEv2) subsystem due to
improper handling of fragmented IKEv2 packets. An unauthenticated,
remote attacker can exploit this issue, via specially crafted UDP
packets, to cause the device to reload.

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '15.0(2)ED' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.0(2)EH' ) flag++;
if ( ver == '15.0(2)EJ' ) flag++;
if ( ver == '15.0(2)EJ1' ) flag++;
if ( ver == '15.0(2)EK' ) flag++;
if ( ver == '15.0(2)EK1' ) flag++;
if ( ver == '15.0(2)EX' ) flag++;
if ( ver == '15.0(2)EX1' ) flag++;
if ( ver == '15.0(2)EX3' ) flag++;
if ( ver == '15.0(2)EX4' ) flag++;
if ( ver == '15.0(2)EX5' ) flag++;
if ( ver == '15.0(2a)EX5' ) flag++;
if ( ver == '15.0(2)EY' ) flag++;
if ( ver == '15.0(2)EY1' ) flag++;
if ( ver == '15.0(2)EY3' ) flag++;
if ( ver == '15.0(2)EZ' ) flag++;
if ( ver == '15.0(2)SE' ) flag++;
if ( ver == '15.0(2)SE1' ) flag++;
if ( ver == '15.0(2)SE2' ) flag++;
if ( ver == '15.0(2)SE3' ) flag++;
if ( ver == '15.0(2)SE4' ) flag++;
if ( ver == '15.0(2)SE5' ) flag++;
if ( ver == '15.0(2)SE6' ) flag++;
if ( ver == '15.0(2)SE7' ) flag++;
if ( ver == '15.0(2)SE8' ) flag++;
if ( ver == '15.0(2)SE9' ) flag++;
if ( ver == '15.0(2a)SE9' ) flag++;
if ( ver == '15.1(4)GC' ) flag++;
if ( ver == '15.1(4)GC1' ) flag++;
if ( ver == '15.1(4)GC2' ) flag++;
if ( ver == '15.1(4)M' ) flag++;
if ( ver == '15.1(4)M1' ) flag++;
if ( ver == '15.1(4)M10' ) flag++;
if ( ver == '15.1(4)M2' ) flag++;
if ( ver == '15.1(4)M3' ) flag++;
if ( ver == '15.1(4)M3a' ) flag++;
if ( ver == '15.1(4)M4' ) flag++;
if ( ver == '15.1(4)M5' ) flag++;
if ( ver == '15.1(4)M6' ) flag++;
if ( ver == '15.1(4)M7' ) flag++;
if ( ver == '15.1(4)M8' ) flag++;
if ( ver == '15.1(4)M9' ) flag++;
if ( ver == '15.1(3)MR' ) flag++;
if ( ver == '15.1(3)MRA' ) flag++;
if ( ver == '15.1(3)MRA1' ) flag++;
if ( ver == '15.1(3)MRA2' ) flag++;
if ( ver == '15.1(3)MRA3' ) flag++;
if ( ver == '15.1(3)MRA4' ) flag++;
if ( ver == '15.1(2)S' ) flag++;
if ( ver == '15.1(2)S1' ) flag++;
if ( ver == '15.1(2)S2' ) flag++;
if ( ver == '15.1(3)S' ) flag++;
if ( ver == '15.1(3)S0a' ) flag++;
if ( ver == '15.1(3)S1' ) flag++;
if ( ver == '15.1(3)S2' ) flag++;
if ( ver == '15.1(3)S3' ) flag++;
if ( ver == '15.1(3)S4' ) flag++;
if ( ver == '15.1(3)S5' ) flag++;
if ( ver == '15.1(3)S5a' ) flag++;
if ( ver == '15.1(3)S6' ) flag++;
if ( ver == '15.1(1)SG' ) flag++;
if ( ver == '15.1(1)SG1' ) flag++;
if ( ver == '15.1(1)SG2' ) flag++;
if ( ver == '15.1(2)SG' ) flag++;
if ( ver == '15.1(2)SG1' ) flag++;
if ( ver == '15.1(2)SG2' ) flag++;
if ( ver == '15.1(2)SG3' ) flag++;
if ( ver == '15.1(2)SG4' ) flag++;
if ( ver == '15.1(2)SG5' ) flag++;
if ( ver == '15.1(2)SG6' ) flag++;
if ( ver == '15.1(2)SG7' ) flag++;
if ( ver == '15.1(2)SNG' ) flag++;
if ( ver == '15.1(2)SNH' ) flag++;
if ( ver == '15.1(2)SNI' ) flag++;
if ( ver == '15.1(2)SNI1' ) flag++;
if ( ver == '15.1(1)SY' ) flag++;
if ( ver == '15.1(1)SY1' ) flag++;
if ( ver == '15.1(1)SY2' ) flag++;
if ( ver == '15.1(1)SY3' ) flag++;
if ( ver == '15.1(1)SY4' ) flag++;
if ( ver == '15.1(1)SY5' ) flag++;
if ( ver == '15.1(1)SY6' ) flag++;
if ( ver == '15.1(2)SY' ) flag++;
if ( ver == '15.1(2)SY1' ) flag++;
if ( ver == '15.1(2)SY2' ) flag++;
if ( ver == '15.1(2)SY3' ) flag++;
if ( ver == '15.1(2)SY4' ) flag++;
if ( ver == '15.1(2)SY4a' ) flag++;
if ( ver == '15.1(2)SY5' ) flag++;
if ( ver == '15.1(2)SY6' ) flag++;
if ( ver == '15.1(3)T' ) flag++;
if ( ver == '15.1(3)T1' ) flag++;
if ( ver == '15.1(3)T2' ) flag++;
if ( ver == '15.1(3)T3' ) flag++;
if ( ver == '15.1(3)T4' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(2)E1' ) flag++;
if ( ver == '15.2(2)E2' ) flag++;
if ( ver == '15.2(2)E3' ) flag++;
if ( ver == '15.2(2a)E1' ) flag++;
if ( ver == '15.2(2a)E2' ) flag++;
if ( ver == '15.2(3)E' ) flag++;
if ( ver == '15.2(3)E1' ) flag++;
if ( ver == '15.2(3)E2' ) flag++;
if ( ver == '15.2(3)E3' ) flag++;
if ( ver == '15.2(3a)E' ) flag++;
if ( ver == '15.2(3m)E2' ) flag++;
if ( ver == '15.2(4)E' ) flag++;
if ( ver == '15.2(4)E1' ) flag++;
if ( ver == '15.2(2)EB' ) flag++;
if ( ver == '15.2(2)EB1' ) flag++;
if ( ver == '15.2(1)EY' ) flag++;
if ( ver == '15.2(2)EA1' ) flag++;
if ( ver == '15.2(2)EA2' ) flag++;
if ( ver == '15.2(3)EA' ) flag++;
if ( ver == '15.2(4)EA' ) flag++;
if ( ver == '15.2(1)GC' ) flag++;
if ( ver == '15.2(1)GC1' ) flag++;
if ( ver == '15.2(1)GC2' ) flag++;
if ( ver == '15.2(2)GC' ) flag++;
if ( ver == '15.2(3)GC' ) flag++;
if ( ver == '15.2(3)GC1' ) flag++;
if ( ver == '15.2(4)GC' ) flag++;
if ( ver == '15.2(4)GC1' ) flag++;
if ( ver == '15.2(4)GC2' ) flag++;
if ( ver == '15.2(4)GC3' ) flag++;
if ( ver == '15.2(4)M' ) flag++;
if ( ver == '15.2(4)M1' ) flag++;
if ( ver == '15.2(4)M2' ) flag++;
if ( ver == '15.2(4)M3' ) flag++;
if ( ver == '15.2(4)M4' ) flag++;
if ( ver == '15.2(4)M5' ) flag++;
if ( ver == '15.2(4)M6' ) flag++;
if ( ver == '15.2(4)M6a' ) flag++;
if ( ver == '15.2(4)M7' ) flag++;
if ( ver == '15.2(4)M8' ) flag++;
if ( ver == '15.2(4)M9' ) flag++;
if ( ver == '15.2(1)S' ) flag++;
if ( ver == '15.2(1)S1' ) flag++;
if ( ver == '15.2(1)S2' ) flag++;
if ( ver == '15.2(2)S' ) flag++;
if ( ver == '15.2(2)S1' ) flag++;
if ( ver == '15.2(2)S2' ) flag++;
if ( ver == '15.2(4)S' ) flag++;
if ( ver == '15.2(4)S1' ) flag++;
if ( ver == '15.2(4)S2' ) flag++;
if ( ver == '15.2(4)S3' ) flag++;
if ( ver == '15.2(4)S3a' ) flag++;
if ( ver == '15.2(4)S4' ) flag++;
if ( ver == '15.2(4)S4a' ) flag++;
if ( ver == '15.2(4)S5' ) flag++;
if ( ver == '15.2(4)S6' ) flag++;
if ( ver == '15.2(4)S7' ) flag++;
if ( ver == '15.2(2)SNG' ) flag++;
if ( ver == '15.2(2)SNH1' ) flag++;
if ( ver == '15.2(2)SNI' ) flag++;
if ( ver == '15.2(1)SY' ) flag++;
if ( ver == '15.2(1)SY0a' ) flag++;
if ( ver == '15.2(1)SY1' ) flag++;
if ( ver == '15.2(1)SY1a' ) flag++;
if ( ver == '15.2(2)SY' ) flag++;
if ( ver == '15.2(1)T' ) flag++;
if ( ver == '15.2(1)T1' ) flag++;
if ( ver == '15.2(1)T2' ) flag++;
if ( ver == '15.2(1)T3' ) flag++;
if ( ver == '15.2(1)T3a' ) flag++;
if ( ver == '15.2(1)T4' ) flag++;
if ( ver == '15.2(2)T' ) flag++;
if ( ver == '15.2(2)T1' ) flag++;
if ( ver == '15.2(2)T2' ) flag++;
if ( ver == '15.2(2)T3' ) flag++;
if ( ver == '15.2(2)T4' ) flag++;
if ( ver == '15.2(3)T' ) flag++;
if ( ver == '15.2(3)T1' ) flag++;
if ( ver == '15.2(3)T2' ) flag++;
if ( ver == '15.2(3)T3' ) flag++;
if ( ver == '15.2(3)T4' ) flag++;
if ( ver == '15.3(3)M' ) flag++;
if ( ver == '15.3(3)M1' ) flag++;
if ( ver == '15.3(3)M2' ) flag++;
if ( ver == '15.3(3)M3' ) flag++;
if ( ver == '15.3(3)M4' ) flag++;
if ( ver == '15.3(3)M5' ) flag++;
if ( ver == '15.3(3)M6' ) flag++;
if ( ver == '15.3(1)S' ) flag++;
if ( ver == '15.3(1)S1' ) flag++;
if ( ver == '15.3(1)S2' ) flag++;
if ( ver == '15.3(2)S' ) flag++;
if ( ver == '15.3(2)S0a' ) flag++;
if ( ver == '15.3(2)S1' ) flag++;
if ( ver == '15.3(2)S2' ) flag++;
if ( ver == '15.3(3)S' ) flag++;
if ( ver == '15.3(3)S1' ) flag++;
if ( ver == '15.3(3)S2' ) flag++;
if ( ver == '15.3(3)S3' ) flag++;
if ( ver == '15.3(3)S4' ) flag++;
if ( ver == '15.3(3)S5' ) flag++;
if ( ver == '15.3(3)S6' ) flag++;
if ( ver == '15.3(1)T' ) flag++;
if ( ver == '15.3(1)T1' ) flag++;
if ( ver == '15.3(1)T2' ) flag++;
if ( ver == '15.3(1)T3' ) flag++;
if ( ver == '15.3(1)T4' ) flag++;
if ( ver == '15.3(2)T' ) flag++;
if ( ver == '15.3(2)T1' ) flag++;
if ( ver == '15.3(2)T2' ) flag++;
if ( ver == '15.3(2)T3' ) flag++;
if ( ver == '15.3(2)T4' ) flag++;
if ( ver == '15.4(1)CG' ) flag++;
if ( ver == '15.4(1)CG1' ) flag++;
if ( ver == '15.4(2)CG' ) flag++;
if ( ver == '15.4(3)M' ) flag++;
if ( ver == '15.4(3)M1' ) flag++;
if ( ver == '15.4(3)M2' ) flag++;
if ( ver == '15.4(3)M3' ) flag++;
if ( ver == '15.4(3)M4' ) flag++;
if ( ver == '15.4(1)S' ) flag++;
if ( ver == '15.4(1)S1' ) flag++;
if ( ver == '15.4(1)S2' ) flag++;
if ( ver == '15.4(1)S3' ) flag++;
if ( ver == '15.4(1)S4' ) flag++;
if ( ver == '15.4(2)S' ) flag++;
if ( ver == '15.4(2)S1' ) flag++;
if ( ver == '15.4(2)S2' ) flag++;
if ( ver == '15.4(2)S3' ) flag++;
if ( ver == '15.4(2)S4' ) flag++;
if ( ver == '15.4(3)S' ) flag++;
if ( ver == '15.4(3)S1' ) flag++;
if ( ver == '15.4(3)S2' ) flag++;
if ( ver == '15.4(3)S3' ) flag++;
if ( ver == '15.4(3)S4' ) flag++;
if ( ver == '15.4(1)T' ) flag++;
if ( ver == '15.4(1)T1' ) flag++;
if ( ver == '15.4(1)T2' ) flag++;
if ( ver == '15.4(1)T3' ) flag++;
if ( ver == '15.4(1)T4' ) flag++;
if ( ver == '15.4(2)T' ) flag++;
if ( ver == '15.4(2)T1' ) flag++;
if ( ver == '15.4(2)T2' ) flag++;
if ( ver == '15.4(2)T3' ) flag++;
if ( ver == '15.4(2)T4' ) flag++;
if ( ver == '15.5(3)M' ) flag++;
if ( ver == '15.5(3)M0a' ) flag++;
if ( ver == '15.5(3)M1' ) flag++;
if ( ver == '15.5(1)S' ) flag++;
if ( ver == '15.5(1)S1' ) flag++;
if ( ver == '15.5(1)S2' ) flag++;
if ( ver == '15.5(1)S3' ) flag++;
if ( ver == '15.5(2)S' ) flag++;
if ( ver == '15.5(2)S1' ) flag++;
if ( ver == '15.5(2)S2' ) flag++;
if ( ver == '15.5(3)S' ) flag++;
if ( ver == '15.5(3)S0a' ) flag++;
if ( ver == '15.5(3)S1' ) flag++;
if ( ver == '15.5(3)S1a' ) flag++;
if ( ver == '15.5(3)SN' ) flag++;
if ( ver == '15.5(1)T' ) flag++;
if ( ver == '15.5(1)T1' ) flag++;
if ( ver == '15.5(1)T2' ) flag++;
if ( ver == '15.5(1)T3' ) flag++;
if ( ver == '15.5(2)T' ) flag++;
if ( ver == '15.5(2)T1' ) flag++;
if ( ver == '15.5(2)T2' ) flag++;
if ( ver == '15.6(1)T0a' ) flag++;

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
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
