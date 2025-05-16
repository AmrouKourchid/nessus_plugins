#TRUSTED 50731c0f18c7139bb8b67cbaa395ffaa0ea5cd92e0f0a4cdde3bbdc88f874ff8072a186d1e3abfe92629a803869988fd051d72de4e7855481d54bbfa2e05caf604d4dbc42bd32b1f0a7c82d16fcca66a0ac2f65be7b72e443e5f003ca6c9111af3caf5f881a92827698f9df9f336dff566092a9fbe9de4b5b698ba1dd9a1ceb1cf3a7671a96b42a0cb8462cc4ca1c416d8bd2cfc88dd4af4cbe3fd45bcd2cd5d4da19f9e5fd15162b9e350c9783b3aacc256e8cc344300e5b95d18a35784e0da38eca9829504f80222a5108a827a15c4ce35337f697e54d2a681327cd2412c70636e157d512333d1a20ec0d0120e334f352f6a8209a7ddcb8ed6985a53caf0bf68c38aaf424a50d2b1494033dd82bdd8a4259045c4cce46d95a2409da18213f249d3a9bdddffe022ebfc913f3d438aafaf34ff21b6804056af9a676d24ad748d1a8cc33dd512a5a48b0f06a7d72c221fcfd732666992c8d1d99d0fcedda69713bc850a6675e61ba7f10a24032fbef60091b39a439fc17e0a9dfe86d06753f839520b367c6a7269cdf666245b4b4c73d151ab9f8fa088853650e6d2c3178218e2d9f56d43c41aadc0d40936769ba8e9b7fe3a7f2ebf1f71e25138adb71e152c51176f30c7ac6a5d987383612936a49626b9662e18a9edd5003dc950168770c68b58aa1a69dc8802759678320367ca27d8ae356113f3dbba7865675ca416adb8cd
#TRUST-RSA-SHA256 6bb0bb10a28454c7816d260e2e1617599d037c5d6f9e0b86f6447e685a95bce00ad7f1f88a51bf419dc3c827ec8a202dba7c6178633b61c2f8c42fd7bd4cc9f5845efe3042701a57de670adb29448a347a4e0fa2b7b3b3b62cce51c2fd077799b6fcfd72029170d36d3c33f85d7ca232558f85b30cbc0ea53fbd1cd681f4fac51cc3d9137982528f0b74cbdad2a069531bfeb29bf4655ea88fa043997a050a6bd742eae815738cceea4a3aced385ec8477bcc072808e36b082ef73458339b67ed9317768eb27a8427367d63aad402f2696bee2c18c79bcd96998a22b9f8db6830b8cf4d5c31c4ec8541634e583bb137f5b42d2d10cadc17a65f18d8ce674e2712dfdf4af100077a82e2521fa9b116305a79d72a1ed2247edcb0f9fab45d01e4a2a04cf71b724cc002c43652a825d1629d63e33e99bc81ecd8aa1d7b5123347d481190a611b43b4d503b7ac6b4d8406d6208cca325d57fb1b466ae4830e0bea041b57e6b9f56439dbf2080fdaad93c65e0e11fc633bbd3560eb4c11f334a9fb9741a92b4c89cde338d2464888268e2e68950a13a0a39b64311ad52531fda89a5826bfded6bfca54f65562b53fcc41fb4c8ea6b30e66eac8ddcd26ccefa7bd4ddc1bd6fb4f379b91fef6b2ea70a6dcaa2b86f315e422582eedf601c70a10bd727c9d389c7de0e7be76be2280ff67dec21df8b01b7e9965b8e04a374c2f968a855c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86248);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-6282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut96933");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-iosxe");

  script_name(english:"Cisco IOS XE Network Address Translation and Multiprotocol Label Switching DoS (CSCut96933)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and is configured for Network Address Translation (NAT)
and/or Multiprotocol Label Switching (MPLS). It is, therefore,
affected by a flaw in the NAT and MPLS services due to improper
processing of IPv4 packets. An unauthenticated, remote attacker can
exploit this, via a crafted IPv4 package, to cause the device to
reboot.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-iosxe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?280014a1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut96933.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (
  !(
      "ASR1k" >< model ||
      model =~ '^ASR 10[0-9][0-9]($|[^0-9])' ||
      "ISR4300"  >< model ||
      "ISR4400"  >< model ||
      "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

flag     = FALSE;
override = FALSE;

if (version =='2.1.0') flag++;
if (version =='2.1.1') flag++;
if (version =='2.1.2') flag++;
if (version =='2.1.3') flag++;
if (version =='2.2.1') flag++;
if (version =='2.2.2') flag++;
if (version =='2.2.3') flag++;
if (version =='2.3.0') flag++;
if (version =='2.3.0t') flag++;
if (version =='2.3.1t') flag++;
if (version =='2.3.2') flag++;
if (version =='2.4.0') flag++;
if (version =='2.4.1') flag++;
if (version =='2.4.2') flag++;
if (version =='2.4.3') flag++;
if (version =='2.5.0') flag++;
if (version =='2.5.1') flag++;
if (version =='2.5.2') flag++;
if (version =='2.6.0') flag++;
if (version =='2.6.1') flag++;
if (version =='2.6.2') flag++;
if (version =='2.6.2a') flag++;
if (version =='3.1.0S') flag++;
if (version =='3.1.1S') flag++;
if (version =='3.1.2S') flag++;
if (version =='3.1.3S') flag++;
if (version =='3.1.4S') flag++;
if (version =='3.1.4aS') flag++;
if (version =='3.1.5S') flag++;
if (version =='3.1.6S') flag++;
if (version =='3.2.0S') flag++;
if (version =='3.2.1S') flag++;
if (version =='3.2.2S') flag++;
if (version =='3.2.3S') flag++;
if (version =='3.3.0S') flag++;
if (version =='3.3.1S') flag++;
if (version =='3.3.2S') flag++;
if (version =='3.4.0S') flag++;
if (version =='3.4.0aS') flag++;
if (version =='3.4.1S') flag++;
if (version =='3.4.2S') flag++;
if (version =='3.4.3S') flag++;
if (version =='3.4.4S') flag++;
if (version =='3.4.5S') flag++;
if (version =='3.4.6S') flag++;
if (version =='3.5.0S') flag++;
if (version =='3.5.1S') flag++;
if (version =='3.5.2S') flag++;
if (version =='3.6.0S') flag++;
if (version =='3.6.1S') flag++;
if (version =='3.6.2S') flag++;
if (version =='3.7.0S') flag++;
if (version =='3.7.1S') flag++;
if (version =='3.7.2S') flag++;
if (version =='3.7.3S') flag++;
if (version =='3.7.4S') flag++;
if (version =='3.7.5S') flag++;
if (version =='3.7.6S') flag++;
if (version =='3.7.7S') flag++;
if (version =='3.8.0S') flag++;
if (version =='3.8.1S') flag++;
if (version =='3.8.2S') flag++;
if (version =='3.9.0S') flag++;
if (version =='3.9.1S') flag++;
if (version =='3.9.2S') flag++;
if (version =='3.10.0S') flag++;
if (version =='3.10.01S') flag++;
if (version =='3.10.0aS') flag++;
if (version =='3.10.1S') flag++;
if (version =='3.10.2S') flag++;
if (version =='3.10.3S') flag++;
if (version =='3.10.4S') flag++;
if (version =='3.10.5S') flag++;
if (version =='3.11.0S') flag++;
if (version =='3.11.1S') flag++;
if (version =='3.11.2S') flag++;
if (version =='3.11.3S') flag++;
if (version =='3.11.4S') flag++;
if (version =='3.12.0S') flag++;
if (version =='3.12.1S') flag++;
if (version =='3.12.2S') flag++;
if (version =='3.12.3S') flag++;
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;
if (version =='3.14.1S') flag++;
if (version =='3.14.2S') flag++;
if (version =='3.14.3S') flag++;
if (version =='3.14.4S') flag++;
if (version =='3.15.0S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  # Look for NAT
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-include-ip-nat", "show running-config | include ip nat");
    if (check_cisco_result(buf))
    {
      if (
        "ip nat inside" >< buf ||
        "ip nat outside" >< buf
      )
        flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
  }

  # Look for MPLS
  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-interface", "show running-config interface");
  if (check_cisco_result(buf))
  {
    pieces = split(buf, sep:"interface", keep:FALSE);
    foreach piece (pieces)
    {
      if (
        "mpls ip" >< piece &&
        ("ip nat inside" >< piece || "ip nat outside" >< piece)
      ) { flag = TRUE; override = FALSE; }
    }
  }
  else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCut96933' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report+cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));

}
else audit(AUDIT_HOST_NOT, "affected");
