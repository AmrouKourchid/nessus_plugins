#TRUSTED 9ca920d302f0f3db9bd66af813b79ee687c8faf4853a245182b048e0993bbc81470a5cba7b418efb1086ca4c182739f567bf7c400c4667a508f3fbbefb596c9e02e7aebde9ca2ae6f237000625f6e0a2b63ef8351ae852bcd906faedeb9b25d062997963e5215cac7eedf12784aa00f1a621499b01be836b92c3a44ff671f2a396e9c08be1d2baa4ac17ba1f23379c7b461fe5f468435999fd3ed06df7b5d7655c3d22cecb4bdee8389c7206920abf4cefa6470e4c775d23777ca564f57c7ff743e13509be29acce2894f560968acfaa56a0f9b193fa84a89a64eb1ea098988e13f86c39aa480b7329b3b23338d4fe85ec3b8818ec31aa5e50eb61e544ef3e8429f585f04a1ea971953c5d56cc79686f656af1e1287e34f57ca4ecdddf1bf8706d48c5cb3d0fc47d0edbb683dbca23f3112cee22f9f05711707753d4f8841d18c2adb19605dbbf00d311de8ea47530102a3739719d4287acb141f77842641ca411368842c86934309adf81ce9ed349d2dbc670924438152723caf084d127df261282a62ec0a47a6fe48a8e5e836d7517bd5c53168e5bde68c2a039d89b9b445ba164da10609ec3351ca2f39e0c29a313a5e405acf2e264d1a3d8f23cde9349e95a9cccf6a96b6049925768a8729188ec59553dc32c03dfe787c4329ab72cfb271ac3db8d1d315ba123f6994b73b2f7e8a1ad75a23d5924fd2a1bc132a657a5bf
#TRUST-RSA-SHA256 531ad3b4694567d8103ae50e3735ab4b0d8179cd71fa431c85a639967ed43f07fb3b5c7738b6ba269635a32b89988c0a35ef18e713451cf8c1a2bea1667855ac8514bcc02ea9bad532549ff8ed0124ec05b166d7c2d0fa435d4ca879721aaaabe5033ca94fa86bd4602c6e9b60a09d41490ea35a493ef93f7a1e11b745fe0e5406709da447024538bb0de31cb5f0102c7240cc31d0749512146129f7af940aaf1f83e913e201512a06d775da52ebca22cb5cd8f10d50310d7b69f59c849de545501e640c66675370edbfe9d7f778779599b926336ec393bb9c6f6f1adbf3497fa444bbb413de862bba944411535c674764b28ae27d0702bf3793df774f7b003ea2fab3aed257b1d6bc3959c4f85c25b3db7630963f78216fe474c5c11c4b783b0ae2f4bd8c6fb01ccd5362ac4b1d352106f32f8f60c428ef32e232cb5db1c3308387ef9fc518b2fe472d5a276642328574a1eae139e9a196ed0372c0525421aea9cc557a754f96935ad907beaef681cc57ef9756382bfc66c9f3bdde34ed948ac4424d8c8d2458bdd7dc5fac47ee1ae058d49ac69ac646223637f347d8fedc6dad68f1cc73131e405a00abd56f6af88943610181c7f5f281a268064bc5ba5ed09821c42f50948b6bc0f3123060e4658910a00862aa239ed8735502057aaeb296f2441003280b09c78c6215f7a0aa953e3715a9e309bb05c6b12b65b8d5370597
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99665);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-6607");
  script_bugtraq_id(97933);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb40898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-dns");

  script_name(english:"Cisco ASA Software DNS Response Message Handling DoS (cisco-sa-20170419-asa-dns)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the DNS
code due to improper handling of crafted DNS response messages. An
unauthenticated, remote attacker can exploit this, via a specially
crafted DNS response, to cause the device to reload or corrupt the
local DNS cache information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-dns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75ae1722");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb40898");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-dns.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6607");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^1000V' && # 1000V
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v' # ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCvb40898';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.12)"))
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.18)"))
  fixed_ver = "9.2(4.18)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(3.12)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(3.12)"))
  fixed_ver = "9.4(3.12)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3.2)"))
  fixed_ver = "9.5(3.2)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(2.2)"))
  fixed_ver = "9.6(2.2)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config dns server-group", "show running-config dns server-group");

  if (check_cisco_result(buf))
  {
    if (
      ("DNS server-group" >< buf) &&
      (preg(multiline:TRUE, pattern:"name-server [0-9\.]+", string:buf))
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because a DNS server IP address is not configured under a DNS server group");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show running-config dns server-group")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
