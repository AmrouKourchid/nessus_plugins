#TRUSTED 224cf2ecb2ba3d6006fc26d927c3475cab9cca4cd27158ae967036b5fd83854ab4aa7d78bd1df2a97ef18b040c07827d4646d7970f98a9c0c39050ccf6f85bddc0911fd3558f7610865fb2a5dd4f313a1567742b6539f7fbfacb23e6ffc18b3c894de79128f2ac8a786f4b9c6be67e801cf33782ac44826a3bde7d46d12f8780d5a1c17b527ce49044037ea1d6382a79b50ae4581fd7fb92863852fc25c7b36ba866bd5a1e27fee07b3806ea80a2e0b51d0097b2cbe6cb9b67ac9ceb346d96396f2f03f78d6174d0933cbc563f6fae5eda175005702b684c0da359891e149f7443c0619664e436eee448be0fe4dcab46a1787549ffe943197fb8dcabd69ba50a525303e7968bca52f4f6296976f355aa3800d394370822e0ce808315b34147e157b8ca29d50916febdafeae8c77ce02c6ff4da7bbeacddae4ccc628e96dc4a71814d45aa79ba180276577f02c5f1344d7b7c7bbc7f89747951964dc69d9c2034aec8a58944f27b4d63160f40457ebb54de30211f830693f61dfae01b758e2f395e362d7e6be26048b9e4e811166e332cf028389c6556762285150e635b7ab2ca8202ec3bc36c776983c125296b763f9a72e5d6ab5c6bf69ef55545c0021ea76d8b58d187d701f2eb44b3fa6223dadc1875cee1f0d4b6f07ea1b645c74ecaddd31ae40aa9292fe4999dcfec3411619c76c5a7c1e15a64d6715216f976cb81227b
#TRUST-RSA-SHA256 39ed8c015489b8f3ab245fca5affb46277e74379309566af13adbb0aa0d3a782f941e410933bbf94d7c5feb0405d0cd399eb65aa9d7b5d064a7bb16f7a897e7c4b4428f0993c98a48cd4768a81bd31a18a9f1d09919338d5608460fe0e6be31cbdbb4b5e6c593895a8f18b6d34f45c73df7f4d16e069577920a850df1af4562ce43a499073d020171fb42eb1e349dbd32037b4607f3db95072b4fe2daadd51efe09038ba447c2d4ff5f459bbc94daadbc9a1667e9f7239a58caa65d6ca08726e12aba491703f3622a5a75034e7d8ccc831b6fdec02191e6dccf3665a415b206619ff3223704a9bed0a6a18766927fa24b4f0e50ab910cb8bf72aeb3e985c51407c8cb6a33919fad3e00a9f70f0d68bea0875c243db80feca3871a183c07b88de694200c796cc71593d4c0f71e5b9ea15a861eeea23acb694d5e536c8e9d80dd717c3255f09714caf163a565bc1ae52692cdc3e6b5330ce53b9864023d27a5582acc5b4668da0d308630cb9eb464d10b0bef035c18cd553027c3741a4868c6198136b9c62078295de01cf81c9e947f35660a749358e681bd3601d762b2a3097495b1e63cd02317387aa7afe5e93c8a69b5e9765b02dc01902faf09a9829093ddef8a5595c69c6ea0e0e53760ca8c492a8abd790be34e1dba9a9ed9ab6985689241a6d228672f69564041b767de239ca01da855acd061925ba3a28d741350ff9c6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87821);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-6429");
  script_bugtraq_id(79745);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw08236");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151218-ios");

  script_name(english:"Cisco IOS XE Software IKEv1 State Machine DoS (CSCuw08236)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Internet Key Exchange version 1 (IKEv1) subsystem
due to insufficient condition checks in the IKEv1 state machine. An
unauthenticated, remote attacker can exploit this vulnerability, by
sending a spoofed, specific IKEv1 packet to an endpoint of an IPsec
tunnel, to tear down IPsec tunnels that terminate on the endpoint,
resulting in a partial denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151218-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b10e25c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw08236");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20151218-ios.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

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


# 3.15.2S / 3.16.1S / 3.17.1S Labeled not-vuln in SA
if (
  # CVRF IOS XE unmapped
  ver == "3.15.0S" ||
  ver == "3.15.1S" ||
  ver == "3.17.0S" ||
  ver == "3.16.0S" ||

  # CVRF IOS XE mapped (via cisco_ios_xe_version.nasl)
  ver == "3.13.0S" || # IOS 15.4(3)S
  ver == "3.14.0S"    # IOS 15.5(1)S
)
{
  flag++;
}

cmds = make_list();
# Check that IKEv1 or ISAKMP is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";

  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:pat, string:buf)
    )
    {
      cmds = make_list(cmds, "show ip sockets");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s500\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s848\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s4500\s", string:buf)
    )
    {
      flag = 1;
      cmds = make_list(cmds, "show udp");
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : ver,
    bug_id   : "CSCuw08236",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
