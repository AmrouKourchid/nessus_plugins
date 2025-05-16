#TRUSTED a2057e7101eb9f1d3e0a7c0e7df482aba4619330c8792a804b9efa9ba4d2353fe58a0d40d73b2b1221493176c448b307af69ece1e23efd53d434fefbd7f777f22d599062685a9b29e45071e562bdca6762299d6c4cdb691424ae0b06ccec0b57bff58d66a445357f8f67b60d0c0fcebe84a317c1f618fa7b9f5844141f5b6155f6ffd2bb4ef49f6410c8ee1499b02966ade5bffc6864524adf28bab64b1a490ae75232e274cb27b67a978167d9078ed0402074da99477b2da96af0ec95c19ace8be5822e397c277c4e486ba622b730451d42763f7a5d904b3fd1c689f6d29a776aa273377923dcd8b2e73925b3372400192b166524a9fa405420d62379f5148ee9755f9f433a47a8c60ce05a190e3bb482616e3e4eb1e757e0c5e7c0b2192d7c270125e12ad1038523176f892ed0abbef4a2c7b227fc46faaa7a32990bf279f2067a7d8d0638d4151ee9ae707bf4e22c87ed01a2e0af01d37284ab2eaccbf0cbee4f0631f085865d818aa70307b4aeaaa4e54146465c9148f89fee2f777145bb6bad6b3022417c95e6c03d0bf12e4c03302c7abfc88517c4fc9e5c0b3a15f229e738a5f8fc9849c4ff980caf80ba5a50c2fe1905c600e5bae5a30a96d5fd750867c855a97054e2bc22e8d1eda355a86f4fd9af73624ef0a90af5fab665f265e55bc3fef2085dbf560ee62f14fb8a722692e3967429e4f120853e8aecb3f9a140
#TRUST-RSA-SHA256 64ea62ea386c70b118d7173d16be8066ad7a1daa20a5b04a58a0110060dbb46afaecc80be002aaa4d5f00e0c43dfbd68da4992aa3307fc3f7e67eff22593dbbe3a5802950f47d811e2d183a818924896b2ff54a6048ac35f261bb1d7da86cf65167d74e9239df9566228f3d4b5c7259d64c3e648f776fa1d040201a759d840c4a25298aeae43a6a149a73ad7866201845020e0d81ed872d1db1ecd9b61fc6aed6ef7d1026b8e8b69ab85a8df19d3a80c228f4119e90565895ab4cb3af4aced0737a6776559ba1f474b21b36bbb0c3582fd08622f5e1634dc3f15f3c095dd15ab62db8f0c705e42d03f233f323de8fe72c3b9036739b13ad4c183f947b3c64a571813760dbd6337117b54d8f6924b0fa305699b95c5ef19c1ad84e3d66f60e128937b7bceef5d9c5beb3e135428f4864ffc3cea6b03d371eb0a846bdddf6c7a4b69dc2037f4ec4c0ad208b50f6cde34ed2fd05a95ec701afbdf32b9860ddfbd3407868a6989443903ed1661d5d2e0dfa2fbcfc70e0efe1f073fd1a22d37595ce37efd38d20a753f5a2b42c4530d8530a0835abdb4478d2c1230d0f3a327cbd16f05e1343941835db4a2ad89efdfa66185932b2236582e89e9aedd3dedb87cb263f172226c21a34246e336d371c0824263c7fea9f24f59e4e659b486dfc933deb336adfb50fa0ca3a3bd5550d6fd2a95145493842a826f2cb1f3e1e90569725fcd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90311);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-1350");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23293");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-sip");

  script_name(english:"Cisco IOS XE SIP Memory Leak DoS (CSCuj23293)");
  script_summary(english:"Checks the IOS-XE version.");

  script_set_attribute(attribute:"synopsis", value:
"TThe remote device is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Session Initiation Protocol (SIP) gateway
implementation due to improper handling of malformed SIP messages. An
unauthenticated, remote attacker can exploit this, via crafted SIP
messages, to cause memory leakage, resulting in an eventual reload of
the affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddc3f527");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCuj23293");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

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

version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
flag     = 0;
override = 0;

affected = make_list(
  "3.8.0S",
  "3.8.1S",
  "3.8.2S",
  "3.9.0S",
  "3.9.0aS",
  "3.9.1S",
  "3.9.1aS",
  "3.9.2S",
  "3.10.0S",
  "3.10.1S",
  "3.10.1xbS",
  "3.10.2S",
  "3.11.0S"
);

flag = 0;
foreach badver (affected)
{
  if (badver == version)
  {
    flag = 1;
    break;
  }
}

# Configuration check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = " CCSIP_(UDP|TCP)_SOCKET(\r?\n|$)";
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_processes_include_sip","show processes | include SIP ");
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

if (flag)
{
    order  = make_list('Cisco bug ID', 'Installed release');
    report = make_array(
      order[0], "CSCuj23293",
      order[1], version
    );
    
    if (report_verbosity > 0)
      report = report_items_str(report_items:report, ordered_fields:order) + cisco_caveat(override);
    else # Cisco Caveat is always reported
      report = cisco_caveat(override);
    security_hole(port:0, extra:report);
    exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
