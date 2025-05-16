#TRUSTED b24795a1c41e62932673e08e8b848f34135c39fd65d5d2322b29c0b0a51fd2ef7b8896a62720a8fc56427110152c9280234936a9bc5686a4176ead953666d2137c5f757331d404ec55ef2e261f72c6233d760bfa93fa5cf7711cdb078d00544aae1a2a61aca57e0fac5bcf768598f1538d6b462ce0056c1f579245a1b53017ae42ef6ccf5a9e526342bca07656424d739f443c97e659d8f3ff61992e899ba8d34d9c292df7166710c5a0361c51275c066b4ee5acd4e714b20ac8d752a6da19fb963d33ef344c8dafe157592db022537db49a219b3a59547cea430f4a09cb1ba1317c7062023d1068df4eb44baa897845ae12ca5c46fab53308b330d62f201c06cfea5d800f69729d7a41ee051f26095b4b10e2f42c19a3094b454de9d286cde1a13a833e6c8670e4bf84f77d3451c69d3ed88768b26f7f6d9e425cb3e240218d2da5a0d5a88ecf520cb9e4e913af7e058ac50625c2827870de15e84ced1bd1099a78685f8b9d08374b7b4c1e01c9bf28faaa7d03c9efe84590ab1ca4c2a7e62748b30227c3f079c72983d707165f3377f06e676a0e9a99b0935666934f0aeffccd6cb4ddadaddaa4300923002f87fb6581da4febd98e5557e3ead483523677e3dda677e5a10e66ad2aea28481ef6cb07933a01d1daa398a50c98adf389aa6acf1e0a54b78d15d69b2fae30bf9aee2ed201e71f0bff3e94fe12c513135188a86f
#TRUST-RSA-SHA256 5c85afbc326500371e6fe8ca1318684e82bf0918dba391e7e2ac8f664f4a042ac2e162d21bb6e0dc65547436b18e0893336567f84d31d3c8a72475ac5d9ee07ffce3ec07274dc38a6e4c28e650de99bb7aad808dc8b3ccb3bb225e85de115e430b12b7d79e01b18c03178c4416d534939ffc3d546d63a76aa639b59776291ef9ef2b7a97693bf98bffc2d21ee2fa08a2cbdd57fff388cca4b97a8db8d63830afefd234f4ed4afbe316460095a4e75d71b71030a9599a0434bf93f3dfe6b3e08e5d18bf2d3c4c5756ef65c49c44866630411c3fd8d9bd7f9fd3cc808d7324b98d93d53e230d05da8ad28722600d295498cfa2b0ea0b701a06cbb7aacb1df521adb6f9594f49d475fc98f6fa229e605372eb2c043fab6d3c0f934523385f9677d34848ae1912f0afbe934b4200d1b40f48248b60b47b63a03174e3d8097b6e6673d1e0de032a77c8642c42f64fc1f14db6989645e29367c6a1433ec3651d985d9b6bc04fedd561fca4aeaa2bc30d0e3928e3937c31fdd22cce7c985f086164387de8c8e5a8b0a29a5eb60959aa89457aa64013d812e5a552a961d6afa3a9e92b827e8413af810e49c57fa48a0f9782f48bdbbcde6f91cf92c8f3492375fb7cb6e51c1817c212ba2fdad593a2ae4a127c9440d0d0443121ff98545d4f5dbaca5e376e199fd6dc80ea32e1e381d9bf2b0bc8f661f932d3e738fcf791957ba48e8614
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70125);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_bugtraq_id(56401);
  script_xref(name:"CERT", value:"662243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud10546");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud10556");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20121108-sophos");
  script_xref(name:"IAVA", value:"2012-A-0203-S");

  script_name(english:"Cisco IronPort Appliances Sophos Anti-Virus Vulnerabilities (cisco-sa-20121108-sophos)");
  script_summary(english:"Checks the Sophos Engine Version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device uses an antivirus program that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IronPort appliance has a version of the Sophos
Anti-Virus engine that is 3.2.07.352_4.80 or earlier. It is,
therefore, reportedly affected by the following vulnerabilities :

  - An integer overflow exists when parsing Visual Basic 6
    controls.

  - A memory corruption issue exists in the Microsoft CAB
    parsers.

  - A memory corruption issue exists in the RAR virtual
    machine standard filters.

  - A privilege escalation vulnerability exists in the
    network update service.

  - A stack-based buffer overflow issue exists in the PDF
    file decrypter.

An unauthenticated, remote attacker could leverage these issues to
gain control of the system, escalate privileges, or cause a denial-of-
service.");
  script_set_attribute(attribute:"see_also", value:"https://lock.cmpxchg8b.com/sophailv2.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/en-us/support/knowledgebase/118424.aspx");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20121108-sophos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a16e77af");
  script_set_attribute(attribute:"solution", value:
"Update to Sophos engine version 3.2.07.363_4.83 as discussed in Cisco
Security Advisory cisco-sa-20121108-sophos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/AsyncOS/Cisco Email Security Appliance", "Host/AsyncOS/Cisco Web Security Appliance");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

version_cmd = get_kb_item("Host/AsyncOS/version_cmd");
if (isnull(version_cmd)) audit(AUDIT_OS_NOT, "Cisco AsyncOS");


version = NULL;
if (get_kb_item("Host/AsyncOS/Cisco Email Security Appliance"))
{
  sock_g = ssh_open_connection();
  if (!sock_g) exit(1, "Failed to open an SSH connection.");

  cmd = "antivirusstatus sophos";
  output = ssh_cmd(cmd:cmd+'\r\n', nosudo:TRUE, nosh:TRUE);

  ssh_close_connection();

  if ("SAV Engine Version" >< output)
  {
    match = eregmatch(pattern:"SAV Engine Version[ \t]+([0-9][0-9._]+)", string:output);
    if (isnull(match)) exit(1, "Failed to extract the SAV engine version.");
    version = match[1];
  }
  else if ("Unknown command or missing feature key" >< output)
  {
    exit(0, "The remote Cisco Email Security Appliance does not include a version of Sophos Anti-Virus.");
  }
  else
  {
    exit(1, "Unexpected output from running the command '"+cmd+"'.");
  }
}
else if (get_kb_item("Host/AsyncOS/Cisco Web Security Appliance"))
{
  if ("SAV Engine Version" >< version_cmd)
  {
    match = eregmatch(pattern:"SAV Engine Version[ \t]+([0-9][0-9._]+)", string:version_cmd);
    if (isnull(match)) exit(1, "Failed to extract the SAV engine version.");
    version = match[1];
  }
  else exit(0, "The remote Cisco Web Security Appliance does not include a version of Sophos Anti-Virus.");
}
else exit(0, "The host is not a Cisco IronPort ESA or WSA.");


# nb: Cisco's advisory says 3.2.07.352_4.80 and earlier are affected
#     but tells customers that version 3.2.07.363_4.83 fixes the issues.
recommended_version = NULL;
if (version =~ "^[0-9][0-9.]+_[0-9][0-9.]+$")
{
  version_num = str_replace(find:"_", replace:".", string:version);
  if (ver_compare(ver:version_num, fix:"3.2.07.352.4.80", strict:FALSE) <= 0) recommended_version = "3.2.07.363_4.83";
}
else if (version =~ "^[0-9][0-9.]+$")
{
  if (ver_compare(ver:version, fix:"4.80", strict:FALSE) <= 0) recommended_version = "4.83";
}
# These next two cases shouldn't happen.
else if (isnull(version)) exit(1, "Failed to identify if the remote Cisco IronPort appliance uses Sophos Anti-Virus.");
else exit(1, "Unrecognized format for the Sophos Anti-Virus engine version ("+version+") on the remote Cisco IronPort appliance.");


if (isnull(recommended_version)) audit(AUDIT_INST_VER_NOT_VULN, 'Sophos engine', version);

if (report_verbosity > 0)
{
  report =
    '\n  Sophos engine installed version   : '+ version +
    '\n  Sophos engine recommended version : '+ recommended_version +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
