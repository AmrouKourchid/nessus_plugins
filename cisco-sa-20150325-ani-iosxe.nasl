#TRUSTED 030128c855e55288a6bf0aa4f36b7fbc4255527dd3b88cd1334d160ab0ae7230c9b41dfde2ebeed5182df34b621065e396047449d4e308044226b33c6d4783b368995cf241bf6fbf762908164cc6245315cbbbc57712aed24fa814adc06259fb2e4064a9961223f0a93dad3428ca27adf3cba978cee30fc2aa6717f2ea97b382d8ea40821e4724e6755e1c465ccc099fddcc6697484e11c226b3a7a17dc4206343e0f44c6970e6a1e8cd14135d02b3764fa23ecdfbfb38798331a5352a3cdbda149c71525055be05c2b7a6fd6dc2b0143541a420c413b47d40e7ef80ac38b4befef7f4000ae6a752117c070beb0a2dab3e5f911fd854111ac07aff0c43f31be1e09b99843bef1ea2d6a40829f4d88af560f2fa8f93ade5cdb9728a5669c2c866cb7364196086076807a3ab660b80c132a37c0679c623195e20863bb98970f05436e2895ebb318382ef487af6c492c1274134b0a94dc8bffdc3329d90f8139b98eec84ca4e0e9605031ed91210c99afdca8ccf4ad18eb63ece6be4645cf67df4c557202c41fee9ea3a8fe0fdeb4c8c47d9cc3943e97eed081ebfd596690ae9d2f18bd99e1e4d3382abbc8ca85dda37d6e2541a5a5708dc004051a5682df0a37f01d9433939406a820260af0d863669fbe10a773d276fac7ddaea5f542a358f31a9198c84129c51d888ee50bb7f1228ca3ceffe1b4ae996119e0fa7144ebf852e6
#TRUST-RSA-SHA256 a78610536d6f0f02698363f3a1b17d76d2d9c461abff285d547c02e30c7ee5f7b7cee78b85acb81eb59e326af38c46119bfb248a386fbdd4f2059a0c21621cb45fb683fb2a0e206cfc14ec6e7e403f4a99494cab10f20ee3699d82121ca18647e9aa6213f18f6452f29ec70615756664f742210cefa3a30008b729c922b7449ce2149b1051b310b6f3ae7c0537eef99cb7be7f5d48cfe2bb8dfbb628b03c41ed324f2a47987b5cad10518f7802880937fb6145f4dacdee8327188b1d721c2953a01df3759cf1c6baaa3893a538fd5b5f926eaf57bb594cfe884a13966b94df130f1d82f9f82527561e09fc0b48a504d3ff0cf89724555373efe7618eef8377bb2033d4dc500b220f26ce543df37d8c4fc5498b469dbf6dffd735b4130b416ea60e178203deada4d085139ecf0a2bf873822431587e5febc0add10ffa28ad096e29b75917904aff315b7d1215dd3f11b72b627d79f10fb227ea7807161fae6dccd17182d256e271649fe3c74dc636ff05a327f4dd9bff38979d45aa423623b98122cd707592d80f6f9fefc5f3c8756e2086503094a469e79932e7b3530cde862da1bcf7223635c360010f1037f116232c22ae484286985039e5ed13ed15467534dd334d1e1d8de89e2a05618c66cb676fcd716ccaaa4bb0fb35698ca5b98da3e5c480286e3a788b12241b901dd4d3ddb390b533ee682ee6475279e03d28103fbb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82585);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0635", "CVE-2015-0636", "CVE-2015-0637");
  script_bugtraq_id(73339, 73341, 73343);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62293");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ani");

  script_name(english:"Cisco IOS XE Autonomic Networking Infrastructure Multiple Vulnerabilities (cisco-sa-20150325-ani)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by the following
vulnerabilities :

  - A flaw exists in the ANI due to failing to properly
    validate Autonomic Networking (AN) messages. This could
    allow a remote attacker to spoof an Autonomic Networking
    Registration Authority (ANRA) response and gain elevated
    privileges or cause a denial of service. (CVE-2015-0635)

  - A flaw exists in the ANI due to imporperly handling AN
    messages. This could allow a remote attacker, with a
    specially crafted AN message, to disrupt autonomic
    domain services. (CVE-2015-0636)

  - A flaw exists in the ANI due to improperly validating AN
    messages. This could allow a remote attacker, with a
    specially crafted An message, to cause the device to
    reload. (CVE-2015-0637)

Note that these issues only affect devices with ANI enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ani
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dabca9f4");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37811");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37812");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37813");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

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

model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (
  model !~ '^ASR90(1S?|3)$' &&
  model !~ '^ME-3(600X?|800)-'
) audit(AUDIT_HOST_NOT, 'affected');

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

fix = '';
flag = 0;

# Check for vuln version
if (
  ver =~ "^3\.10(\.[0-5])?S([^EG]|$)" ||
  ver =~ "^3\.11(\.[0-3])?S([^EG]|$)" ||
  ver =~ "^3\.12(\.[0-3])?S([^EG]|$)" ||
  ver =~ "^3\.13\.0?S([^EG]|$)"
)
{
  fix = "3.13.1S";
  flag++;
}

# Check that ANI is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if (
      ( !empty_or_null(buf) ) &&
      ( "no autonomic" >!< buf )
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (fix && flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup62191, CSCup62293, and CSCup62315' +
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
