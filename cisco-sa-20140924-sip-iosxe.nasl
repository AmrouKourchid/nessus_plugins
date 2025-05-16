#TRUSTED 2d099d0d8e58e82fb43938ef686cacfa4370e7d7882c32ee8a90abe236354fb54588f06ec8a95565c94d54cba23c8f39f25c13eb9ce35f17dfe89de650fe2c26ed031d57fe4c0e7ab174b1e10be192cfc0a40c10b5d6b0c104def048e60294b90a1d91d84117daa83acf1e41949896a0a1fc3c886b814191517678476202ea0b591e13732595ebac60366135acb5bba682766a0707b13cb1aadefb3aac062e1a7d30df6ebd8c0daa4cb62a729235ed423ce13749a4a418efa5bdfecd9980ea7e0127fbda3b35022329555e88af02af0749ac6774f187c273352a279b00d71c141528f95c2604340760ba67e157d22cbde33046c37b7e6ad3683b7e6dea2454723805f66e84d236bfc09c384094d76dda09a6ea5f6bb4284df2c29818ca5a0ff14c07356d5e25092d46e3c86bc308fd869dc65f24c70019a1455c11d4595a99d41de4bd5b58630a23e1b1387c08d7e621265d3314b8365a63860a738630543186c5f142a3368050daa420f27a920bacb803e17c629064630629188349db2274fc1c9ffcba7c71d187efc70cff2a86364984ccdb1554f7c8ee0d6300738255c5c854e8d191be62948aebd76ce1a7d86400a8ade8b701eac5feff86442dbb5ed2673b2d0003fb49ef9f71af316e6c4f8b4e972c133c5fbfc6bd5fe259587576449341875ec76cfdf179d77ef71043305758b70f5dc694a317ffbf068920664c241c
#TRUST-RSA-SHA256 2722a9ab0bd57810af777d1f702472945aa11e2506328d77dd8a2968f8dbd409d95b75135ebf3b676b917f3936d1b965d544e489a8babb554d4f9624878c9afb34a6318f9280ae34c9c3a5949c54d70e5acabb22c21dc6845ff26e8fe6023a59932f5f2d4a4d51eb2bd90b1b7d21fa17a827f6ee76a36eaed7c619252677a19b9de866a170ee3815b64721dbd44ecd9eb81a6a6ff61d9bd3f53c792ffda4c30f499a0bcd28efcbb34ccc857f386de11d3248e957069a4e2e4506614de71b355718a54981b75c2adc4157efb935ed90a4b191c1ecf1d06568698f9bad8270adf896c02c809704a35741e667304c56955d6d7c57ede3dff2d66bf71b4c017bdcd4691d89072e31a160f94e82360392b7efd9c73bb7d4dbfd3c5d67f3f1f7e1849f86b917c02df47cd6b2a8083a607eb68f067f20247c5f2e0acfbdc9936b8728270c24c61f99dbea4886ce3b653cf7ea2d4a557b25d13be814b088ec1b488bfd3999a33cf3659aa460d3c9de3f758673bb1e61e20fcf66e2e83d748c53e027267f3e61161faf1186e7a0cd78aa23d299b688a98e913371655a0b25b4232ad473484b3945c7495328112872dc02f05616584cabfc1c77b5dd029485865799f6bd77e6408ecd569d5ce40d513af7b013dcbaf465f4eac939b5e2dc4faf7f1b162319397ab31bac64a5327afbe8d5dec75d42070cae49d2cffd75fe865f310a11596d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78036);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3360");
  script_bugtraq_id(70141);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul46586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-sip");

  script_name(english:"Cisco IOS XE Software SIP DoS (cisco-sa-20140924-sip)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a vulnerability in the
Session Initiation Protocol (SIP) implementation due to improper
handling of SIP messages. A remote attacker can exploit this issue by
sending specially crafted SIP messages to cause the device to reload.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS XE versions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00b78a3e");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35611");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35259");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul46586");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCul46586";
fixed_ver = NULL;

if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^2\.6\." ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-5]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-3]SG$"
)
  fixed_ver = "3.4.4SG";

else if (ver =~ "^3\.5\.[01]E$")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[0-2]S$" ||
  ver =~ "^3\.10.(0a|[0-3])S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# SIP check
# nb SIP can listen on TCP or UDP
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # SIP UDP listening check
  # Example:
  # 17     0.0.0.0             0 --any--          5060   0   0    11   0
  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:\S+\s+){4}5060\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # SIP TCP listening check
    # Example:
    # 7F1277405E20  0.0.0.0.5061               *.*                         LISTEN
    # 7F127BBE20D8  0.0.0.0.5060               *.*                         LISTEN
    buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^\S+\s+\S+(506[01])\s+", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because SIP is not listening on TCP or UDP.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
