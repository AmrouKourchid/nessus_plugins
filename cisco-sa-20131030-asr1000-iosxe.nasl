#TRUSTED 2dacf003ddef9a1c8e7bcd4eed5783c94d82ef948c907f6867bce60d0df699ca7aa8bb5965cf4cac12c3ccdc352f14a4a2c0879d5d4268d26548eacfc9978d1022d397e99a38c6565254a4deb96445db413eb9f012b6d606bc15afd3c63080ebabcc8d4326ebdd3a627899c459b93ee3a6699737f9f1aad9bafeb10682fb546772c8982a34a02617ed5407f76b58e1d99c14bf8b6ffce7978ed1b65bf84c790be9b6f6c19ee31790edc1a3d634c1a9bb3fb5f137c2443a77c62bd61f17af4c8b9fb9d466cb267a9799d5ae94654e35fe359d037ee7d2fe720d70b7a0eb73399c2cfb5917bdb495fb397d89cdb8935a4c87056b1f586355b62b0f9800acef64524ed97cbd69164edfd5d4aa7557e61f7826b160f5d9d73cf8d5faeca9b162002ce41aeb880b41b2d15cc86bcc0cff79828658d482fab758a2139d1dc576bd013ec7988c3b96fe7f82a9d58cff43d0d4e9630f5699e1dfdf937adfe53c23cff80da5d03013287611928caea89ea7e3fea712f9b28072662c4ca6e62ad8703cd20cfdadb6d8a5f8310127798a51e76940e102808c915fea55d47a93845914a30aca91e453b0b1a14e5ca3ee4b3f7b1e21d453dae29574717fc51da01b3d5d84097bc5eb044c3d53caa5ad542bac84fdcf3f9e1b1e766436e9d6d195c9587c60e2ad30c1c7a24ac5906a6a5ce3af2c42ec9928a102b248e170016d3187f8585c73e0
#TRUST-RSA-SHA256 85b6ace7ac30e9c83a355e879abc6932e55827cc0364b8475ae7d079e6c6b96664063d3924d01348e5dc06c73dfe078bac303d5ef8a24b265495c39c743f3fd32ff102d046f92b4244bd7f80d1a0910920a923c9ae03f66aabb1c0f6a3ca9974dd3d92a35d8e52111c2061bdf63aaae995cc5df0660b04a5ebc74c7d8bcb7a145711a32a3f0cabe6f48bed7c2e568a9240584e17c17b41a168d4d56c4f667e57b11e43acdd82f428015bd2b31ef6347953050a82e3289f8272929f516bd82b6b753cd39b6257be4d39a89761f6aef9b2b53da9267fc0115cd4868e6fe31f2055d3e276abbe415423e5cb9aebdb596093468f13a1f6bdb41a62bd313ade2976fbd7ac6b27c60074922de601f768b06ee3d181745e229a06ca40a7697433ca613271b44ee113a2331e97cd60255ff85dcdb6fb04b2d9feca04dadc906971783241cec3310010b3c9b970d119631be0d9da6b0adfb6bdc997c89246f36f0ffb430b6dac1cd031714e76c5de7d37a8fc9e43bd704654ef7177245669205965cba358aa4f1497fd098ce58a6c1f810343b1702a197d6be1475d5bc966493e678d47179d65e46d853995ed153c9b20b1fc8930aa59d5971fd9d69ef0972b2122a615c5980de9858645fa2cdaa2b6c9392ad1d7b7ed7ac4143b377f64fe4dd785b48b500ab29886ae520ec7d6069f1168aeb382160ad8d918d2319d772020f86e32ca0c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70784);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2013-5543",
    "CVE-2013-5545",
    "CVE-2013-5546",
    "CVE-2013-5547"
  );
  script_bugtraq_id(63436, 63439, 63443, 63444);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt26470");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud72509");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf08269");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh19936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131030-asr1000");

  script_name(english:"Multiple Vulnerabilities in Cisco IOS XE Software for 1000 Series Aggregation Services Routers (cisco-sa-20131030-asr1000)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XE Software for 1000 Series Aggregation Services Routers
(ASR) contains the following denial of service (DoS) vulnerabilities :

  - Cisco IOS XE Software TCP Segment Reassembly Denial of
    Service Vulnerability (CVE-2013-5543)

  - Cisco IOS XE Software Malformed EoGRE Packet Denial of
    Service Vulnerability (CVE-2013-5545)

  - Cisco IOS XE Software Malformed ICMP Packet Denial of
    Service Vulnerability (CVE-2013-5546)

  - Cisco IOS XE Software PPTP Traffic Denial of Service
    Vulnerability (CVE-2013-5547)

These vulnerabilities are independent of each other. A release that is
affected by one of the vulnerabilities may not be affected by the
others.

Successful exploitation of any of these vulnerabilities allows an
unauthenticated, remote attacker to trigger a reload of the Embedded
Services Processors (ESP) card or the Route Processor (RP) card, which
causes an interruption of services.

Repeated exploitation can result in a sustained DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131030-asr1000
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91b80ea8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131030-asr1000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/07");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report_extras = "";
override = 0;
model = "";

# check hardware
if (get_kb_item("Host/local_checks_enabled"))
{
  # this advisory only addresses CISCO ASR 1000 series
  buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
  if (buf)
  {
    match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
    if (!isnull(match)) model = match[1];
  }
}
if (model !~ '^10[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# for each cisco bug id, check version and then individual additional checks
cbi = "CSCtt26470";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.2S"; temp_flag++; }
if ((version =~ '^3\\.5[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.5.1S') == -1)) { fixed_ver = "3.5.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (
           (
             (preg(multiline:TRUE, pattern:"Match: protocol udp", string:buf)) ||
             (preg(multiline:TRUE, pattern:"Match: protocol tcp", string:buf))
            ) &&
           (preg(multiline:TRUE, pattern:"Inspect", string:buf))
         ) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------

cbi = "CSCuh19936";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.9[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) { fixed_ver = "3.9.2S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (
           (
             (preg(multiline:TRUE, pattern:"ip nat inside", string:buf)) ||
             (preg(multiline:TRUE, pattern:"ip nat outside", string:buf))
            ) &&
           (!preg(multiline:TRUE, pattern:"no ip nat service pptp", string:buf))
         ) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------

cbi = "CSCud72509";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.7[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.7.3S') == -1)) { fixed_ver = "3.7.3S"; temp_flag++; }
if ((version =~ '^3\\.8[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.8.1S') == -1)) { fixed_ver = "3.8.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"ip nat (inside|outside)", string:buf))
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
        if (check_cisco_result(buf))
        {
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP100", string:buf)) { temp_flag = 1; }
          if (preg(multiline:TRUE, pattern:"ASR1002-X", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------

cbi = "CSCuf08269";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.9[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) { fixed_ver = "3.9.2S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"tunnel mode ethernet gre ipv4", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE, pattern:"tunnel mode ethernet gre ipv6", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------

if (flag)
{
  security_hole(port:0, extra:cisco_caveat());
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
