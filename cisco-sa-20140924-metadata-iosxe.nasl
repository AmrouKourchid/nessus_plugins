#TRUSTED 9d7f1c730493b20d15e356d00807106286ba425395ffd9c93a92c96e7aa3ab8dc53ad258d601984fe0c314171b1948302c2b951127b59107830c87e4d0677fb030ba8abbee75e7aa3ebd48d881829418b926d3154aed372906c41e31a09d728160a771209c3e6f6811a4650ea0e68fa08a06aa8363b8810ba538ada4409e29b64a7623c4b62837080942b0c49b5fce4950e7d81088ad651a4451f1bdd741f95af9200a51a0a4b38ae94baff88a05c7223c1edd70d41eb4fc3ae6730e0d2533a40899bd9d13058b54d6ceef8386776a27f7b954165e657b4c65714736c572ae585590226c3d3c5837d71b644b57f435d549187aa4ef179f229e3bde8f91d4496436a494371d91830ebf47d606bba3604b3c1594aa844817b063804aa210125435faaa5e6b42622e95f504860025c37298a64c2bad8b213dda841f17136b8c277db96ee7518e6fd80dc28df20edfbbf2d046f9749e39055bed2f933c7ed04bfdbe76d5daa8b64da163acbe99d8e47d128b72c06be551dde4304228c09bf956ea155b906c444657b38d3572dfeb09525c98fe968b4c45910de49350af9bc466253997147cd1de8908fe34ee824af960be25491955a08fe574c3ba72ee8cc7b191ec9f653053b5c1bb592c147ddffa5247d1e980d2876edda2f7eda337ada51e8a83d969ee4cd1254dc89cd3b24ba0a41e78164250f1ddab98dd35250a678cc6ebc4
#TRUST-RSA-SHA256 1d0010dcdfcee9cbf0acde9ee859cb36e72220a133f2fdd9f8005b02d512bd3e8d7ff805bc326f77222f54de9fd7836d61e6d253a282232b1345deb295f70207729c5c90d4e8fa5797f149abb07bc5556585f4d7cbf19e484ebf6c90f96660c40c9e5f7979861902e5d3f30ea798af7b846de7ab06f7c3d02a80401ba09ce321b7b5ae104d5c0521132ff361220428e42e4a6dd87da075282c470fa576a15dff95f27635be06281ef2a9657e8e549a989e659812ab0eb3ab44ad150e6d0ea41dd3a1845fd95f97a145c9150aff40457c4b6beeddf005bed8c8a5d000695739596d247a5422b2fa879ca9d1b23cf4e9c842015366e29ff089c3e9dbedf6aaf9e4ef89838ba69b63b25388419b3f8a7b8452456ce09fd1d14d94fc92d8f810aa11136491c0fde9d26e225c6d73ec17b50735ffe29d89bd713f363074b166c18a6ee52ecd6c729df3ff11cb4ab7b806cf7dbf69f424aa1bf1059aa831e6ad08100faefe8b7ed905ee54960efa587d3c0505d1e39c1326cfde818e54be23aedf215c6aafb21fb87e1449b91d7f53ce7207cf9fcbb85fa0a174d5ff3f6ceb0c907b6f85838be4c751040344c81741ec6bbed0e26ea41242a292c35a1ec1eb28a868e5ac131fbe2713c506e712df3ce1005215218f64e25e3144911b7e66487e60a54ffb06ef4c35184a47919a3bf1d5eaff13282faf6a708895c32f9e328762fc726d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78032);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3355", "CVE-2014-3356");
  script_bugtraq_id(70130, 70135);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue22753");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug75942");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-metadata");

  script_name(english:"Cisco IOS XE Software Multiple IPv6 Metadata Flow Vulnerabilities (cisco-sa-20140924-metadata)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by two vulnerabilities in the
IPv6 metadata flow feature due to improper handling of RSVP packets. A
remote attacker can exploit this issue by sending specially crafted
RSVP flows to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-metadata
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?102835df");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35622");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35623");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCue22753");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCug75942");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-metadata.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCue22753 and CSCug75942";
fixed_ver = NULL;


if (
  ver =~ "^3\.6\.[0-2]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.(8|10)\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$"
)
  fixed_ver = "3.10.4S";

else if (ver == "3.3.0XO")
{
  cbi = "CSCug75942";
  fixed_ver = "3.3.1XO";
}

else if (ver == "3.7.5S")
{
  cbi = "CSCue22753";
  fixed_ver = "3.7.6S";
}
else if (
  ver == "3.9.2S" ||
  ver =~ "^3\.10.(0a|3)S$"
)
{
  cbi = "CSCue22753";
  fixed_ver = "3.10.4S";
}

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # metadata flow check
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*metadata flow$", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # IPv6 metadata flow check
    buf = cisco_command_kb_item("Host/Cisco/Config/show_metadata_flow_table_ipv6", "show metadata flow table ipv6");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^Flow\s+Proto\s+DPort\s+SPort", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the metadata flow feature is not enabled.");
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
