#TRUSTED 42bcfd5f0c86e948befd53944f6c7c0e3d633bf819b2192ae7bde8de55f02095281155d2a3aff070baf755c3a92ed5d502299b0f8f98934ec4a9bf4929217efe9d99927af884c3284ae951e4b66708003952869825af3893fba8c859b2d6c0eb3d5d7099c895c6ee46cdb51c483dd0c80d45bd48f21f0f1a250887408b65a66ea332f922edb3e4f7cc732f3c803858f75dad79cd24ef107a2fc06d92b7b5d8b0757cbd1c92a14db176d949dbbf5917664d3b97acfaa5e6ac3f3e2d7b987e0ce6cea05b80a7a932c95e0c34a0d2061490ae556b4e9c0399a545710b0d09ae19bf8d13a39d8415d3c3d3c1e5367df77b1a927f05b6faa175cdd5ab9fcebfd95458692296f59d24c4e5373020c3b7363649212a29348f7c12d316a7bc4fd2056fa2f5582afce3c4ec32847bc9ff7f83cc915c4e107186001df99a5d8ac7f5416243c947302037d028c5c27334579d1c3ddd3f4dddad29c83b712396e5ab4eb282995bc712bd0c962dca129c159d3f726de86d75c5affd1e0fbe960617a7a292f6715da90c7cac3c3833a85bc116788847586cd231cf9e520a67c02f509982857540a2c1b8068d8fdf82891d9962a65c1af4e9a4ab781b62b78028336a3569f15c7e8cd3184fceb0bc0219708530a971abc4ff00591d1d449e8bd061e4d969071c8ef549946bcc4e639690f71d752c42635c665ec92fe71dd6ca3eda38333f4a9961
#TRUST-RSA-SHA256 5b79f8ffbc0e794e64450b8a0063236a0ec0a59fd7785d4bf615c029d4e7fefc009d6d80a94c1b146900960080575a26beb1649870e762e27648a2d8744c2deac16a90fa12268c70a643837328c15ba3c44bff0f1d303ead3e412ad4b1c504a71c1f5c3c32623f25fc7a1f1271fcf2e76c8ffa7ab57ec3d9be0b27ed2c39faba59b4ca0512ad6e5f6cbf180601be422d35ec5d1c04f38fdf8c509b6327ce956718e402b7699c0925e973f236a309813bc3d00d2b9b336f81c4d6c434e3d01ea2654603b7446619a36ceb5da530d001390a4a86db425813eab4831fe3b83e19bc87b1449c92343189a166034c188e05de326d67a3c420106335f6612d5a75d9f2e35f653b29c96fe6bb6f7ba5f8390fbec531bdc16f60f8295645d0bf06aca8f726821fac5bd860387a92da2ceab993f0a3042fdb3365fc189c5e46f6c05f9c16387ad7c75acfefc95fafe6fffa5f9ea289148b9ccce26e66b4606ef6a3722c454a48896f647fad916a1ef24c42a4d0998af50d72495568699fc9d5c8f7efce30573d2fa83341e6646e853a3f4b3f74dca6331da833d98f7e10ede6be7614f30766a6ff721925051e2489e950062f6f1f9a03d06dd94bf78a871f08e3793579b37205f68778c2013a96600943c2f0c107deff472eeb8244d4ff88fc35815ccbfccb52cb2082a7f098f8db1cdac1c4c75812dd22183e8f5f4803ed6465896dda7a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90527);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2016-1361");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv17791");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw56900");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160311-gsr");

  script_name(english:"Cisco IOS XR GSR 12000 Port Range BFD DoS (cisco-sa-20160311-gsr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is a Gigabit Switch Router (GSR)
12000 Series router model and is a version that is missing a
vendor-supplied security patch. It is, therefore, affected by a denial
of service vulnerability in the ASIC UDP ingress receive function due
to improper validation for the presence of a Bidirectional Forwarding
Detection (BFD) header on the UDP packet. An unauthenticated, remote
attacker can exploit this to cause a line-card to unexpectedly restart
by sending to the affected device a specially crafted UDP packet with
a specific UDP port range and Time-to-Live field.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160311-gsr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07a86a86");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20160311-gsr.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1361");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = FALSE;
override = FALSE;

cbi = "CSCuv17791 / CSCuw56900";

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model    = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (model !~ "^12[0-9]{3}([^0-9])")
  audit(AUDIT_HOST_NOT, "Cisco 12000 Series");

# Specific versions affected according to Cisco
if (
  version =~ "^3\.3\.3([^0-9])"     ||
  version =~ "^3\.4\.[1-3]([^0-9])" ||
  version =~ "^3\.5\.[2-4]([^0-9])" ||
  version =~ "^3\.6\.[0-3]([^0-9])" ||
  version =~ "^3\.7\.[0-1]([^0-9])" ||
  version =~ "^3\.8\.[0-4]([^0-9])" ||
  version =~ "^3\.9\.[0-2]([^0-9])" ||
  version =~ "^4\.0\.[0-3]([^0-9])" ||
  version =~ "^4\.1\.[0-2]([^0-9])" ||
  version =~ "^4\.2\.[0-4]([^0-9])" ||
  version =~ "^4\.3\.[0-2]([^0-9])"
) flag = TRUE;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XR", version);

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  # System has to contain serial network interfaces
  buf = get_kb_item("Host/Cisco/show_ver");
  if (!preg(multiline:TRUE, pattern:"^\d+\s+Serial network interface", string:buf))
    flag = FALSE;

  # Specifically bfd ipv6 checksum MUST be disabled to not be affected
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (flag && check_cisco_result(buf))
  {
    if(preg(multiline:TRUE, pattern:"^bfd ipv6 checksum disable", string:buf))
      flag = FALSE;
  }
  else if (flag && cisco_needs_enable(buf))
  {
    flag = TRUE;
    override = TRUE;
  }
}

if (!flag)
  audit(AUDIT_HOST_NOT, "affected");

# The fix is to have 4.3.2 plus a vendor supplied SMU
# so 4.3.2 doesn't necessarily mean that the issue isn't
# fixed
if (flag && version =~ "^4\.3\.2([^0-9])" && report_paranoia < 2)
  audit(AUDIT_PARANOID);

report = "";
if (report_verbosity > 0)
{
  order  = make_list('Cisco bug ID', 'Installed release', 'Fixed version');
  report = make_array(
    order[0], cbi,
    order[1], version,
    order[2], '4.3.2 with Cisco SMU'
  );
  report = report_items_str(report_items:report, ordered_fields:order);
}
security_warning(port:port, extra:report+cisco_caveat(override));

