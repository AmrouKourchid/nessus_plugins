#TRUSTED 8254417fe518eea8c3eaa34e03cb580c36ec261d5eccf1d0256460c841f87fa307ff6f6a0ce7997728e7d0bd61f81d40d7bb0cc543c8a34cc02de8c9cab77d8eeb0fdde74ce527c9bc5ae18f171fcd5df5ce3ab4bd503bc1f833c85b1703159dfc2d53dd03e57e96ebb7a058d8a2df7171bf846d296b6ec187fb67cf3377461d2de990006f0bcb449f151739cbee3fe9ae6cec3d793b656dc50267af3d1ae19679150bb2d4cb680a1a8f899e4e394451bfd256dd9317249ebf27b94f0e9187bd742bbfb3a090b2206ead82d895417978b00c1a18299434e1413dc7aea0915dc0bbf12ed56d6cbbb61604e9fba765912adea8dfbedb0205c793f53c320278575fc5fae08612a87ce279414932e500be48c2589643e259d30cba1c96ed1d726cc10431e75a6f2147d8d5ff97fbd421c5a8c539275c0ab7d25fd8a319891af2d899f27bf71a8545861bfb65f087f8da86cfce1b34a63264bbed2e593b9fc9928f8dea02e5b2a866ac26bfb1b861d2af8984c8bc0a52ccdd3f02f98c81514a07976b55188ef3b9741152de302450121caf3aaca7bfd19eaf57dce1970e5d205a43152258eadf70a8d7d0cf53145eb79180e696c7bc71b694e11c41897ea62124bf06e552ec626f1ca1c57cdc3c980b90c08a533c27d707299c214b297739e2dfb41d845ce44ca0bbbf74684a7df78dc43984d28c9d23cca20392986f16f08482047b
#TRUST-RSA-SHA256 88752a0a77141c64a610356c0ccf40b518a3c688a5063ff45ff49a227449ac61de4f15c81eba457c4ac90d1326f88071c0235663dcb1f812fd2da6de2c7748caf4f612ccdd7205f5a31b1085ef8b69a4d4ed6a3d53caf92fc0a26b6fe617c633d4c5dc3b17dbca664dc45484ed7d1fa0b99ed3c1c47c33ad266f5824897942358bfb9e0d11cc0834fa4ed5e0b7cbd420b3244c361ab525d5ddd932ad86d59cbe8ae16bb33e28055a1f6de30e37d08a2c722485239fbb3dd58a6ce017e706717013ef709f9ab4f97835a6ee0e14298c5b5c9189c6470d12c35a02cfb78922a09f58c5593df55b4e3c78e9939bb272f9f9ba625509dddf213e9356cfd59e59d228dade0eedb26a51b3c19091d31ba0c139ee731246ebd3b77cec6fa07fd6a89d6d54784689f8350c3c803c0c68b112f9ca970cfa14336dacee2caf8b9dcf0f0ceee8055c86f6f90a13d091102c72ee55aa21b152a49b733d9689c78d10625c54094e2f46f80d310136f3edb0f76abe83f26b35547295ba6c9d3d88210fd816b6616935ee8e2102950ef866b4cb3c39cd22657a1088dcb85c4abac8cc3916afe1281ae7954429829fa4f549c7ba9c4af84587089d6b749e8fa31700d194dcc9cdd458ad3766f5e3f60840615a4d99f4abbd976d7535a8cd93c9d68f1980347ce88d6d7fddf07c5b4a3135a3d0eef794ce7944812b17ab6c0d4fbda1b4d582ecd31d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90862);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-1384");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux46898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160419-ios");

  script_name(english:"Cisco IOS XE NTP Subsystem Unauthorized Access (cisco-sa-20160419-ios)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by an unauthorized access
vulnerability in the NTP subsystem due to a failure to check the
authorization of certain NTP packets. An unauthenticated, remote
attacker can exploit this issue, via specially crafted NTP packets, to
control the time of the remote device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160419-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8965288b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux46898.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");

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
override = 0;

# Check for vuln version
if ( ver == '3.2.0JA' ) flag++;
if ( ver == '3.8.0E' ) flag++;
if ( ver == '3.8.1E' ) flag++;
if ( ver == '3.8.0EX' ) flag++;
if ( ver == '3.2.0S' ) flag++;
if ( ver == '3.2.1S' ) flag++;
if ( ver == '3.2.2S' ) flag++;
if ( ver == '3.2.3S' ) flag++;
if ( ver == '3.2.0SE' ) flag++;
if ( ver == '3.2.1SE' ) flag++;
if ( ver == '3.2.2SE' ) flag++;
if ( ver == '3.2.3SE' ) flag++;
if ( ver == '3.2.0SG' ) flag++;
if ( ver == '3.2.1SG' ) flag++;
if ( ver == '3.2.2SG' ) flag++;
if ( ver == '3.2.3SG' ) flag++;
if ( ver == '3.2.4SG' ) flag++;
if ( ver == '3.2.5SG' ) flag++;
if ( ver == '3.2.6SG' ) flag++;
if ( ver == '3.2.7SG' ) flag++;
if ( ver == '3.2.8SG' ) flag++;
if ( ver == '3.2.9SG' ) flag++;
if ( ver == '3.2.10SG' ) flag++;
if ( ver == '3.2.0XO' ) flag++;
if ( ver == '3.2.1XO' ) flag++;
if ( ver == '3.3.0S' ) flag++;
if ( ver == '3.3.1S' ) flag++;
if ( ver == '3.3.2S' ) flag++;
if ( ver == '3.3.0SE' ) flag++;
if ( ver == '3.3.1SE' ) flag++;
if ( ver == '3.3.2SE' ) flag++;
if ( ver == '3.3.3SE' ) flag++;
if ( ver == '3.3.4SE' ) flag++;
if ( ver == '3.3.5SE' ) flag++;
if ( ver == '3.3.0SG' ) flag++;
if ( ver == '3.3.1SG' ) flag++;
if ( ver == '3.3.2SG' ) flag++;
if ( ver == '3.3.0SQ' ) flag++;
if ( ver == '3.3.1SQ' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.4.0S' ) flag++;
if ( ver == '3.4.0aS' ) flag++;
if ( ver == '3.4.1S' ) flag++;
if ( ver == '3.4.2S' ) flag++;
if ( ver == '3.4.3S' ) flag++;
if ( ver == '3.4.4S' ) flag++;
if ( ver == '3.4.5S' ) flag++;
if ( ver == '3.4.6S' ) flag++;
if ( ver == '3.4.0SG' ) flag++;
if ( ver == '3.4.1SG' ) flag++;
if ( ver == '3.4.2SG' ) flag++;
if ( ver == '3.4.3SG' ) flag++;
if ( ver == '3.4.4SG' ) flag++;
if ( ver == '3.4.5SG' ) flag++;
if ( ver == '3.4.6SG' ) flag++;
if ( ver == '3.4.7SG' ) flag++;
if ( ver == '3.4.0SQ' ) flag++;
if ( ver == '3.4.1SQ' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.5.0S' ) flag++;
if ( ver == '3.5.1S' ) flag++;
if ( ver == '3.5.2S' ) flag++;
if ( ver == '3.5.1SQ' ) flag++;
if ( ver == '3.5.2SQ' ) flag++;
if ( ver == '3.5.0SQ' ) flag++;
if ( ver == '3.6.4E' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.6.3E' ) flag++;
if ( ver == '3.6.0S' ) flag++;
if ( ver == '3.6.1S' ) flag++;
if ( ver == '3.6.2S' ) flag++;
if ( ver == '3.7.3E' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;
if ( ver == '3.7.0S' ) flag++;
if ( ver == '3.7.0bS' ) flag++;
if ( ver == '3.7.0xaS' ) flag++;
if ( ver == '3.7.1S' ) flag++;
if ( ver == '3.7.1aS' ) flag++;
if ( ver == '3.7.2S' ) flag++;
if ( ver == '3.7.2tS' ) flag++;
if ( ver == '3.7.3S' ) flag++;
if ( ver == '3.7.4S' ) flag++;
if ( ver == '3.7.4aS' ) flag++;
if ( ver == '3.7.5S' ) flag++;
if ( ver == '3.7.6S' ) flag++;
if ( ver == '3.7.7S' ) flag++;
if ( ver == '3.8.0S' ) flag++;
if ( ver == '3.8.1S' ) flag++;
if ( ver == '3.8.2S' ) flag++;
if ( ver == '3.9.0S' ) flag++;
if ( ver == '3.9.0aS' ) flag++;
if ( ver == '3.9.1S' ) flag++;
if ( ver == '3.9.1aS' ) flag++;
if ( ver == '3.9.2S' ) flag++;
if ( ver == '3.10.0S' ) flag++;
if ( ver == '3.10.0aS' ) flag++;
if ( ver == '3.10.1S' ) flag++;
if ( ver == '3.10.1xbS' ) flag++;
if ( ver == '3.10.2S' ) flag++;
if ( ver == '3.10.2tS' ) flag++;
if ( ver == '3.10.3S' ) flag++;
if ( ver == '3.10.4S' ) flag++;
if ( ver == '3.10.5S' ) flag++;
if ( ver == '3.10.6S' ) flag++;
if ( ver == '3.10.7S' ) flag++;
if ( ver == '3.10.01S' ) flag++;
if ( ver == '3.11.0S' ) flag++;
if ( ver == '3.11.1S' ) flag++;
if ( ver == '3.11.2S' ) flag++;
if ( ver == '3.11.3S' ) flag++;
if ( ver == '3.11.4S' ) flag++;
if ( ver == '3.12.0S' ) flag++;
if ( ver == '3.12.0aS' ) flag++;
if ( ver == '3.12.1S' ) flag++;
if ( ver == '3.12.4S' ) flag++;
if ( ver == '3.12.2S' ) flag++;
if ( ver == '3.12.3S' ) flag++;
if ( ver == '3.13.2aS' ) flag++;
if ( ver == '3.13.5S' ) flag++;
if ( ver == '3.13.0S' ) flag++;
if ( ver == '3.13.0aS' ) flag++;
if ( ver == '3.13.1S' ) flag++;
if ( ver == '3.13.2S' ) flag++;
if ( ver == '3.13.3S' ) flag++;
if ( ver == '3.13.4S' ) flag++;
if ( ver == '3.14.0S' ) flag++;
if ( ver == '3.14.1S' ) flag++;
if ( ver == '3.14.2S' ) flag++;
if ( ver == '3.14.3S' ) flag++;
if ( ver == '3.14.4S' ) flag++;
if ( ver == '3.15.1cS' ) flag++;
if ( ver == '3.15.3S' ) flag++;
if ( ver == '3.15.0S' ) flag++;
if ( ver == '3.15.1S' ) flag++;
if ( ver == '3.15.2S' ) flag++;
if ( ver == '3.17.0S' ) flag++;
if ( ver == '3.17.1S' ) flag++;
if ( ver == '3.16.0S' ) flag++;
if ( ver == '3.16.0cS' ) flag++;
if ( ver == '3.16.1S' ) flag++;
if ( ver == '3.16.1aS' ) flag++;
if ( ver == '3.16.2S' ) flag++;
if ( ver == '3.16.2aS' ) flag++;

# NTP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
    if (
      "%NTP is not enabled." >< buf &&
      "system poll" >!< buf &&
      "Clock is" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux46898' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
