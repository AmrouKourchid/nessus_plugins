#TRUSTED 9cf837acf4ad747f0262e4f157e850788c3787b0ecf3f19ed77afda55661af3d6bcb759de3364330511ee45c2aa0ca4097e6786edab706fddd7ab4456d9f25d7ea3f1720b309ddce7a22afcb38ce4eb1afad33c9fa26db0802d8940a1447baa4d34002e243bc0013f5653f10d5e922bf5e019bf2fec308931e434f09353027f7dd228c080f0857f4414f996e108afb8817dc4cd74b13cb8ee6614d8d79b5e2d9296693cbeb1e614c1263fab0453f8bbb32b5be03f23858906c6e78787e990ccaba5dcfdca2c94838214aae5c71a5cb2fa1f8e8f1ea1a4ac87e32d5a9daad4fd4c739d97197d7e2c799a7e85a4733f612a810ed27ab350df4112b845b988aef80b7a7d7fcbcad27a2cc3b47292ae4b7fd7910ff7e8dec191eb2ad044b5f74abce355f6ba817b09355c53da14677e7df36e1518bc557598adbc1c3c5a03a1467bb334a6351d1f3a43ec05bcf7febbb1bbc76ae7b4f66aa90d9e39a11fe2ba8da0045be6468f69f0271c175631ea76ff7a25fe71de3daff1f2e0b9c885b74721329ab76dc0132cb747715b51563e6930fa0f142f52d3d37e8e45291b9ff37fd620200e8b6b0b014b127da0f47f71f585abd5da9c4746e6865973a1817a5a54869d77d9c72c0e9d506cbbb25c932eb551aa1d94d622bb92289ca567d568bbb4aa5bd06c73fc4dc460657ba3c5b769e496347d2af4e5c711523b949132ecf81fe1d65
#TRUST-RSA-SHA256 697c4cbc3b110ee2412eee0220bfcba49485cfb21aedb70ae4ebd99de2f6ba69570e7efff35af51257936f3f47525cddb49c9e9add93604ed2712f0f5d0febe963897a08834eeedb8dfe8aa7dafe6da94a8d21a495d6cdfc40c503870ddde72a3957be0e820452717397a3b635b212e002dfcc3afd340e4a90d0dc962d2d1501f95105700d658029d118b7049dd66eda0ca175ce8583b433c53ef2ef2eca933406da481624ab31bf28d2810bc5bb395fe457c2c6a38b6fccebba4d730ee831278c0500040bf980b8b622963ae02712cff7a8fb8e1668da52361d88ebe7a1b341b1a22e0498fab762afde465c9c2f1aa6b0a019437dab2614b996b36a7334285137a294ec69450247a4fc16ab40b4afd96186b45012f744a32146cdf819a4ddd698e4ebeac91114afe47eae584a6d2347d1bac78621e99672dc1098e9a5f417342e751c1dfcf1166c9d6fe32bd19c81a9dc53cbf01f95ed01e6cab324d548c0c0f07c2e83a7c32f2e2711acbf201b4f81503f500b7b969df1d1a5d308c7eb23ed983aa011606f183559a8332b6b2abedb91f6dde0e81b25144b9ba98a8e68fa8addf00eed9b0a8005282ada342eb8921ff8efac6f67739682508ab87dd196b647fd706afee7aa41e3170ef207f0928ca881dc9cef5643de5088b4de771b464898666d7410c6ba9b1252c13bcfff9b6513c05c6befc3fde9648cd118fbed9b4614
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93123);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2016-1459");
  script_bugtraq_id(91800);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz21061");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160715-bgp");

  script_name(english:"Cisco IOS XE Software Border Gateway Protocol Message Processing DoS (cisco-sa-20160715-bgp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE Software running on the remote device is missing a
security patch. It is, therefore, affected by a denial of service
vulnerability in the Border Gateway Protocol (BGP) message processing
functions due to improper processing of BGP attributes. An
authenticated, remote attacker can exploit this, via specially crafted
BGP messages under certain unspecified conditions, to cause the
affected device to reload.

Note that Nessus has not tested for the presence of the workarounds
referenced in the vendor advisory.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160715-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94ed1c7e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20160715-bgp. Alternatively, set a 'maxpath-limit' value for
BGP MIBs or suppress the use of BGP MIBs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1459");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

app_name = "Cisco IOS-XE";
version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (
  version != "Cisco IOS XE Software 3.13S 3.13.5S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.2S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.3S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.4S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.0S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.1S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.2S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.3S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.4S" &&
  version != "Cisco IOS XE Software 3.15S 3.15.1cS" &&
  version != "Cisco IOS XE Software 3.15S 3.15.3S" &&
  version != "Cisco IOS XE Software 3.15S 3.15.2S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.0S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.2S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.1S" &&
  version != "Cisco IOS XE Software 3.16S 3.16.3S" &&
  version != "Cisco IOS XE Software 3.16S 3.16.0cS" &&
  version != "Cisco IOS XE Software 3.16S 3.16.1aS" &&
  version != "Cisco IOS XE Software 3.16S 3.16.2S"
)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# We don't check for workarounds, so only flag if paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

## If the target does not have BGP active, exit

caveat = '';

# Since cisco_ios_version.nasl removes "Host/local_checks_enabled" when report_paranoia > 1,
# we will try to run the command without checking for local checks; a failure will return NULL
buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_bgp", "show ip bgp", 0);

# check_cisco_result() would cause false positives on devices that do not support BGP,
# so we are only looking for authorization-related error messages or NULL
if ( ("% This command is not authorized" >< buf) || ("ERROR: Command authorization failed" >< buf) || empty_or_null(buf) )
  caveat = cisco_caveat();
else if (!preg(pattern:"BGP table version", multiline:TRUE, string:buf))
  audit(AUDIT_HOST_NOT, "affected because BGP is not active");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCuz21061' +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + report_fixed_version +
    '\n';

  security_warning(port:0, extra:report + caveat);
}
else security_warning(port:0, extra:caveat);
