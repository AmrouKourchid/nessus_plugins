#TRUSTED 11d175a194789cbfc51e5aa0dcbb70e9724757e21f04d07129adff1d3687e87ac5c79867a60faad3b869031f4d4692ce869ce9f6afec273098b39ae7575aa53783b619edf707b5dd1334b80b199f813c023cb104c2f21592c742470a5059d825a47343e03f2cfeb6253a3a653b7c06ab13961038f87fb0035096d34992fe38d190276c4b5c43f9fedbac4178d25f1d36825e91b078a0b9cffabe24757d6a5e99e6a6874037926929436c2344bf579a7b9fc96384187ca155cbc5597f8af19ac334a8000e9998b803db4f56cac32a1d00b1da2d320d73d352c94f749fa7f621f68baad9ab77f4ac34ded6e872a6ab9f7da5b3782593607fa10d7bf4445007f3ae6d3c10ba171045bc972b249e6914b1bb3e1568962140d1c63510a6af5a21107449f6a25e3389c043c65850f17a7c10fc6317d6dd9546ec78fb256e88fc144f746d2f14d91bb38105539d25a1618ccce903f0cef7cd0543ccbe4c50afa481dd8a9344757993487d07623b7e9fbcf645b1cdeb83de3935ae064728eb2135a89b83fdaefbb834abbae23f6925bb0054ddb2f9ae7b60fcc5fc20ecc155af818731983a3596d11931913c0b49c8916f7feaf732e7be27ab16655f1ee1d9f4199306ce021a2edbe46ae51c1e2ef06263084d7540de4b0df94d31c0a2437657a1191770d620f0933aeda83122191f764dfa7c13dc8d8dcc77f11ec1d94af9ef99788cff
#TRUST-RSA-SHA256 30ec7131ae485d9aa1e258bb4e25d99beb4283443ddc74086bed3fc10590dce6f6ea21bb0d03d03bfcfaaf9f61eb21ff18cda4066da4938589d3c39290a58e604cdd1f5ca11fef31b52c8621058f14a0f0996bbd15486955f16e638b124267d541019ba6fbba8a3b657b3bf26c983d08106e5eaab49e21f04f58a39050e070cba65457bf7af4952faa6ecf3aaab0985fbfb1d543e2c18ab1b580c85d960bbff15b6ba92f810ef7cab823979677ad7584774209c2fc62cda45dfa58267d922f96baf068237a714f7e6a6f700c6ec4454067c3438ee8a18365ec121d9c87db8dcdd21d0e6f98df0cf9454c81e522e934d0b842a661d84b7f0ecf232cfbd533b920476e8931c559f511f9863f379f994ae802735b0ed411b1ebb66fb9aef6c69f5567096dc39dabc2819af72f316b45eb4dd273faf8c658b1fee39ab58ad878aad2504a3afa2abf7a618591475fd5af46b8463532e54cf902285debbf94c9bc2ab6ce485fe315c92063797a28d66fc9013067dea39a82036acdf9695d99fba60b541d9ef1246eed43d8034307ebb015f813dbaf3c9a1e8674a0fa0682587f0a3ccba5783175333ab67a1df1778c3a3a35fc6160fefff12a284f1ad96a4150bb7cada6b7d39a3c668345e5759b1a2f7605f2353b61a4b0aaab4def8731a82f54a8ac1935a2b8c03b69f3bb9706185ac2921797f149154ec299fcfd2fbebda8c74d0b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93122);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2016-1459");
  script_bugtraq_id(91800);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz21061");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160715-bgp");

  script_name(english:"Cisco IOS Software Border Gateway Protocol Message Processing DoS (cisco-sa-20160715-bgp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS Software running on the remote device is missing a
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

app_name = "Cisco IOS";
version  = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (
  version != "Cisco IOS 12.4(19a)" &&
  version != "Cisco IOS 12.4(24)GC4" &&
  version != "Cisco IOS 12.4(24)GC5" &&
  version != "Cisco IOS 12.4(15)T17" &&
  version != "Cisco IOS 12.4(4)XC7" &&
  version != "Cisco IOS 12.4(22)YB2" &&
  version != "Cisco IOS 15.0(1)EX" &&
  version != "Cisco IOS 15.0(1)M" &&
  version != "Cisco IOS 15.0(1)M10" &&
  version != "Cisco IOS 15.0(1)M9" &&
  version != "Cisco IOS 15.0(1)S" &&
  version != "Cisco IOS 15.0(2)SG" &&
  version != "Cisco IOS 15.0(1)SY" &&
  version != "Cisco IOS 15.1(4)GC2" &&
  version != "Cisco IOS 15.1(4)M10" &&
  version != "Cisco IOS 15.1(3)T4" &&
  version != "Cisco IOS 15.2(4)GC3" &&
  version != "Cisco IOS 15.2(4)M10" &&
  version != "Cisco IOS 15.2(3)T4" &&
  version != "Cisco IOS 15.3(3)M" &&
  version != "Cisco IOS 15.3(3)M7" &&
  version != "Cisco IOS 15.3(2)T4" &&
  version != "Cisco IOS 15.4(3)M5" &&
  version != "Cisco IOS 15.4(2)T4" &&
  version != "Cisco IOS 15.5(3)M3" &&
  version != "Cisco IOS 15.5(2)T3"
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
