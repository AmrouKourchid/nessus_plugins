#TRUSTED 4c2cd7cb3314f1db19e4c92bd152ada725e9793f223bc58ab753d170405debe5804f7cc89cc8fb0787737a2cbe053c5b81c56306fe1e3a4f9f0224e2b29163f1a0576fc538a6017b1709ada3f9aa7eaf0f49620db030330770c6147976a8b896a3c76309b6e2530ed001e6e54d7bcd4df820afecc53467a6aa5070ad69241c23493bb52e21b094f43e72b8f3cf59ae9c816a19216bdc5f2caa39df5e007d5933dee25114c1adf156189cace1fa6d99a69d3aa90914cec48f9f0656ee453a3c8770a0f95f486b45846599de84e6b732ca860dd3f5290834ebed3a4ace1aacdbeccb94e90622c19d21dc895d9d9a771fd1fb1df18e2b7395503241c585a91f6dddeb8730c94e2092356fe09b1bfce857d3d01264c07f29506f96c2f570d7db75362ab8f4666d693d9412794de5ca476fc0f4e844ebbbec9a90cb9694cc84405f0c0b51bcafddcb4df3b77481ff14500aa25cf814477561389dcd368e95bef05c9b6f1ce6b94ae7370dc02e442a505b081a6dfb0c533d3e8edb6276b781904d52f9b0f83ea4c3b0a1e28a9a8507f42eb7f21f26c2c07401c4270674625c00336f9c67f1d51746756478519850f9e002616f18728ef2a618b03c6903bd907b616b344857f8ab43133f9df6b7897fdce840218fcb7529f0d893e04de8d8dc3c7ca67ef8292a30e9386314a433d44db4cd0539563f78ffd2a91c0c392fa113e510ebc2
#TRUST-RSA-SHA256 776f68f4b7cc4a08e13769f2041525131f4781fb4537af5ed9fcd830e00d8d8419701c855e10f192ca60ffcc447b4b5a26e6bbb0f071b8e6c3514debae5c711b329a4f4e6390bf8c9b4143602c554dcb02484eb44177a1edcf0ac36eb23c423c05bd31c12a32bb5d3858589eb33bcba98c5b4b08c2f46da0fb65ccf50bf26cb1ea90f0f778e91f6ea8d229a077c10862b33c9d410aecb21324798688be655841d70a61e040d339cb6886c472cc7136c08d39e4c9ca1edeb2678affa918b6e65bdaf799e533290aae2491fa09001de6b00eca15eaa02e14ffdf9d418e97d04658e71dc7bf89b7c53f94dabb3e78ba8abfbf54ccbc41e885f138c3849b8fffce6b840a3ba38bad692e91e5f38d0afaf4fcc9bb170d624d9e1045a58daa4c697a247a77c62d40c263a9e0891c24be26fc145501dbf7760cdf123ccff816793556897129b71ad3597e438bdb363d550a438c07292ef9c73e0ecf1ee84dd3195d7ddf9d11f453cb2ec99e6883c7d63977bbd79fe9527e8e52e89bdc2d1007639a9b4d486ddca8d2982fa495b976b793bdd717ed64e0e835082cb4b96808f48bf5f24975f1e32e425863e1a92cdbd0626c943e42010eba09a83fb556cf5acd2a672aedaf7145dc9f63b0d0c365751a71afe7db9b3bd99e68cf8786c8fb48be1aaf6a16a4c71b8f0bc3aba70739c6157eba4c18829026908cba0739893e0b218ce18424
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85125);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0681");
  script_bugtraq_id(75995);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts66733");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150722-tftp");

  script_name(english:"Cisco IOS XE Software TFTP DoS (cisco-sa-20150722-tftp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the TFTP server functionality due to incorrect
management of memory when handling TFTP requests. A remote,
unauthenticated attacker can exploit this by sending a large amount of
TFTP requests to cause the remote device to reload or hang, resulting
in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150722-tftp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f445f230");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCts66733");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150722-tftp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCts66733";
fixed_ver = NULL;

if (
  ver =~ "^2\.[56]\." ||
  ver =~ "^3\.[1-5]\.\d+[a-z]?S$"
) fixed_ver = "3.6.0S";

if (
  ver =~ "^3\.[1-3]\.\d+[a-z]?SG$"
)  fixed_ver = "3.4.0SG";

if (
  ver =~ "^3\.2\.\d+[a-z]?SE$"
)  fixed_ver = "3.3.0SE";

if (
  ver =~ "^3\.2\.\d+[a-z]?XO$"
)  fixed_ver = "3.3.0XO";

if (
  ver =~ "^3\.[2-4]\.\d+[a-z]?SQ$"
)  fixed_ver = "Contact Vendor";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

flag     = TRUE;
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  # TFTP Check
  #  Router#show running-config | include ^tftp-server
  #  tftp-server flash:c2800nm-adventerprisek9-mz.124-1
  #  tftp-server flash:
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"tftp-server flash:", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}
else override = TRUE;

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because TFTP is not enabled");

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
