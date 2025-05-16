#TRUSTED 89fbfba9e0b70ad3c9c2619115f1fbd05e8f6c8eef80c7e723d99a0c8ef119779ccd99967783534f4fdfe7d846c58bd2721957fa0eb55efa7832e25aa2b80f1d7de87a4b11ada15158ead2d40bc721cbda48aa64f7dcd4b9a085c0b1c926a16ae8957f16f70152147edb34f4b533881719aa0395eb2414506333b1667d367f3047bd057bbb7725065dadb59692db9ce14dcec5b1dfe477afd9035a7e7fc30d8c8a023a8c1165441469ead4f36816aed06ab828bafc8b519948842de8d5bf5cc7845de5e73e76c15667a026dfd806e9ac53c19413d5a34d15401c216a7089ee2e8a696a630becd7cba9393e3a5798f743bc940910c75ca820f1ed38c9bdce2ac7489eb2fad9031ce4add008f91dd6995efb496f2bdeaf99813cfd91bc09d46323c7ab0fdb997386d357724bd4d55f8afd973e2fc4ebe630ab261e2bb71c5b3d6452055d70a66c116cfb2ff19d5387d023b27ddf9f69e187faf3d575a35b2ca411794e1aa9d90aef24266dec3294b39cc923c2e75d04d9d1812262b11ad0a7b5067adc2cfb2fe4726631e86f9cfd7fcdd8f96670ea3c0a89ac9b4fdae1c848b8cab4d85c77811b0e9d621310dcd313eaae97ee8b493b46f48f06d5affb74f4da74f0376671cc6e108dc360dfe92f9b0df5b40a0e4bbfe0d23c8ed5cb78b1a0292b93a405ec271b58751c65fb7d3743685113833fa1edd9c66f0ae694e9f034c938
#TRUST-RSA-SHA256 0e6262144512b1bd07382502cdd224721d5eb9d091b5ce12ce7a49b09fa6b935a5f9dde4b62734718941a6623facbb3a48b6b8e93217471f185c58fcd0c3d9f0a3802fef72846899331657750232f8923e2f4aba9e172bfc0ef12795cbfabc32986ad0d05e8d18c498fcd0e37a4c47d88183adca6fb43a261d85304a02f5d83c5b432f52728cca75125a5e3d7b259e46a49aa9858e1c629864fd3dfd2c9a4fbb5b600eb8c14128963ae40bbbcb415a6b94d65eb90066c95a8802e046a50e09a12e22dd567d330598192287a7a776a0a085c9231485db8e6d8a0974d1c7e2349747a90d18e7865d3f0636937eed308aa538af754381cd87b1627368b3e7dfe2cde06c24b4fd05f57f7da3c25e896540e288012ed1dd0c2e0552a416e80f15a70374dab263ab6316086de90b6763742d988c0d7d0aea4f04e8cbb4f49754dbfe9245bc67f7ef493da77840292a7ca284881d4ecc55b5681af2f77339a1110696e82bfce84dcb3fe22f7f91d0664e32a3681e2e5bdb1156b9e49275391c8246e08f85096af6851be205213271baf75c2015c31ddfac30cb65cb70e35ded174024604f43b6219701cfabf47edf7198cf20d4f7f845efbb7ab643cfeabb24ea3a03dc298ff71464f576ea3f737cd830222a4e7ae1c5c4657f3b2a9142dab3299035dc35987b7c603ca51f88a68bd1552c847dea67c7c1ed8b953b4935a781bb5e9dd2
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117954);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2018-0476");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg89036");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-sip-alg");

  script_name(english:"Cisco IOS XE Software NAT SIP Application Layer Gateway DoS Vulnerability (cisco-sa-20180926-sip-alg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-sip-alg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d523ce4b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg89036");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg89036.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0476");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.2S",
  "3.15.1cS",
  "3.15.3S",
  "3.15.4S",
  "3.16.0S",
  "3.16.1S",
  "3.16.0aS",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.0bS",
  "3.16.0cS",
  "3.16.3S",
  "3.16.2bS",
  "3.16.3aS",
  "3.16.4S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4gS",
  "3.16.5S",
  "3.16.4cS",
  "3.16.4dS",
  "3.16.4eS",
  "3.16.6S",
  "3.16.5aS",
  "3.16.5bS",
  "3.16.6bS",
  "3.17.0S",
  "3.17.1S",
  "3.17.2S ",
  "3.17.1aS",
  "3.17.3S",
  "3.17.4S",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.2.1",
  "16.2.2",
  "16.3.1",
  "16.3.2",
  "16.3.3",
  "16.3.1a",
  "16.3.4",
  "16.3.5",
  "16.3.5b",
  "16.4.1",
  "16.4.2",
  "16.4.3",
  "16.5.1",
  "16.5.1a",
  "16.5.1b",
  "16.5.2",
  "3.18.0aS",
  "3.18.0S",
  "3.18.1S",
  "3.18.2S",
  "3.18.3S",
  "3.18.4S",
  "3.18.0SP",
  "3.18.1SP",
  "3.18.1aSP",
  "3.18.1gSP",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.2SP",
  "3.18.1hSP",
  "3.18.2aSP",
  "3.18.1iSP",
  "3.18.3SP",
  "3.18.4SP",
  "3.18.3aSP",
  "3.18.3bSP",
  "3.18.6SP",
  "16.6.1",
  "16.6.2",
  "16.7.1",
  "16.7.1a",
  "16.7.1b",
  "16.9.1b",
  "16.9.1h"
);

workarounds = make_list(CISCO_WORKAROUNDS['nat']);
workaround_params = {'sip_agl_disabled' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg89036",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
