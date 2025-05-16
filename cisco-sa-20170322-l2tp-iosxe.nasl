#TRUSTED 790ce9f9eaeccd3ddc9dc18e8117ab1232bd17044108b6522d8016445ca6a2c9345649d28c2642485dab3686d3a29069853c35039eac0d9dfa8d353cb314e05f69fdc4193fcc06dd89dd95bb31c31f4cb91aec3468114d6e41023656939d2e10e485ffaf7a2bbc2b3618a701c75d4944f3e366080f8070621e27d3e8f997e5da6eaee508ac37d1c4eeb05d4436c0d0a68f3ed236674087a838ae034de0591a36e7e48a6307a41259e8b6dd03c2d7c89812cbd7c972f5346582a9af0a3f3dd00f4df603094f8acd23ce6dd2275265de970fac7ada5dcdca7035307df89924515676e7300e8a08656f63a02fcc61d7281c8a6bd846af413e0c9c986646adcf58528d908a6c794ac6262c3f67c5a3e6ffc99271995e7810d23995949991358580bd5206e48d4ea442b73aa0140c85bf51d36049872f45612093652a64fc9f62d6c65ed61586b8727f9a5f073094d580650c22608238f7df4adee0387b7dd0ba4395cfa3281880ff111b27f5b33720449f9f2d687b99b7bfba8e17f6f2eadbd6e875942e0f1b60f03d798e242e2bcc24a278b3490abefad1fd7d7a6cb0a2825ab54c900f60bf7a7c6105da4f4eda8e5f9928921907a29592e9885d4731fb8f3341a0d06aeeb8fefc73c0b9c9bfb4fa1ef01ce2f3283069db46fef0d387a3ed597613655f803f881442d74bcf63c0c77939b0e186e25693b17fa984a162b24ddfb974
#TRUST-RSA-SHA256 3d92b3fc8606cba448449ebadb08ba94518dc13e1a7e5e4741b0b9cd0676d7fb0d46fd4f261527d895283ce778ef67d7988f448fbbbee509952cbff3ecaadb0c486926be65d74542a05258b91fd2bc86822bca373cfb124bc2f19e60f98daceacc17243bce36e08e390ef44cff2e3bf990578b7663221697ce073889ea6ad897539012cc06721d8eca8d1b7f2b1fb3d7bdf3b66759af132102e69a190552c232b8de27aa40e6394ba38e12b29d7a82921321f0cca36c0dd2550c242dcadc9cf03d40bbd4e7c464c4359f2edcf8c233409a30330a1dadbadc994ff7d520c7b01ac1c2bfe532d80f2402a307df7034ad2c15a54888d053939d306fb06f3085f592cfbc67158dbff7a37974489c022f3b0ab1466081e6c106d13848603d6ed357f38cdfeb9fde02c92cdd6766938f2c9ade7280e992ed9051d2c1d7d5e5d20293c0d407e2566fba001f4179e554f6ce487d953e249153097d4437b33d1faee64489ecd6ffe2043c0ff9c24030d16d4fca4ea46c49c2c4e67effc7374c4d1b7b39495ff964d91978e67b56ef270c7fcd72c06dfaf737b003be86987e4e86592f7b48bc8f52c253944407dd73dda679897871cf945066145833a0cad0230f095b7d0e6d2400178551df2149dd16f5b1ef2923db76ad7353fa897a028c1e5173b8be74fee15d5a96f5d2ad1ea6fc408a9c05a707f93364c9e05ffb52c2cf1d48f17707
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99029);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-3857");
  script_bugtraq_id(97010);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82078");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-l2tp");

  script_name(english:"Cisco IOS XE L2TP Parsing DoS (cisco-sa-20170322-l2tp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in its Layer 2 Tunneling Protocol (L2TP) parsing
function due to insufficient validation of L2TP packets. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted L2TP packet, to cause the device to reload.

Note that this issue only affects devices if the L2TP feature is
enabled and the device is configured as an L2TP Version 2 (L2TPv2) or
L2TP Version 3 (L2TPv3) endpoint. By default, the L2TP feature is not
enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-l2tp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4fc7ea8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82078");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy82078.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.4.0S",
  "3.4.1S",
  "3.4.2S",
  "3.4.3S",
  "3.4.4S",
  "3.4.5S",
  "3.4.6S",
  "3.4.0aS",
  "3.4.7S",
  "3.5.0S",
  "3.5.1S",
  "3.5.2S",
  "3.5.0aS",
  "3.6.0S",
  "3.6.1S",
  "3.6.2S",
  "3.7.0S",
  "3.7.1S",
  "3.7.2S",
  "3.7.3S",
  "3.7.4S",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.7.8S",
  "3.7.4aS",
  "3.7.2tS",
  "3.7.0bS",
  "3.7.1aS",
  "3.8.0S",
  "3.8.1S",
  "3.8.2S",
  "3.9.1S",
  "3.9.0S",
  "3.9.2S",
  "3.9.1aS",
  "3.9.0aS",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.10.0S",
  "3.10.1S",
  "3.10.2S",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.1xcS",
  "3.10.2aS",
  "3.10.2tS",
  "3.10.7S",
  "3.10.1xbS",
  "3.10.8S",
  "3.10.8aS",
  "3.11.1S",
  "3.11.2S",
  "3.11.0S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.0aS",
  "3.12.4S",
  "3.13.0S",
  "3.13.1S",
  "3.13.2S",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.2aS",
  "3.13.0aS",
  "3.13.5aS",
  "3.6.0aE",
  "3.6.2aE",
  "3.6.5bE",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.2S",
  "3.15.1xbS",
  "3.15.1cS",
  "3.15.2xbS",
  "3.15.3S",
  "3.15.4S",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.7.4E",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.16.0S",
  "3.16.1S",
  "3.16.0aS",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.0bS",
  "3.16.0cS",
  "3.16.2bS",
  "3.17.0S",
  "3.17.1S",
  "3.17.1aS",
  "16.2.1",
  "3.18.0aS",
  "3.18.0S",
  "3.18.4S"
);

workarounds = make_list(CISCO_WORKAROUNDS['L2TP_check']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuy82078",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
