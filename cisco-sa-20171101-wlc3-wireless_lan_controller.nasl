#TRUSTED 52e22c390994900143e4275433b6a70356dd6c92084f15b143a9e7c061f8413929ce7c24ccf1e182966873deb7d3359fe600551a8cfcfc592c9cff251fea7b46a4c007367d73bf67c5e46c2a7240dc3a89df3f7884bb34454950d1cec01c4195ba57f340eb57b0e6cfa8e9504291cb4eb15fb145c9aef31cf0212b7d813fc1f7239a9e21a5f64318538a1f89ec1963e92bd7c3f774a7d61a723b8716bdb0370cb1d9e466df872d9710725bc809f0f167180425fc33b2fc83aa12df1532fe6515dfe3f67c4f4d8e3673da9ce5c41d4c15e6b07adefcbb05840875a103fdfa473b29b688bdabf427a05191b4bf1b48b2131106bde0b1535438096f74c52e33a7a597c3f6ae53d1a1a8e9d44a5296fefdba925aff2fe2d8ccc1bb68e9da8acf87b0a183353c35b61867f959d0cdb780d9530e62f3e3d5c5148dfaa303bf6bca92a683249e7af5dd89d8c0c3e855eb21622ba667554a0cb494a1dd9c7d572bb11d4ecdbaa6bfcbcd2981621412502ceffc80fa342095037671ecf54e693ff7482d4bf449f0a9a58e7175e94c821dee2d0583e093758219ead1c02b585d14ecb40af32d47bf71bfb533c0b9864d6fab6aafdc7f343b9bacd6c7a50708a2498e98e3de0942d450ac4b01053def155600f1cb0f138895d82de886d3a7ff170d8c53ba378baeb43ff155ba0246bb3541a0be5d1ec46eb409af05d00cfb7485d27c0e7c81
#TRUST-RSA-SHA256 15c50db6c02cbb4d352b3ca55eeedc6c025cb20b092168f0412dd4881757f1e3fd9156b93dce9f7f04938970bdd5fe1e5ef63ddbe92438ba35406b96be42c016ec3efb68f854284a7225b2836b3b4d1f73e755b7cfd7ffc3defe82286170d69a6dcf5a75d7d5a07badfa06958d9fad4d28d0913a37ba3c319530d2c0e834be1ca25f3f7d896e1970fd86b30aec924743eb5f9cf0fa6020503f805505302c3766378fbaecfc50284ba110df8a9bdc75f15d8a7daff758354665595c28a5c4345eb5ef173ff8412c0d2e8e961636fb3bc85233b60621b11a1a7e883bb42ed2dc48fa69757d20a6fd1b29e7217cac35173e274b099d3fb17ab0c1759b17ac7d17dee23ba06b92fac4a3c7c8016c4075db0eb8a35d0aa2bc8333a384dfb6f9a05e8782fff67d4667fc5df7ba03b2fc3593a1272624be27fc43ebc485625d2700308a42dfa7a67ad279ff562482935106ddc78fea9bd28d792a53d68ac66a3e75eeead4eb451a95e887f3bc8ba28150285ae0376bfafdca66804035825f67bc5ff30bacfd32a06d518184a6b4607cbf9c0eed9f4281c6af3b41dbdbae020face45222e7456d14ec12fcbd536b3912c2f39c5852a0c952b598030eb88b360465c98673c339a88f55e55d9989bc7de2ca023a9b081de446d89b9a74e791dc83fa71e1550258c49ca17bbd6bbff7005ec25ac4bd1c90979ba896ffc24c1fd6edb6373749
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104461);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2017-12280");
  script_bugtraq_id(101646);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb95842");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-wlc3");

  script_name(english:"Cisco Wireless LAN Controller CAPWAP Discovery Request Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco Wireless LAN Controller (WLC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN 
Controller (WLC) is affected by one or more vulnerabilities. 
Please see the included Cisco BIDs and the Cisco Security 
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-wlc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88a89292");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb95842");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvb95842.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Model", "Host/Cisco/WLC/Port");

  exit(0);
}

include("cisco_workarounds.inc");
include("ccf.inc");

var model = get_kb_item_or_exit('Host/Cisco/WLC/Model');

var product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

# Only model 5500 is affected
if (model !~ "^55[0-9][0-9]([^0-9]|$)") audit(AUDIT_HOST_NOT, "an affected model");

var vuln_ranges = [
  { 'min_ver' : '7.0.0.0', 'fix_ver' : '8.0.150.0' },
  { 'min_ver' : '8.1.0.0', 'fix_ver' : '8.2.150.0' },
  { 'min_ver' : '8.3.0.0', 'fix_ver' : '8.3.111.0' }
];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvb95842"
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
