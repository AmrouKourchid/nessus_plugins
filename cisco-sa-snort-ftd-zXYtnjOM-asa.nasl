#TRUSTED 2a0c0710b7ae021438cf84ffc06b78c81b7e0e8fdde9ac14dbcaa6b0a204e86dc81c909058c4b6a439ca7fb2069ffb090a29af5b07490adc3ecd69c69d65b3e8f9a42c18613499dd7e9cbb1d6893c0e251e65e9ff66fa58c8e04d7656d2b2504b29726745a1a6a1bb03d2df73e79ce47d5ac2a96e5aeb2920c3b1b729740b2fd7d76c5be330f35c1118b17c68bd4851be876cae7936c374e46ca1bb33387a6612a955fd1391c42c0e6abcddb179a8638b9ddaf95cf08115d72900ede1678e382185ebfbd68a5eb6ddffeca7b4442f7d9b23aca3ced0c5e9e04d3afc9715f836e77d3d72f61d96377923498944f26b0e8f678136f4ad0a20a4cdd6b721f6e051834b55aa460ba979a8abb815e2b3e48bcf127d9c032a2ca01101d724d6e1f6836c63004787954b742f782a05a2043089dc922a2869a81e340dbe9768aa35a97282284dbe2db6a1d94d87e4df1f9257d9b1c165aa322b16c74404fdec199802d5fc0478e0adf707c36d1d05d744f8289cf5e74b8f845d0f258ae0582a62471b4a4c2525fd2c30c087a852239fa82982e078dd6ee43eba198e5900b66d2fc09ef2a62734c557cc51f258b344720e0fcda342799c69320d7cab7eb2230e21734deadef2576e6721c527c09e86d4e3dfd7186b458051e4a273a99f027b968df55e1d408491fb006556d5218ea00713ccd542c440ccb1e0fe6cab2e93f29c4cc5735b5
#TRUST-RSA-SHA256 55a5c3339f4428be2b45736f340c8616380e966c23fa2a8ee59cc74a2b9c77f941d28b8accae4c0873d2faf8053a5c3212076eca2530f8574389413d7337a556f071266a1df1f122c5de6f50b1ff221f6a774ce6246e644d2cdee01418d809bc3ec40812a66eecdaf7acbe688f77cc5f6bcac609754801d90aac4493727738013a69a01d1e5aab4869b695cdf388c5f1804d8fe0c9b62f97e0fdf3e9501e85b41fb0f1e92d3e403657d8adbe5d3b853a7632112e14bebe50f2652797a13463f9ef1c781e927c76991816fdb94dfe21b7e5718709fe8326c11ff241c2d2df59d15fd099bf9d003af7ef776be00a7315440952038c5c0b4f8b11276e2afb206302e00cbc2d4244d78706f50efb9925a92579f2faf813e99c034375c4bd299f9d4dd186a73fffb5d791c535d82331dcd82ba3c21a74dba09eb352b87f6583c03370ceb1f9566cc11aa80aae9afeb7ba425bd4774dfccf5a166b7e9fde632e14d2fb88678cd1f93f585bf86a648c764609b411e612b4a97ac9575db99e9e33a6e136aaf4572b91055a950f76724bcc6ab04516a7f9fa6568a1d01e8313811c61eb0e4006df7fbbd492085847bd5171089506415f75fac9f0834971f2cf7ef37e68d6032b4a9e5bbd600dfea13c67d14a636483ab725a07156d4a8d5bc508c377396747b193875db0a70007006e3c7ef58098fb96ec04199b5bd2d6bd48dfc8edcb3b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184169);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2023-20071");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb69096");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd09631");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd83613");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe02137");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe57521");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-ftd-zXYtnjOM");
  script_xref(name:"IAVA", value:"2023-A-0596");

  script_name(english:"Multiple Cisco Products Snort FTP Inspection Bypass (cisco-sa-snort-ftd-zXYtnjOM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-ftd-zXYtnjOM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab2357d1");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74985
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c46133c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb69096");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd09631");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd83613");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe02137");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe57521");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwb69096, CSCwd09631, CSCwd83613, CSCwe02137,
CSCwe57521");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20071");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': 'None', 'fix_ver': '4.1.3'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['utd_enabled'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwb69096, CSCwd09631, CSCwd83613, CSCwe02137, CSCwe57521'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
