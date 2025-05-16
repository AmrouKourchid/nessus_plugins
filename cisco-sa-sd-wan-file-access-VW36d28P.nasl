#TRUSTED 7ec6a72728c4fc1a7703e098b934c05b6ba122c662de5d264f39bd5a030674dd5a6e19154cb31dd2cc384f1e2b4bbcec173af67b1ca23b18d07c8cd635a53b72f97a3460265fb9cb99bd937ffa9e2ea09cdea44a0660e2dafe91d6a8d031da1e95767fc24bd5fb11993f831ae89dc9ea8f205fed0ce2bbaba72bfa758bd54c26467e709743ee861abd9d1036a5c86861e8255fde689fe923f3be9b839cc01a632c70802999fd044e022ed6837220bef7af39fd91cf416498429175795b271f3b5dbec905814d3d1ed388fb27f650862fcfed9938babdb696a96e34c110cd4e704c0698704ca814d18a36997628ce638eedd7ba7d9d6a05ed4b4e33fd9565f2bf79040b5b29834d3c8db9e0a31f2bbcef9716224ae62981a13d4c9fa0c4270dd4490d663d8501f1f184571cfcb1ec575c1080974cc3823f077a992d12db264604dc50e68bb34c26b209287d9f796ba57d1837cfb1e197fac9d065e95faee521ca7f5cf2efdaeb84b62454d26cccd1933b50932974a6a347c72b4f1a78b1ed7c780435fb7d5b92fb556dce083b0db4b42ec0b3dc4add34c186a7371add5249440aa1e4a2d0da2d974f93505577094385ce11e558473b6a9eb1c6112d311339c80e7ef1dc676f29d0fabce7142223bd3757688ca50a906855701c0a9752c1028bdf6611cffa7a966f4bf6d06ffda0f6658cb6f59a21d1c55b3dee816f91d9c09119
#TRUST-RSA-SHA256 61b6c3ca124f2139c359d246b1672169442e5845c79af6ad94ea62c7000d47c9ff1855ce3ae2b9d609bab2f2dbb66af5a3ff9874d19080e9051b3b6eec8a7a3c25fbbea025e3f0e4a4cb8370917398ae3cf4a341561e1501823ceb6a5947d2314a44a7ed2810577063c9b7cf5177e6dab5187726f8d9cfa24f6d271b9b5096558f50611bd4f37dfa3a73c741a0069c297cdb7933c2f5de53349310b8ec21470114d7b7822929ea77ecea9703949c4e27a6b35ab1442ba8fe6f46ca91be21ce5323ac02da8ba3a0f6cfa3042f370cf53984fced18126f105f08da9bd235f9d41be13a61fa44ebc4a57f9f78e777bcf27e65cb87b5dfa137d12f6c210c839ca1d52a298f5618eb761efd6a517c7a6dad12a283dd959d7c5e0affc38305e9583b6cbf85cb1704fb6a467d5adababc961fd104359bfa2cab708c51392f4d04573290d195e0a99c59d050f7183c306ecbda15f056b869e3271fde9ecc1cad42ab2a73b87a8a3bdcffa1d2d888dea9922359fddd81d7d38fbb44a60d398f1b8329e416765f953949ae3f76e0d5962f2867201862bb79c61e62450f1b0005053af434ee561753f7e6c711bf0b03354c04749700890ecf320a3f3736565d375362f847496883a9588aa033423a0ff437ecc578a308fc46f30c07f8c63c15b2f053d018c1608cb59658e5a3f7876b17b49b4f0e0d8ef31d6b9c3bc62ed8ab6683b40c7db0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159718);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id("CVE-2022-20716");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy11382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-file-access-VW36d28P");
  script_xref(name:"IAVA", value:"2022-A-0158-S");

  script_name(english:"Cisco SD-WAN Solution Improper Access Control (cisco-sa-sd-wan-file-access-VW36d28P)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to gain
    escalated privileges. This vulnerability is due to improper access control on files within the affected
    system. A local attacker could exploit this vulnerability by modifying certain files on the vulnerable
    device. If successful, the attacker could gain escalated privileges and take actions on the system with
    the privileges of the root user. (CVE-2022-20716)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-file-access-VW36d28P
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f70bc151");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy11382");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy11382");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20716");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '18.4', 'fix_ver' : '20.3.6' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.6.1' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvy11382',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
