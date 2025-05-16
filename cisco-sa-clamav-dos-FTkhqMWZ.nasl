#TRUSTED 8e2848d7d83ab063bd0bfc51699ac98f49cf616a169a87a18d446a04b3d018796d1eae64aaa57e38e1a6d8012df2527100bbe71ddbc237008d3a2458378a249ad20cd2b0a1383adc0ab5439d072de5d36804fe978c39a9378861aae8fb99dcfda913f7033483c08d85797930dbe73b7b9e3e61931f4aca510933cd83b702695819221e3706b0d7ff37a200d9a7ac26701d2905522ed309d6602516241a842d5f239cf6f3ab4f74d3861a282164e64ee369a24c98fc9fb4dc6eb7b67dcd904f8dfff3dea348a50ddc88a78835b01837f85592f3906d666d8fa7d42e7b75304f28e2c1805195c6d0e581cc83e1aae52141e87c7015e311cb675a093894c9147ec0729a68dae0480cc58a194c4fed6d96d510513e72dd732f8cb94ce244b4cfa4cac4742381fea9dc68b92d7695a464d0f746119769b71876e3ed7bcb898e3d76776a6155426a8211c3c3489ea7cc4ef3649f7209d75457cfaf350d0f456d83f83d9377f0eb2f854b575e65bddee7a88216a7c8999e1f807917df2b621eeebc05b9ebce056f07710cf80362941af87913ca421bddfe3c9188b7d5d636ae25a079d569f42c795a7af91189029b714f6587e37d47b0548c3378a5ba877b76fd8abe6a185b1814aa442c58bd5ff536886b7293668a9d8b0027427112cdcd26cad087732598342ffab79926813213c9e173679f429bead290285f6fac213c231b89f947
#TRUST-RSA-SHA256 986f1215e60a307ae8f048fb5e9346b02704269852fa7e68896a9eb55817bd5164cd2cebda225ddfcd18081e8f730959bcf995df78a6279a371a2a2dd3492cd26ac0ce43325a9c267842fdb5d1ec895b8c2d2a682d2d0a15294593271a323e63ebda23aafb519444f3c78f41f1aa64398daa8ce7ddc8e7e9431e6b81a0f79a4c783cd63a32a67b44bfd1eff3a9632dfbf1755488446e81159cd77f98b7100bb0e26e605dafd1cabc9261dfcca525202cb62d5876176944563e28d4ca36184cf776b6306fe944e1e77a243863c83b8035d11e2e4c0c2abd0bbce0ffd1f8ac3563e53aa4adac9980ecbb720275f803b08884f9903102595842fbf926600022341b4ea0ca40046a115c7ef8195b5a6d44996b31a179b85e8ef7ad78a14331c28f870ce1fce601614c9b107526d68918d00432ed02a145918e030a8c892ca0bc079f2eb026ca58976008b4f6038572b2b0aec61fc0f3d26f58d2dd39805177c74d28c839e267210afc7ffcf53dccfaf4f2b1983160cd570aea70f9a91f695982855d31f76819c423419bd3f8612fc1133cadb419cdf3bce5748134ac37853e99a6d4133ac7b0ab29ecd32cdbe9ad560f6290c09285dbc503831c27af6a9ed18385606ad3caefb2b7d3a724b643378cb7b162d6f98489fa803ea4b12590d9f5cfdb50e0c2d75a151e79e33ab5c047c82fce5a104ef9b39e8d48e6acb37c364d6a4a42
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190509);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/20");

  script_cve_id("CVE-2023-20212");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf30972");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf30973");
  script_xref(name:"CISCO-SA", value:"cisco-sa-clamav-dos-FTkhqMWZ");
  script_xref(name:"IAVB", value:"2023-B-0062-S");

  script_name(english:"Cisco Secure Endpoint DoS (cisco-sa-clamav-dos-FTkhqMWZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Cisco Secure Endpoint AutoIt module of ClamAV could allow an unauthenticated, remote 
attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to a 
logic error in the memory management of an affected device. An attacker could exploit this vulnerability by 
submitting a crafted AutoIt file to be scanned by ClamAV on the affected device. A successful exploit could 
allow the attacker to cause the ClamAV scanning process to restart unexpectedly, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-dos-FTkhqMWZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?318a8832");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf30972");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf30973");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwf30972, CSCwf30973");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_secure_endpoint_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Secure Endpoint", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Cisco Secure Endpoint', win_local:TRUE);

var constraints = [
  { 'min_version' : '8.0',  'fixed_version' : '8.1.7.21585' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
