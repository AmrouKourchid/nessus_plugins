#TRUSTED a3773b125569644c52edfdccca03db4babbf38277cf19cce3a02d828f027459c84f69a2e80003e07190d98ffe270c7df52661395495168403f51c7760822e74398abbec2a54a3dc9f892c27f4462c032b6072ccf0659f23cd1b5ebfefec39bc4061eb8ab752ebb88f25c10b3c6ede1fa6926da50cd0dd19557067c7bcf5ca52b200ab0901d4bf583226bb05fee197fa36b544cccea8d5fae60ba76cd4fc5c838512d41b1ba861e5ea97507862b71be7cf6d8a4aed4c02f425e7631518cc0ccf3e2a08dffe6d91959ecc55513acd3e22d7a00e6ea4b4f86f5ddae90d3803c4b04338d462ae3cacedf4af6e7a7037a5a1389964fa1efa04225c0c440a28d4fc2bb78fe97a0d843f899fa00e9fa61f5d87a1c8ab823a232ff5335eece3e1b98c0c88b585af5dd3be5f54e4e6bb4d3f647c333908bb81f5c2b01893e9d84fe0bd9ae15f42e264752bbc376278e3ff31cc7c96dc5b7fb8d26c729dfa077528810807cb092c06e27a4d95cd12d61a4f88a57b0f89f2002f0385758f2901783b23f85ebaefa1fef73ccb92610991440a7a7f14138bd95eb9916c9cd3f5b0eda3a43a75a6fa5ad0242bdd695e440ea33ae5f6b6f087dae21ba44b92d90aac25071bb56ce62208e99fe9f5cd9dbefa085f8cba68308ad4c98c09b44732ff73b088d313bcb747aa75570c1f58b82fcee926d738e1073f1709ee82ffa7ca2470062b72c5b4b
#TRUST-RSA-SHA256 3d365cb64cfd2544a1a24cb22c57ee04b9cb15b1ce4f3af13cb7943e667a026fe55999ea34efba4c670641585e522c81af2ebcdfb9e9c7749403cfd33816ec41f02f438b67332ca2105b3d28fc46df36e17db7d4ba79e58f39a0d44d171ad53f3d4759b70f02bbe1a55bde8e0e060b848cb32fa1c00e51496e9d4874c651ab8fc0f904b719af6f1fb8a11d7f93e92304cfeb41e6cab17dbc3d36f4b3e5650d54b577bebb4abd387d34a632ea2a58f7ad3ef9c355c84f771b5c641bf7bd613e776da0bdd0eabc73170969750ae1ba8cedc3c3529a228a667b2ed20a8c01a9da92d6f459c64ce0c12ca14efc4f8ae3707683c42e0e9bde73a59d9741afa918c5ce2ff463383af36ee9fafa4a22f3ef020e0901b724af80f97b01a8f768475c0109a7ff09e6f6d0ae3d31723235c6c523db68ddc9c9daffd3a39b6c73c3e6235de8bdcf5cc9043f1317adf8ad7a077dbcd34db9d79c532ab61a3cb5cb15599af866e6e10fe3274713631c502fd829f6dfa87b664206419af58b8f6cd6838561eb5830ba656a81a7dc42b6c1cac770ab7a6e3e3e630ad3bbf01208b84f816963531879d08d9dd700940b45a51a1725612e2ef4ea387d836f3fcebe5ebcb17e708e4c94c00f218f43317488ea4760508733d3804f1581e143083da73f0fbbab60bd4585f0838516322bc0cc1acb50226d8819f448285e717d00d17c0be685f61f3f18
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166905);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2022-20772");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz24026");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa84908");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ESA-HTTP-Inject-nvsycUmR");
  script_xref(name:"IAVA", value:"2022-A-0463-S");

  script_name(english:"Cisco Email Security Appliance HTTP Response Header Injection (cisco-sa-ESA-HTTP-Inject-nvsycUmR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by a vulnerability due to a failure
to sanitize input values. An unauthenticated, remote attacker can exploit this, by injecting malicious HTTP headers, in
order to conduct an HTTP response splitting attack.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ESA-HTTP-Inject-nvsycUmR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc1d0d7c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz24026");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa84908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz24026, CSCwa84908");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20772");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(113);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  { 'min_ver' : '13.5.1', 'fix_ver' : '14.0.3.015' }, # no versions between 13.5.1 and 14
  { 'min_ver' : '14.1', 'fix_ver' : '14.2.1.015' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz24026, CSCwa84908',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

