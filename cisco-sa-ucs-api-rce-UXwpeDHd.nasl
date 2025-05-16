#TRUSTED 1449211ffdf03ec8c27260bddefa8a59d06d99b1e7314feab94b22ef374b33050c536a3c8c5d059caaa001a442b598ae568efc754c296eaf4e76b6eeac46a4bf3e1da3847fedc45f4737c790995b5653ff046602db5c7d6383fb9510d5ffaf69089baf6f76ec4f4c18189a0871eae1c00f82765585ab21e0928e3873587d791108e0f9742372084d31775e5ec19973441327be7c3b43b1b99cf8956b9344b3b6f163d1c8b3192c00db9ffcbea7dd6590cff02d08565c3ac658e7188cb3bb96fc021381d0d834f70ddd859a71d2be47b28e385786932bd179c076ef3eb4e8f625a8ab9c47467840f786f01135cdfb076175358a2e10e92cd80739195ba80ce5865cc1f28e387937d6e1be61dfb6f62e92b968cb1531f7ca42e5a94ff18dde301465280d16a21b001203fbc57a5956eb8a884e75dc1bec15bda7a8eb5795980cfe937ad5982f73e633110369047041994d1ded814ddd789bea648fff112dca61ee2dd3542913aede138f2a216fbd9f661e17720485523b3137d7578cad727cb2ddc7df9251c97815f264ce6e6404062f1a5e2b820d870fa8e48c2e5c22761184121f3804dccc5567c7be7e85970cac3912ef42bc3b924f74c08d14f83f8d594cd3119e6455035fbe2d86e3121b0d0f5f0d426aac122278f0b1bf14fba884854229db7b2ced4cea6f8a0c28954300daaf14d7ea8e1ed410b77085c7769d7078e019
#TRUST-RSA-SHA256 66d1d74dbb273429fbf95a2c851554a55922df08ce4a5162af11970ebc21c8dd39bd7b8a26a553330dea3b45f570c0979fec78e945eda3f675538bc563c11f509e77d96baf77e2e6b4a8e2fbd00c55c27f1e6593845d495e4319dea9108ae6c82c04d4f53f65d964dca446e51c28ee0829e680258c147663388a9ed03108e2cc394e01c9768735c9fb95782ba5b0ab8df67e35a45c679d6c06c55e7b0270ec87097a3043ea1566e734ee2b70e8315762a57c5cc91b43d9d4e3776b8b24c5ad700f75be4634f340cd82d635b412f9d202e262f0f7ce484e3e7c99e2bed3352b55d7fefd3c8c991d26cc2f4362b97c97e7be6afa807ccba7ceda58412ee7300c95becf88889ee54210ba75e7c18199d614e9c0347d160e3441c197322104fd98d4341bc9a7c799cb6c03c9e387583dd8c0a873c6f3452b1c9ac85b03b00b8c6556d95a17d26f5b0017bd12c315ca440ea8170f78392cc11d1f79cc8abb60ad596ac1b325f2da2691d46a1adaaaebb318f58e37cec0233bd547dc519a74deed163d4cd0b683974aa4fbd3acde7ad3c5e25c0650f75794d8ee9fad52aa1d4e97c544cc5a07ee3df1f664b82044e6b8bcdf65d712fb54e30da8e591344e64cb6ce4d72f4a7bae55b9a260fb801bda40039e23a632f04a4bea31d865e61324c83c56d757919eddecb7c41398052f07f905e988ea24234e0ff18f54675e05b4628795aa
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143150);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2020-3470");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu21215");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu21222");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu22429");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu80203");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucs-api-rce-UXwpeDHd");
  script_xref(name:"IAVA", value:"2020-A-0543-S");

  script_name(english:"Cisco Integrated Management Controller RCE (cisco-sa-ucs-api-rce-UXwpeDHd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Computing System E-Series Software (UCSE) is affected by multiple
remote code execution (RCE) vulnerabilities in the API subsystem due to improper boundary checks for certain
user-supplied input. An unauthenticated, remote attacker can exploit these, by sending a crafted HTTP request to the API
subsystem of an affected system, to execute arbitrary code with root privileges on the underlying operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucs-api-rce-UXwpeDHd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e999cbf5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu21215");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu21222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu22429");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu80203");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu21215, CSCvu21222, CSCvu22429, and CSCvu80203.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Unified Computing System (Management Software)");

# Cannot distinguish between [CES]-Series
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '3.0(1c)', 'fix_ver' : '3.0(4r)'  },
  # All 3.1 vulnerable
  { 'min_ver' : '3.1',     'fix_ver' : '3.2.11.3' },
  # 4.0(2n) is fixed for C-Series M4, but 4.0(4m) is fixed for others
  { 'min_ver' : '4.0(1a)', 'fix_ver' : '4.0(4m)'  },
  { 'min_ver' : '4.1(1c)', 'fix_ver' : '4.1(1g)'  }
];  

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu21215, CSCvu21222, CSCvu22429, CSCvu80203',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
