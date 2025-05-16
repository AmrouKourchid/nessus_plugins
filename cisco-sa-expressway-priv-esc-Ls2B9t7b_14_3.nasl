#TRUSTED 999e3dc13af1f19d43c0b9b9f92bbc128e79ec4c14d269ddcfb94161f23ccc12f6c8ae5a305a9885022051a27c1dc7e1e534c46db947e5fb06523fa1563e6bc0cef38d8d9af1e983601195426bd35be4a7cff8a64c690f51b8def3f4d578cf2014bb60fbe5848d25f5f1925bc931bac2fc1a83d1dca59c2bb9cca9e5b1614df1438960823549042f39cec89f1c4662784eceeffa00ae1ba21660fc9a67d6c31d3e3b23edf6800929693322d011d9cd80e7fedeb468dafa0cfb0ebb5cd15d375852a823cc89a9bf50ba03e0f00dc9e25470b88696fa854992c68ec8dcc342222507f9c01d57ffcfb151dad19e4b4b4369acaf765c0e7989ebfdd79aa7951219ce79161db92746b5f7ca12dbe48b19cb7eeb39b2a93bf1023e19c80594ad899a0d4106c73a7d729d9f53d2d30164ecb5d05aeb340c211a07cad644ce57b6d66e74921cd3705b248bbcd16d0926e899066c46df5538545a7d93e44e63b1ea05467f04f5e86a7c9b92d01d7868b1c80e608ff94b01122372e5e5e6858d1e7a6d92a31c6d5e63889628ee3265d2864bb27bddacf7d8b32722a5c42731fb788c36c92b812774a65d1419129ad6df4a1c0e9d14a85015d8fd957113f0e4abb6699cb547aeb4d14966a09f8ef7017fa33c1a799aa2099136cd76bd419c344205518d615bc8e3d7b1df526b2390ddb1ab5a7edd9d83428068a4269b0ae0007cd93c5bb31d
#TRUST-RSA-SHA256 3dbc144b0effb3668b2edef6cab26dee2214ea1702b862cdcb978c67b2a55bb3cbcdac289dad32f629eac42c90bb81de9f501fb1f969d8486697eb002f4beafe3d7743f79297d1498f5f2a49530ed74b7ca561f0a727cc71f87b0573136eb66aad143e44d5745d1bd7a9b89ff7ccf4d0385c6fc683c9687a52578e2865c3d40db89f8366f9a8ec99ad3afa3d0a9f066745cc7ab62387da938a089dbd9fe9a5e4e3478c2a00a9ee55a26e65171fc485e7096c891e0e8fec576b974a9f3494ea5f382dd0f0ae19ee0e709fa2b0c2eeb41a0b6e57538ef429d730d19967a539a56db2a94233ebf766a0ac22e89863adaecaff293318aea4d4f7fe56a52e0b4687885bb6e94cdf68c7e53cf86c620ac0ccb102bab3caef06c584da1f450503a2f0434af953ddea73ee460d1992f6cf16db3702c9d1157c2021aebb49b4d2cf2bb43c31405a4614ef780563a56ea4ad988e26b8d4c224bd8208af364d0822a993c11b88f58ba62c1a48cd50c3abbf01de856322e021fc295b84a29dadcae9c7e0f5d1d99aec296d1058ef19e197e792d1d64457ab2cb0dbb93529bc070c432916f1759c913df525a366569ded645d8fa273e978cd338a0d912ee06a45b0938933a2051ba5ce0432246b8e8849d592494a9ccfc7bb60ab8389e3d89735c664f8af9b3d32f6a8430ac29605be2c2a5f1d6940e15a178fbc92c4c6e5fe0b8eb0b78517f1
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177368);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/24");

  script_cve_id("CVE-2023-20192");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf28030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-priv-esc-Ls2B9t7b");
  script_xref(name:"IAVA", value:"2023-A-0282-S");

  script_name(english:"Cisco Expressway Series / Cisco TelePresence VCS 14.x < 14.3.0 Privilege Escalation (cisco-sa-expressway-priv-esc-Ls2B9t7b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Expressway Series or Cisco TelePresence Video Communication Server (VCS) running on the remote host is
14.x prior to 14.3.0. It is, therefore, affected by a privilege escalation vulnerability as described in the
cisco-sa-expressway-priv-esc-Ls2B9t7b advisory. Due to an incorrect implementation of user role permissions, a local
attacker with administrator read-only permissions can execute commands beyond the sphere of their intended access level,
including modifying system configuration parameters.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-priv-esc-Ls2B9t7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b350287");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf28030");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf28030");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20192");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [{ 'min_ver':'14.0', 'fix_ver' : '14.3.0' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz54058',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
