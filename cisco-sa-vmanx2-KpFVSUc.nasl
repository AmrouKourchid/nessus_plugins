#TRUSTED 70fb7704d5dd77148d023df501ca5ee57cfac54407e16af99d56e52a1f4ace6708c3a67b13492f9702c4dd37c141a95e4bd8fdf6c521141eb19d83526aae4b12370bf1cc40a0be1560984fe416ac52e213bdd4c4c0407179b9c148f7b75ba7afd685ef278b6ee5f31448cbf156e65632d8c0cb3680488ba2c7af2a607b0810d5a6de42b4ffba7abb159c2aca0371976d77d3641d8e6490b06d201311a1c597dcfcdbc274c51a4acf730b51b194d87a942ca7ffce0e2fabc8b1249f105c1cf7b8344acaf947e0353351675286ff12926265f742c6a0180c9724751e9ca8b92176cf71e031197cbf7b9964cf8f37d81305151fe93e86d15a1ff3099e73f59a6a754e7dfad658cc2e6101189db81ec4ac8532d3bab4ace288be54957a8d375976881613e87befa27da2619892b6b4675e52d241bf013b96aa94b5f52aa5ccf5ca5421a65586225e07cc6cd3334bacf6aed35c2961a356d28cd4d2b1400b153cf6c096c628d3ebc33503e39ec8453daa3edd31d91e4ea3e6d9f73ed6c8b11d0d016b52ec885c9c2e03d6ba05ec13efc8bcb4e47d8a8f3a2d91044372195163d2f3eff2b8140efb6f68764c1e4bc77f3aa0be08363d3fef2608b288d0616e474cbaa773e8d2cf789b850673b92282d1378c938474438f2534e027a72f7daffc2260120db170995cedac6cf284ab77cab3465d4d9e89a56fc33c536abad4b26e859b45
#TRUST-RSA-SHA256 8c3f24d572ad60d78a754edc08eaf4d7c69325b0cd2bdd562743802a1ff8a5e0f6262d43c43ab1f0b6f993399587a79a54a6298925582b5cbd1d7f15272157099a70f2034eaa5a8aea1a7448f4ad9da623cd8fc3cf3962b8555062aa29f7906b91296e36020ab80666fa11aebbb7aea00fa3cca7a58c29d4a42162d6c95e602f72c5233325d43d9015bea21a2b7b3d3d5c2463c508a7f22332dd169f97d973a2fe2cfe5c249ae9bb0231e98489ca23b18ecdca977b08fd23fddb9f0b25e6513654fc2670b54100260150c7b896fbc3f1646e3c79b2ad8782bd3729294c17d5b3a5b9a1d8c2ae565ab2dc37b383846933a63aec84a240b70f3afc080ab9d55fce8bc1c0e35827ea052b5483e7fde1c887d76cb63c31db7c56fd789ce203b04f6ffec0bd393c6d4673ad0a7e6e20bc6c57bfef052459b10b4317cad4788ca7cd6301f1dcc3b9be3692cea7af42d77e4923849f154529b38c62a94c5ecbe7be62bd5440eb857a5148de4609cb50a509e7f90b3e536d28f1562de4b9a6a7176dcbaeafe1dd95e71310482a984d826b7fcc984d521d5da85c11298e4180779aadeeb824fa239f8ac72ee4bc151df2ca6013e6d21a81548f0d983fff6e5692971be58e40955b4a4e5b9d0d904b93ecbbc10e5ef077d2e0b03748c470a1a7268de8d6f160c52a26802e74bcd0aab408545857523480a9e7849eb326beb571fbd523e880
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145556);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/25");

  script_cve_id("CVE-2020-26064");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv02305");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanx2-KpFVSUc");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software XXE (cisco-sa-vmanx2-KpFVSUc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-vmanx2-KpFVSUc)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an XML external entity (XXE) vulnerability
due to an issue parsing certain XML files. An authenticated, remote attacker can exploit this, by persuading a user to
import a crafted XML file with malicious entries, to gain read and write access to information stored on an affected
system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanx2-KpFVSUc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4f1f4f2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv02305");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv02305");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'20.1.2' }
];

#20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv02305',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
