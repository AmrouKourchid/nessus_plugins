#TRUSTED 87ef7325058d6bf5e8376d555f401b23a8599458aec795604fc0652771bcb784d3c003c2402058d2fd158202265bf0d75e3e13a3e8a3910f0ab34074ebbae263889fe776c8a54412d2a9ac6072368a6f9b695ba4aba2f9d66174c69303c5fdc8f0c5cd456977b7561da27db9f6168e516e6a84eb3283881b26baa613dee48868a379c45ab7bd36dd998c5de733301d4c9507fae122692cb8b5c2d99dbf526cdea898ac73aff48c39e7016fa63c47494a3b3c8dbefca76c784567b68e675ec6cf3a14f523d16293bc655e02dba885d2a0be1e9a9dd43f36fd53b8c743ccf7a1bea04e0138e674bc6bed052329bd7d71f8547ed13a0d56b6c158ed5084813125e7b45f23f23fde4458e5e417dc0f92067563742c9f7b5a90e1c30a362639c28ceb8cca78a74c468f4e290f2e6d9d96bd06ed2730c3921283e4859e44acc4340a58f8d255e7f44ce71d5315ae2392cb2dd97677358ad4045451ec34e106c0280e6d82aba971fefb9dee34eb93bc4fb32c974b14b159f4dac44d37744c4959349b173a188cdc1eeb3ead4df92498b361c2437d50e3952b9866df5d5944a31f30af759ba135a01e15a17ed465868fb552417efc16fc9908e0f12b4526d3f32bf9f22f01dd4d93f042e941fa924d671105e8e46f494fc9bb1ca2fba2cbaf5a5c7fe389b8e79af762e64d4d37e9702f180766a15858e8eac0bc882461861dc10311e7c9
#TRUST-RSA-SHA256 68e1eb158fd2f54bfc1944d91c4162be68351c29e81ccb6c2455edc00d722d5c768e1f563c82ba8a9b5618588f3e6490a01dafae4431ffbf0b602f9db771a920f11b017ed35266a4439bb8b07f6d3da337ddcf50841de31c4acf19e6db02ec1fc2b447e3d90b0639486f8ad41e2a506728ebe274a0fe5346820fc662c59cb756f0a8720bc3654cee1116fa8ee731c576243104bc3a1ea3027175b0965e236bb38116ec75429dba57f576a59ee9540bb97e857f11701ee52723208d3077c6c1866f58f081a58dc163c0cc504c5f4a22243b988bd49d1d36daa90c7cc300563b8e2fab539a4d49f9962d973abd5a469bb2fec76eeb66abfee08999ae4efaddf9785487005a65d8dbe89a3f26bc847461d63d27ef4b5429ac48b7ad20ad28ba5e4f4abc37c9efce1c75d7214c6841e42204691381d85ecd5a3e839e086cc3c2da6143ebd017b6c9cc371f9c3c7fc312a4ed4664407bdc8fef220ed7b87636284dfa9f05611de0ec8bbcd4dcaedecb43dd8782f6f91887a36a52d126df56c51223507dcebdc7844990ae8368ae7a6820336a98a3479673131c29e2432ac5f8c4a8e3eda9bc95af1f1e6c1237b41f382616ce6a272ca8ea5b01b4f244381fea144cd9b90c195dcdb4daff148d5499641f4fb26768dd8dea4438dfbcace285d860ed906573821a1b827c9648172da5daad5e01898410aabbda699ee0cca0762e9419f1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137408);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3201");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq28110");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tcl-dos-MAZQUnMF");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Tcl DoS (cisco-sa-tcl-dos-MAZQUnMF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a vulnerability in the Tool Command Line (Tcl) interpreter
due to insufficient input validation of data passed to the Tcl interpreter. An authenticated, unprivileged, and local
attacker can exploit this, by executing crafted Tcl arguments on an affected device, in order to cause a denial of
service (DoS) condition on an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tcl-dos-MAZQUnMF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ba71b51");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq28110");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq28110");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.4aS',
  '3.7.4S',
  '3.7.3S',
  '3.7.2tS',
  '3.7.2S',
  '3.7.1aS',
  '3.7.1S',
  '3.7.0bS',
  '3.7.0S',
  '3.5.8SQ',
  '3.5.7SQ',
  '3.5.6SQ',
  '3.5.5SQ',
  '3.5.4SQ',
  '3.5.3SQ',
  '3.5.2SQ',
  '3.5.1SQ',
  '3.5.0SQ',
  '3.4.1SQ',
  '3.4.0SQ',
  '3.3.1SQ',
  '3.3.0SQ',
  '3.2.9SG',
  '3.2.8SG',
  '3.2.7SG',
  '3.2.6SG',
  '3.2.5SG',
  '3.2.4SG',
  '3.2.3SG',
  '3.2.2SG',
  '3.2.1SG',
  '3.2.11SG',
  '3.2.10SG',
  '3.2.0SG',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.12.2a',
  '16.12.2',
  '16.12.1y',
  '16.12.1w',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq28110',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
