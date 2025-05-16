#TRUSTED 00556074c474144e293487088b73c436b1e9333890f3d0dd44ed42ee0d164a0e03a626195b740e06cde3979186b2606b1505aed1abdb49b169ebaf7a42c77dd0c60d659c17ea795f71d689f48521f079131b7c0342343985d45dae37924c8655ec8047c31cb7a37e32167d99329e00735b4df2ffb341c19048c1fb276f15369541fafb9ba7d9dea163a0b23a573902fc99e1f443325fbc42d893d97e2e19520923b58def0a38a9b64bcbbce691fb6ca1d398f67f80d330fe657577b70f06a0650c6d198d7d1ee2a8b6bc1a541cc5119d1020b838731afd8fa6f91ba3b5671601e4040bb5ba764a424f26d845f07d87b665ba69b9ea53ce10967d243041d9c287b6c9b4e3dea40a144e2c91647174efd825bae2594b387ee0c06979d34d1d9d62518377e053d06a51557376263bbe4ba60c31bf3fdbe8775abd1c063a7f9c5fa30d4886d6a35aff560ba0b7a416cd6bf35a0c4a03d9e2e15d03746d2375c7d5668f1d9fb24cccfdadeed7437704c2880c6d16b2498a69d0754bf0e87a13faa03891624c95ac2cede3366d9f4c4c57c936589d99a5792b62e1e2dcf96a282207ee182c281b2fd7b7546cb413c74d03bc07ab9a6bed4752b65ca5e1bc4d02a67123dedcfd4ffdae6c0ff27d4823fad47ffc01db13f7a80663cebc442fbd152c6524ed680abe2eef615d12fd5f19c87b7669cdbdc87c772c57d5bd440b92a5e3bef2
#TRUST-RSA-SHA256 17e4d3d27049d73b5db90783718501b82b06019c57b578d3dd1734e41474c33a26d3829878772d863c99431e6174cca4d3df24176cdca33ebbc37ea5daa1983e717764eb503a5f845778b2ee3f67af4d0200904ba8431277d0d75cff7bc7622bd3caaaa5d6d4684de04d917c3f84e9d8bbe535f55c1ed9d45740ec02934cac25aa53f9425191da4827098b7281bef212cf6c138b40c673b3b9afb1aed6be6605f828b1ed06155912e27b98ea35097a65a9526a66cd4c07ba2eadd7a6483600c90f97c364f183b543a7aa78310bf3e465b1b189594b554864ffac2bedb9e21563532cbde30218571e927cf93033d01296adf8d14f15207b13f3d9982bf9ebf4971cfa9e29e5076a6cd886be1825a99a86b6022196605ca0a92c3e63714eb0d10cd68988b826377caed6a5e8343c22b560f86065b4fc6baa8cc584e9e255b7208a84928d2cf7057e85cdab16a7416fd1c4ffe84273c58272b74d6ec61243256b451576307ca379a3b4c5dce7bffe6066d9ec1b92ac6fa677ff2482477f9ee8df4bd1cf7a783a5a20f185969c168aab76ec3298f4e06624747b0261a4f0b970005620a4e71ff89054e2cc55ff0a1d343dc05e92fea83eda4920969a2bb5ddbac6e42705c44be534ab00a8f15b7a60fe4e96ccbbabd46956015934a7b2f491dc5d80f0ed5c9a189504d1ff173328408ccae61e5d92fe2053eb49c3387eb8b7141208
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148447);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/04");

  script_cve_id("CVE-2021-1137", "CVE-2021-1479", "CVE-2021-1480");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs98509");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv87918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw08533");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw31395");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-YuTVWqy");
  script_xref(name:"IAVA", value:"2021-A-0159");

  script_name(english:"Cisco SD-WAN vManage Software Multiple Vulnerabilities (cisco-sa-vmanage-YuTVWqy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage Software installed on the remote host is affected by multiple vulnerabilities as
referenced in the cisco-sa-vmanage-YuTVWqy advisory, as follows:

  - A vulnerability in the remote management component allows an unauthenticated, remote attacker to cause a
    buffer overflow and execute arbitrary code on the underlying operating system with root privileges. This
    is due to improper validation of user-supplied input. An attacker can exploit this by sending a crafted
    connection request. (CVE-2021-1479)

  - A vulnerability in the user management function allows an authenticated, local attacker to gain root
    privileges on the underlying operating system due to insufficient input validation. An attacker can
    exploit this by modifying a user account. (CVE-2021-1137)

  - A vulnerability in the system file transfer functions allows an authenticated, local attacker to gain root
    privileges on the underlying operating system due to improper validation of input to the system file
    transfer functions. An attacker can exploit this by sending crafted requests. (CVE-2021-1480)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-YuTVWqy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be4b5546");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs98509");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv87918");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw08533");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw31395");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs98509, CSCvv87918, CSCvw08533, CSCvw31395");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1479");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 250, 269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  {'min_ver' : '0.0', 'fix_ver' : '19.2.4'},
  {'min_ver' : '19.3', 'fix_ver' : '20.3.3'},
  {'min_ver' : '20.4', 'fix_ver' : '20.4.1'}
];

version_list =  make_list(
  '19.2.31',
  '19.2.099',
  '19.2.097'
);
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvs98509, CSCvv87918, CSCvw08533, CSCvw31395',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
