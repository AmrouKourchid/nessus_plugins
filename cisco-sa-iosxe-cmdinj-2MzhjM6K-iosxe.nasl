#TRUSTED 2d8e1e2991825dde5a2497f612b0480ec9fb4ad1a52020252ead8dab0f457cdabdb3cc13bb45c053f088f610ab13649aa8f545a69fdb658ef1d161eb9486406736c3d73a5d9fd718f5810b3da6adbe554986a3b2c490959f80be217956658f22790e8e9d62a6d23bb6692e754e6ce9ee55ce2734b7dcf7e82dad4c707d8386d242efd939a1c855cb36db2a7ac9aff16d42c129b8f7fe4c703efbf4f754ba3cea092a1b439e277b40db8df3f3c7db8cc506390ae12a010ff18fb523f5939697822ad054c379229fa34e936d540574a3f98ad6eff01913f6d7c3c916716090c7c84468fc49e26b20d97d103844cd20d34476e007f2e28640c07c70e806650e6a76f58e576a72ece473426a166dbbceda35ede544bb087b9c49f70984730b6d79c731e627d800363bb17bce9ab4bc3e51605e89ff52bbc34fa42f5f9c9185e50382f299108e166cd8e80408a1fbac5788a3ab2bb1a5dfe96224f4aa00eb95ba9fad24192f8aee80e08da892ea8e244e86daee6ec09f0e73a54844a708efb3056c0cb2bde7276135c4939f7a80ee2ce02342afcc308d6ac1c4781b9acd8bd7e3faba50962ccf3448352ada0ab80fdd7585115789f54da1d1d840fa31953bd5aaf84cd7604d60fdf2c7d5045efabc5bfed9f243f10c860e668405398bc69b8ba3fdf6e8f3c9e9c6b697a17fd836f273616c8e76b2b9349f8523e0bd2c38a0dd90bd82
#TRUST-RSA-SHA256 a6e554f9022ff4118fb6b721eca8a9e1473064b52dca4430a01b4b6620d835f856b147cb030634a1c7adc9e4f733adecf2d92d9232190860bd9036abdef1a5208115341fd45257780d1c640cb8591a09b3069f8a1e773553f2a2e347bdbc634033d153751c1d54801c4d1bd3fa97a337ccf97eb8a004dfb118bd3321f7f81a5c0b6d7649e268e8c5bdc3fe6c3c5e61a369efb9b7f84e60f49700723dc90b2cf67f9da95e968595d4c664ee04f3b8b67202d9af363e7ae4485402b5f40171ed90f03a64ad2b0fa07e746e8e44bc14c493787b5983a1af9acffa7a824a63787781c0a39fb793fbe38fd1acaff03e17c5d7ad4dc44b9dda97d49deba4862b11b0053aab2a9fa916c38aa92600e8ebfdbe6a3d75ad2066308740f231552c6c7d25b15031552e628b11c0f3354624025033e78e305d77ac76b87d0c47936ed7921348db3e06400b69de6f1ba120bee186d968d01a77cb732f7041112826374e04afbeeb268131540b7bb609f5efe7e79ab5152f8cb16f6717e393306b80568c54333a9f3003684209508c518470a5cbd766af1c158ad89543c2786bf59b59620eb49e934c51976af21d6ecbe6eb061cc9454dac34017c938d1893aa50a27d3130be9f560346e6cf8dc007c22f84d4a3d389e61ae0c9fdb06df3343cff795f4126a29aa9636bf186e2c6bb5bbf96859c08d5bfc1bee16391a830df7f66e148f4490ff7
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141193);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3403");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs07077");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-cmdinj-2MzhjM6K");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Command Injection Vulnerability (cisco-sa-iosxe-cmdinj-2MzhjM6K)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a command injection vulnerability. The
vulnerability is due to insufficient protection of values passed to a script that executes during device startup. An
attacker could exploit this vulnerability by writing values to a specific file. A successful exploit could allow the
attacker to execute commands with root privileges each time the affected device is restarted.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-cmdinj-2MzhjM6K
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eae30938");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs07077");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs07077");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3403");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/06");

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

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1t'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs07077',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
