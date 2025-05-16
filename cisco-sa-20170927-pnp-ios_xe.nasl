#TRUSTED a9a9b382afa46a815e95ca577d36fac54d08e6380af821fa2069396484b6ef2c528b740dc1d42a2cd1b960ef86a6b441aeabedf8546109877f79faeaa2b4329227a1a2ce9bf0a18445d577ac1eec0d967cb729e045c95a7dfc85e845bb783e08f56f385ee172dd0f5929872ab5a8cac2b3382d681225f26f5c49db09effdef8dfe92aabdeb08061dbcc50897df129aeee97df5fdc0ab195d0671723ea3263b1d04d9e8e1c2ecd765363303b3210132a10a17b7d9da25156ebaa8a4342442ecd970c97314aeffbb1dbf3cc65f6be0d3c846136e824e4e42394fcaed23505087f7a14a7be760a759cbe861441bb9291e711909b88b30ad763898f2ea7305cc2a999599a2d8e1dc943cf1e14a42ed421cbee8ef2fdf9c4cbbdf2027d45d4a7991ff4895d30706dfbc94f11c102a028308a574e55f7120cc4b48ce69f2332ca41601e55af34a90a2903b33b38f37df545d2cffc218db70cf02b5c06945ba7b933f02218ea80757c6f9f99f6246da9ba5488508e73f269f889aed82382725791e5fd29a822da802529eb4f7c0a53c9fc89b1bc71e061e4e9c860877d9b333e2f2dcb46ea912a793a91957647cc9a11494798d11f5972e7a157e7d3d5b0a32180645b32d3de9025765a2861a3a5e46abda0eb56f19d940a6d08fc288275bd431fe54a6c57551515a192a8d542f9d8d82dbfc722ed50cc51fa9408e1a6dfc68e0395d48
#TRUST-RSA-SHA256 6176f711f7371b0bbb7f568384f1390f349e5cb01eef6146b32081b0d26d32837b4c854f94d3a060fd1742f402521d0ce71df13d92ca617f8ea5e0fed5205d6f1f3929590b97ca04175225b3eb80a2db3c9c4fe69b06bb5686243d9049509546d50a36326164a8d650026f00a9dc6058c1c7aaacf1f51cacf868cb1524eb63715395c5c0b740ee566c7f2994319aac3194ca7e32dbbe092403ef75475a55076ca208327e381fd1b997ac9cd4bb03b632f2fb6e20e41aaa778be972aece7feb7a99c059cb4cb7c65426af749b50b333c1a663a30e72517eb5312f42fc704fae85405492fed58be1288cceab51079fbdd20c46f89c7f1acc225e23f19ab52dfa5e88920f3e157a81aa6beb923b16e0bbed088784295f99ae75f7a2e8b5689f0fb871ea511a45692ba32580a9147304501e674e04e495a1f11fe9a5627dff716cc0310a19a46c50e19fc1f1fea44f8c354cf9d4fb35818640fae4aa30e6edc50ad1fd803483ef21dcc85d32739274a8bd34b543edc80854f98ab405381a6759c3aa208ab623a616750d87d69e982757585a65ff5da7a041507d3c7eac2f924ade6cd9d69d4aeed0440409b9093e720484829a62b528908625d02bc42b14e2719d4b002f1597f79828de381ba559554a6275f6482dca023109ba00f1d7819bb87094ca16268e01d3e9888720ce6da2717a3a9dde9e84beffddefe5955d73bdd391db
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103676);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-12228");
  script_bugtraq_id(101065);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc33171");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-pnp");

  script_name(english:"Cisco IOS XE Software Plug-and-Play PKI API Certificate Validation Vulnerability");
  script_summary(english:"Checks the Cisco IOS XE Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-pnp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d9fc170");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc33171");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc33171.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12228");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.1.3a",
  "16.1.4",
  "16.2.1",
  "16.2.2",
  "16.2.2a",
  "16.2.3",
  "16.3.1",
  "16.3.1a",
  "16.3.2",
  "16.4.1",
  "3.10.0S",
  "3.10.1S",
  "3.10.1xbS",
  "3.10.2S",
  "3.10.2tS",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.7S",
  "3.10.8S",
  "3.10.8aS",
  "3.10.9S",
  "3.11.0S",
  "3.11.1S",
  "3.11.2S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.0aS",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.4S",
  "3.13.0S",
  "3.13.0aS",
  "3.13.1S",
  "3.13.2S",
  "3.13.2aS",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.5aS",
  "3.13.6S",
  "3.13.6aS",
  "3.13.7S",
  "3.13.7aS",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.1cS",
  "3.15.2S",
  "3.15.3S",
  "3.15.4S",
  "3.16.0S",
  "3.16.0cS",
  "3.16.1S",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.2bS",
  "3.16.3S",
  "3.16.3aS",
  "3.16.4S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4dS",
  "3.16.5S",
  "3.17.0S",
  "3.17.1S",
  "3.17.1aS",
  "3.17.3S",
  "3.18.0S",
  "3.18.0SP",
  "3.18.0aS",
  "3.18.1S",
  "3.18.1SP",
  "3.18.1aSP",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.2S",
  "3.18.2SP",
  "3.18.3vS",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.6.0E",
  "3.6.0S",
  "3.6.1E",
  "3.6.1S",
  "3.6.2E",
  "3.6.2S",
  "3.6.2aE",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.6E",
  "3.7.0E",
  "3.7.0S",
  "3.7.0bS",
  "3.7.1E",
  "3.7.1S",
  "3.7.1aS",
  "3.7.2E",
  "3.7.2S",
  "3.7.2tS",
  "3.7.3E",
  "3.7.3S",
  "3.7.4E",
  "3.7.4S",
  "3.7.4aS",
  "3.7.5E",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.8.0E",
  "3.8.0EX",
  "3.8.0S",
  "3.8.1E",
  "3.8.1S",
  "3.8.2E",
  "3.8.2S",
  "3.8.3E",
  "3.8.4E",
  "3.9.0E",
  "3.9.0S",
  "3.9.0aS",
  "3.9.1E",
  "3.9.1S",
  "3.9.1aS",
  "3.9.2S"
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['show_pnp_profile'];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvc33171',
  'cmds'     , make_list('show pnp profile')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
