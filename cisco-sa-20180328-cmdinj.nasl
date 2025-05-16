#TRUSTED ae8dd4d4ae75e3905af69bb44bddad4ecb1429a130758fc7d26a4d436f7e6b15c9954ac233ed2c5747092d66f1bcedf6c4b19e399e4302f1604f9b010694e53064fa7fb6e22b76f96c38c7ab24b795b44a2912fa476b16f68bc4d99c280e1069a9cebd3c3f92dd92f24a4e3cbf9cffefb992615a7be3ce013b1b9c676806d26590e4866b64bb188e6d48b27adfb9bdfc74a680a4d26b8d3390cd1fbd868c6ca077b253a5d44ed973140f81847c94bec71777bcd90f84c3eae0919f5d287ec599620f7bb244c6b152dac119879c3527a6cf1141dcb22b1b8d26650d888e82cbb945affae7f44cc65d017bb62767e7bcaec390dc9a51a0bb34c7aea3d9fc5494b581b8e938b5b399487acf618b5123915a5f8d1f1a9e2edf23df282d725f5d0372c3427e5bc91ed09fec7ad59bc33e3b71bc9b0c8a7bd96bf016224f3985c87f9ff8b815d91f4f2eb0d83934ac26dd669e17263a37e2800f98db572a26d1b26af92d936a694d4460e955ea6e87f734acbb21e0ab88d61afa53035949ddff6b89d387e773612918c983f1b228ab7df5dd629d0d643b2172c67f72fed302670536735ac90eeb25f9b7125b5f47621bc6e91b44d48920d9d59e1b8a4335fb14868c9bdeb36057e6a57a083fa3b5d5e4740626a15beed40a4444afe0d8cda7c7d8af7255c3f531dcd780f72be0991cd4b66a3ed8b0f11a3dda2032ffbcb4ac51867aae
#TRUST-RSA-SHA256 7a652b0c8f0e807e2f3c4d1a78b314d561cd0b0e1c70570c53692cd33ac39e914ad872ded396e48863f4b3aa2db211a780b8390389adbcedeacdb68844712f8b741b18733f8a598e61e640403fd8141e42bfa0757120ae54cf7de4fd882ac8943bc38b6c8393d2d178239b8e3e0df193cd30580f85443f52fc3ebe610ee2fd213a5647de52ccf2d33ab9f1d575743d954f2a5691bc7e41c17c0700a51fd1d26aba1370b480f4478ed3f25af799d89f03baae6f5145cbe26a7c8aa8711d5bc8d3d963c4f620e3668fb3c227aed434c3914f7a2cc4ed1e17591ff814630c7441c6271d173c63f03e08369a5bc7ac8ad347d8a93d4542c4d0d0c31d78b23fb73937ddaf1ca82b230858726eedc880379e6a07c28d0f050fef18bfbd4183df89976da5da97936e4a2eacc45a197c6fd8719d0ed4772be2660446b1c30f8f6cb5292bcb2d532337fcf8218c4b4c35513bda215b6a40dae571752ec0d5185998c11e21c7eabdc5992982b183c7be71ccdd9870db01a290fc60a7b482d9dbfadc66c7cb4d0062ba0fb54f29dde733ccd6e475c09eba3a03745ddefb9b10cda86b057446436e0cda2161206fe286685d37eb65c9c8586f0ef402fea999f5f4f5f5dab4384e53ba1c7fb8a7c6dd2a804cb48337a6fe1e9edf0bba774e49ec4a57d1122edd8fcaa308b912279cf591e95444f06d682b1253ee81e9e0679865482bf844974e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132052);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2018-0182",
    "CVE-2018-0185",
    "CVE-2018-0193",
    "CVE-2018-0194"
  );
  script_bugtraq_id(103547);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz03145");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz56419");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva31971");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb09542");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-cmdinj");

  script_name(english:"Cisco IOS XE Software CLI Command Injection Multiple Vulnerabilities (cisco-sa-20180328-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple vulnerabilities in the CLI parser
because the affected software does not sufficiently sanitize command arguments before passing commands to the Linux
shell for execution. An authenticated, local attacker can exploit this, by submitting a malicious CLI command, in order
to gain access to the underlying Linux shell of an affected device and execute commands with root privileges on the
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e07f0cfe");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz03145");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz56419");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva31971");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb09542");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuz03145, CSCuz56419, CSCva31971, and CSCvb09542.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0194");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [{ 'min_ver' : '16.1', 'fix_ver' : '16.3.2' }];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuz03145, CSCuz56419, CSCva31971, CSCvb09542'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
