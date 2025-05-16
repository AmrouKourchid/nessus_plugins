#TRUSTED 6a12fc2b94902e74d0e1fc46e58379c4e4411ad3fdd85bea0ecfbb13c3c1f636dd9ee8b0c0990e9fdbde000c319b243a52990d8c0049f629679110bbcf2420c4b83b0671f5fdfa1fff95d2c20f118a4756eb03b7668eecd7b7e9369621b8e43edbb405c6844b7e18863d519d4d22618a6ed11bd46cb3e9bb83faeda390082b60272b6e4ba7ac536694e2813ce4fd16e3b8d44ed51bba80a612a877af876904952be9133b2e8c535d713e9a2f17da7b8b12a341de346e3a34265dd38488e0baf7f7ded3cafe42a17af29187df831a0ec13e6c405b4ad833eca2a30e910feed22a22ac5d1ebe020786f0bcff6cf9e078a83082576530778f5e5176b18d106592ac92f7f5e1550bf4d7756dbfdae6e409ac704703ad6dc2ef7be631d195b198675119c387bc502a4b1099a12b150cc7d539d4c5c0689a19ab7439f399980efafd310a3bdbbdc70f6f5555e9d03e0d2d0bc78a584444979dd303b79ac9ea3240cd88fc73cc02d8c7fe7723f5cd8eda8637f699dd29b93a8769457ef2f9d3ef2c7ea00aac224e1c490fde296a178bfd1fcf6a1b4fdea57e2bb503bbe0849dda352add2b473a5b9790515e4484d9691b7ae2845f935f7f05caeaf4bee0b7390670e0c6b6bc8c0447f0a56335aec456fd55aa4e185126c080f069f949271bd891e62208a80f658c6e6709c55d6063b49c29dbed99d8707af3a11fb76d457501fd031339
#TRUST-RSA-SHA256 698719b162a37758503230c992df773e549f994c8b6537276a6d17de1de1bb4e80f346bf9aa0149c876a1657e16d2cbb4f84258461b4ed2996ad29e73dc0ce2a0961d4325418e0adac64891d76092c209248e67d283a5907ff48d8fc5e8ea283ad8457f15b3d03ab8163f26b0ae69cb0553b2eab7f292f6c8b5f77c9dfa9cd6459628c32928b4f40a52a1f2a826d4a72cda19cdaccccd68ad4791027bdf0a36c745d9b5be519e77c05b616b000ca4d7b5c86a776b13af5592886346b55504dcbc0904dfc269e81fc7e0f0806a5ac983c893577714a769245dd35399e200d95b80812bd385ef228d3cef5b7ae1d1e255f967b8d2d3caeb56c760ad62d2017a2b9c839876b54080c61c5dc13e1aedde9581ca1b91b696c0f3bc6ab3052a2e22cfb1519d002e597c0050087ff7a48278bc2751baa7133884b2d1e98a0db05bd4a8357995c1d2e4010c19e04f2f55652fb49a1ad390cb0a3671a6f92a193cb6ce9a9ace3d1f9960674e421074aecec9f4d9ef1171b1cff7d6dd8e0b6fb175eb34825c4035de713efea587bcacfc2bfa74618620596892d12b97c7a623a2dc00ac55ea577a6ca22e061c1bf63ac4d293b955799fbb0e9c541bb068cf6505d63467ae09cdff40b23c5ad7867909cf2907eacece6b643d04037efb4e2338c670d8dbb18c55cf0a1b5c3c1c1975776db8b0ddd4ad3b2311a8636e1e74615359a5280a630
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128615);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1742");
  script_bugtraq_id(107600);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36797");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-xeid");

  script_name(english:"Cisco IOS XE Software Information Disclosure Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web UI of Cisco
IOS XE Software which allow an unauthenticated, remote attacker to access sensitive configuration information. The
vulnerability is due to improper access control to files within the web UI. An attacker could exploit this vulnerability
by sending a malicious request to an affected device. A successful exploit could allow the attacker to gain access to
sensitive configuration information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-xeid
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beafef95");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36797");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi36797");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(16);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
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
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi36797',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
