#TRUSTED 7c3be0e918e5a34631886d400b4c27586569f6adf4cc4d134e4ef8c73743dddf3385cef12a5306263a205062fc6720fd5deae469073337106d49e0fa2bc6e0a35fe68ea747dc72a13374c074efe6704f2a5d3ce07b447559a1670958215a58f55ff4e88b6000dcf6d775e789aaa92080806856d06f0b47486932042c37fb3551b886d9e98c20d85d283ca70a1bdd6eae39b6ceee09f648e041c23969656e7a59521c0f0b394d74696bd57c46b6354751515aab102e9ccae58c810dd5bd10f7b6c6757e34602aa3403e0968529918c27499d19a22e5bed759bf0f431d97f7df3591cdefe63cf007c98ba2b511ed83a274ecf130a27a617582d4a53b26f62afee20e26e65e9e2df674eccb7bd4417952fe90456922015bed00d75f8dcabb41faf3ffd0448a8c4e2c2efb97f047674cb86b7af670bd78c69a7978e858d57313d18e63abe3e2f392f757dce13c06c30c0bf74a5850692375e055ac44b4ca3c8ce56f398cf94fd6d53a9846e38516ccc17e536c1b0181e7507666b439fc1cdf29c4ff9c69aaede567f613b2dfe4bc3679b5f5a69f1da6f373cebb84306856d5705e5dfd7f38f549679d5cfad5b4209e9546db28f379e5bb8a08286e35cc2aa43015f315e4e76b924563ac5117765a4d1193eb6dfccef0b6ce0f77129a3e60c883157c6bcba42e34b289404fb9793969af803b8d9a8736c27d7111ae351528eaac6452
#TRUST-RSA-SHA256 1e4c7a1c9b2189bf3a94f13aab8f917f34f7e5b322e80e2168a5b715f07e8de1887f1f87380f08e3c266e7f3a8cb92fe0e90ab1039125bd862c24c809df7107b4b979baad0e490b2e01a94abecea41a96674009eccbdf00a07fd02bd30bde86e854a3498ddf0ca8230ea2f33dfe122f8593702f2e9f4c945660151ea7ae19c8e920f54cccdc1e9bb05870c6981f2f940fd51d74b4647e55f42acc2ed9004361d9adb61f5816267472c66791fde57d768773d708ec71da915aa14ec56653e2c34ad02f4884d9a2ac2ddd6fcb792e9a2b2eb6fe61fa85394eac445d0b465e582b1df62ab6496b2e47cfb6edf9d15d226f08d02a6e9f20124732f557d4c1222e41f2ac5370f8379ce420c160ff92aa29ef58662f391e9fbbacfebdcd1c178a6f53cdb623b4de1aceb220b070e89647a5aebde39bef05d0bad0c95afa5d664e5090dfe9cd816e773143ce8dcaeb6002904aac98376d1d94f51ea726eeafcc5ddb603af94644dc97ae6bd0b6f0014b08aa5cad85803033eb49b6b7b583eebdbc928aec20374190e9e13be958f79ea65a67ced11f52a8de50e418c60ba1ac3f8128f5b105ba12482f9c28e48b64e01a051cf5941b3669e0e2cc54209850cd82b962ff526aed082d2f6721ae07abed4260277bdbe039eac3b87e3aacab47ae2d63a16bf9a09f4c7ff62161f058617f0b220fb1d6eebcc3eba90984c9eb1974e9bebe1c9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125391);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/21");

  script_cve_id("CVE-2019-1597", "CVE-2019-1598");
  script_bugtraq_id(107394);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd40241");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd57308");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02855");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02858");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02865");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02867");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02871");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve57816");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve57820");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve58224");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxosldap");

  script_name(english:"Cisco FXOS and NX-OS Lightweight Directory Access Protocol Denial of Service Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software and
Cisco NX-OS Software are affected by multiple vulnerabilities which
could allow an unauthenticated, remote attacker to cause a denial of 
service attack (DoS).
The vulnerabilities are due to the improper parsing of LDAP packets
by an affected device. An attacker could exploit these vulnerabilities
by sending an LDAP packet crafted using Basic Encoding Rules (BER) to
an affected device. The LDAP packet must have a source IP address of
an LDAP server configured on the targeted device. A successful exploit
could cause the affected device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxosldap
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453a1923");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd40241");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd57308");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02855");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02858");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02865");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02867");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02871");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve57816");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve57820");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve58224");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed / recommended version referenced in Cisco Security
Advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1598");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

cbi = NULL;

if (('MDS' >< product_info['device']) && (product_info['model'] =~ '^90[0-9][0-9]'))
  cbi = "CSCve57820, CSCve02867";
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^30[0-9][0-9]')
    cbi = "CSCve58224, CSCve02858";
  else if (product_info['model'] =~ '^35[0-9][0-9]')
    cbi = "CSCve02871";
  else if (product_info['model'] =~ '^7[07][0-9][0-9]')
    cbi = "CSCve57820, CSCve02867";
  else if (product_info['model'] =~ '^90[0-9][0-9]')
    cbi = "CSCve02865, CSCve57816";
}
else if (('UCS' >< product_info['device']) && (product_info['model'] =~ '^6[2-3][0-9][0-9]'))
    cbi = "CSCve02855";

if (empty_or_null(cbi))
  audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list (
  "4.1(2)",
  "4.1(3)",
  "4.1(4)",
  "4.1(5)",
  "5.0(2a)",
  "5.0(3)",
  "5.0(5)",
  "5.0(1a)",
  "5.0(1b)",
  "5.0(4)",
  "5.0(4b)",
  "5.0(4c)",
  "5.0(4d)",
  "5.0(7)",
  "5.0(8)",
  "5.0(8a)",
  "5.0(2)",
  "4.2(2a)",
  "4.2(3)",
  "4.2(4)",
  "4.2(6)",
  "4.2(8)",
  "5.1(1)",
  "5.1(1a)",
  "5.1(3)",
  "5.1(4)",
  "5.1(5)",
  "5.1(6)",
  "5.1(2)",
  "5.2(1)",
  "5.2(3a)",
  "5.2(4)",
  "5.2(5)",
  "5.2(7)",
  "5.2(9)",
  "5.2(3)",
  "5.2(9a)",
  "5.2(2)",
  "5.2(2a)",
  "5.2(2d)",
  "5.2(2s)",
  "5.2(6)",
  "5.2(6b)",
  "5.2(8)",
  "5.2(8a)",
  "5.2(6a)",
  "5.2(8b)",
  "5.2(8c)",
  "5.2(8d)",
  "5.2(8e)",
  "5.2(8f)",
  "5.2(8g)",
  "5.2(8h)",
  "5.2(8i)",
  "6.1(1)",
  "6.1(2)",
  "6.1(3)",
  "6.1(4)",
  "6.1(4a)",
  "6.1(5)",
  "6.1(3)S5",
  "6.1(3)S6",
  "6.1(5a)",
  "5.0(3)A1(1)",
  "5.0(3)A1(2)",
  "5.0(3)A1(2a)",
  "5.0(3)U1(1)",
  "5.0(3)U1(1a)",
  "5.0(3)U1(1b)",
  "5.0(3)U1(1d)",
  "5.0(3)U1(2)",
  "5.0(3)U1(2a)",
  "5.0(3)U1(1c)",
  "5.0(3)U2(1)",
  "5.0(3)U2(2)",
  "5.0(3)U2(2a)",
  "5.0(3)U2(2b)",
  "5.0(3)U2(2c)",
  "5.0(3)U2(2d)",
  "5.0(3)U3(1)",
  "5.0(3)U3(2)",
  "5.0(3)U3(2a)",
  "5.0(3)U3(2b)",
  "5.0(3)U4(1)",
  "5.0(3)U5(1)",
  "5.0(3)U5(1a)",
  "5.0(3)U5(1b)",
  "5.0(3)U5(1c)",
  "5.0(3)U5(1d)",
  "5.0(3)U5(1e)",
  "5.0(3)U5(1f)",
  "5.0(3)U5(1g)",
  "5.0(3)U5(1h)",
  "5.0(3)U5(1i)",
  "5.0(3)U5(1j)",
  "6.0(1)",
  "6.0(2)",
  "6.0(3)",
  "6.0(4)",
  "6.0(2)A1(1)",
  "6.0(2)A1(1a)",
  "6.0(2)A1(1b)",
  "6.0(2)A1(1c)",
  "6.0(2)A1(1d)",
  "6.0(2)A1(1e)",
  "6.0(2)A1(1f)",
  "6.0(2)A1(2d)",
  "6.0(2)A3(1)",
  "6.0(2)A3(2)",
  "6.0(2)A3(4)",
  "6.0(2)A4(1)",
  "6.0(2)A4(2)",
  "6.0(2)A4(3)",
  "6.0(2)A4(4)",
  "6.0(2)A4(5)",
  "6.0(2)A4(6)",
  "6.0(2)A6(1)",
  "6.0(2)A6(1a)",
  "6.0(2)A6(2)",
  "6.0(2)A6(2a)",
  "6.0(2)A6(3)",
  "6.0(2)A6(3a)",
  "6.0(2)A6(4)",
  "6.0(2)A6(4a)",
  "6.0(2)A6(5)",
  "6.0(2)A6(5a)",
  "6.0(2)A6(5b)",
  "6.0(2)A6(6)",
  "6.0(2)A6(7)",
  "6.0(2)A6(8)",
  "6.0(2)A7(1)",
  "6.0(2)A7(1a)",
  "6.0(2)A7(2)",
  "6.0(2)A7(2a)",
  "6.0(2)A8(1)",
  "6.0(2)A8(2)",
  "6.0(2)A8(3)",
  "6.0(2)A8(4)",
  "6.0(2)A8(4a)",
  "6.0(2)A8(5)",
  "6.0(2)A8(6)",
  "6.0(2)A8(7)",
  "6.0(2)A8(7a)",
  "6.0(2)A8(7b)",
  "6.0(2)A8(8)",
  "6.0(2)A8(9)",
  "6.0(2)A8(10a)",
  "6.0(2)A8(10)",
  "6.0(2)U1(1)",
  "6.0(2)U1(2)",
  "6.0(2)U1(1a)",
  "6.0(2)U1(3)",
  "6.0(2)U1(4)",
  "6.0(2)U2(1)",
  "6.0(2)U2(2)",
  "6.0(2)U2(3)",
  "6.0(2)U2(4)",
  "6.0(2)U2(5)",
  "6.0(2)U2(6)",
  "6.0(2)U3(1)",
  "6.0(2)U3(2)",
  "6.0(2)U3(3)",
  "6.0(2)U3(4)",
  "6.0(2)U3(5)",
  "6.0(2)U3(6)",
  "6.0(2)U3(7)",
  "6.0(2)U3(8)",
  "6.0(2)U3(9)",
  "6.0(2)U4(1)",
  "6.0(2)U4(2)",
  "6.0(2)U4(3)",
  "6.0(2)U4(4)",
  "6.0(2)U5(1)",
  "6.0(2)U5(2)",
  "6.0(2)U5(3)",
  "6.0(2)U5(4)",
  "6.0(2)U6(1)",
  "6.0(2)U6(2)",
  "6.0(2)U6(3)",
  "6.0(2)U6(4)",
  "6.0(2)U6(5)",
  "6.0(2)U6(6)",
  "6.0(2)U6(7)",
  "6.0(2)U6(8)",
  "6.0(2)U6(1a)",
  "6.0(2)U6(2a)",
  "6.0(2)U6(3a)",
  "6.0(2)U6(4a)",
  "6.0(2)U6(5a)",
  "6.0(2)U6(5b)",
  "6.0(2)U6(5c)",
  "6.0(2)U6(9)",
  "6.0(2)U6(10)",
  "6.1(2)I1(3)",
  "6.1(2)I1(1)",
  "6.1(2)I1(2)",
  "6.1(2)I2(1)",
  "6.1(2)I2(2)",
  "6.1(2)I2(2a)",
  "6.1(2)I2(3)",
  "6.1(2)I2(2b)",
  "6.1(2)I3(1)",
  "6.1(2)I3(2)",
  "6.1(2)I3(3)",
  "6.1(2)I3(3.78)",
  "6.1(2)I3(4)",
  "6.1(2)I3(3a)",
  "6.1(2)I3(4a)",
  "6.1(2)I3(4b)",
  "6.1(2)I3(4c)",
  "6.1(2)I3(4d)",
  "6.1(2)I3(4e)",
  "6.1(2)I3(5)",
  "6.1(2)I3(5a)",
  "6.1(2)I3(5b)",
  "6.1(2)I3(3b)",
  "6.2(2)",
  "6.2(2a)",
  "6.2(6)",
  "6.2(6b)",
  "6.2(8)",
  "6.2(8a)",
  "6.2(8b)",
  "6.2(10)",
  "6.2(12)",
  "6.2(18)",
  "6.2(16)",
  "6.2(14b)",
  "6.2(14)",
  "6.2(14a)",
  "6.2(6a)",
  "6.2(1)",
  "6.2(3)",
  "6.2(5)",
  "6.2(5a)",
  "6.2(5b)",
  "6.2(7)",
  "6.2(9)",
  "6.2(9a)",
  "6.2(9b)",
  "6.2(9c)",
  "6.2(11)",
  "6.2(11b)",
  "6.2(11c)",
  "6.2(11d)",
  "6.2(11e)",
  "6.2(13)",
  "6.2(13a)",
  "6.2(13b)",
  "6.2(15)",
  "6.2(17)",
  "6.2(19)",
  "7.0(3)",
  "7.0(2)I2(2c)",
  "7.0(3)F1(1)",
  "7.0(3)I1(1)",
  "7.0(3)I1(1a)",
  "7.0(3)I1(1b)",
  "7.0(3)I1(2)",
  "7.0(3)I1(3)",
  "7.0(3)I1(3a)",
  "7.0(3)I1(3b)",
  "7.0(3)I2(2a)",
  "7.0(3)I2(2b)",
  "7.0(3)I2(2c)",
  "7.0(3)I2(2d)",
  "7.0(3)I2(2e)",
  "7.0(3)I2(3)",
  "7.0(3)I2(4)",
  "7.0(3)I2(5)",
  "7.0(3)I2(1)",
  "7.0(3)I2(1a)",
  "7.0(3)I2(2)",
  "7.0(3)I3(1)",
  "7.0(3)I4(1)",
  "7.0(3)I4(2)",
  "7.0(3)I4(3)",
  "7.0(3)I4(4)",
  "7.0(3)I4(5)",
  "7.0(3)I4(6)",
  "7.0(3)I5(1)",
  "7.0(3)I5(2)",
  "7.0(3)I6(1)",
  "7.0(3)I6(2)",
  "7.0(3)IX1(2)",
  "7.0(3)IX1(2a)",
  "7.2(0)D1(1)",
  "7.2(1)D1(1)",
  "7.2(2)D1(2)",
  "7.2(2)D1(1)",
  "7.3(0)D1(1)",
  "7.3(0)DX(1)",
  "7.3(0)DY(1)",
  "7.3(1)D1(1B)",
  "7.3(1)D1(1)",
  "7.3(1)DY(1)",
  "7.3(1)N1(0.1)",
  "8.0(1)",
  "8.1(1)",
  "8.1(2)",
  "8.1(2a)",
  "8.1(1a)",
  "8.1(1b)"
);

workarounds = make_list(CISCO_WORKAROUNDS['ldap']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
