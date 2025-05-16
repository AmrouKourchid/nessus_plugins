#TRUSTED 437d748b79f04316908ecbf6fe027b579825c18f5107ff7c0b5fb3212415d566f1137b913bf92385f75269ebe1af9d7db9594b9eb3e71a46e1c0bf568f36a6c45847af170316be38420b4d8ed31f78cbb0e5f579e7daf2ee03a3264ad6c06c10153cdf856f4db895b8dbf91a23b065034a2c760061b183f44423069fb094f37a6c20458ec81d57805ae309e0641c16c3488313f5b6383ad36e072e11d44fa13a9adeceecd16994c7b3dc58d4b1900ffb5645ff200a8e2d32f60f2d703c449ca09b5a1eaf98b2851c63847f52fb93d91b8460b2ad69df30542c6578d2e70c4cd0ae8728b3571d7c8ce65180456d73678d4fcf1a57d85d226ef30a00858e9f5a4d0caac7f43e9dc4b8c24a84a82e6eaa0178731c2a68b7388b81154b05d87a7b54369cff9b10d87fa77011a593b9d6191bce3869a329327fbdf736725b9f36b22b532828d700b427ece39fd0c168685cab3e35b18ec0da255bee8a6d03d86cb5572ba53e6490e0d1106aa82396fbcc4136dda64e56b05dd667cccadbc4892789f96b1a955066969ed1b22360ed70f350487d2eec0dc475adbd0fc9f7f082f63973882e581d419b415f92803fd242c09ed11e832aa9e877ac081e35900ca4558293010dae905799255356134dfb6148ea0a4bd2755c9aae6dd06b30a0d30d05afae71b86a43745e891c2a1f53d738fa4499b1d6a9f702d75f34294b9e20fa8b9212
#TRUST-RSA-SHA256 a8e37569813f830e2abd4ee7e822defc0ba7cb4454435ec7bcd6a3bb314fdaa44d9ac79ba51c3e3d53bb269971f844587c01e526f8c0e879133a1faa778285de2b9e67357da353ec03b03acdc810b6324b89f8a56323c084f5b3dd58ccc408ecbcfb2af95fe6678b1fc0a83df9fb60bae4d5cc8b737b3ce5e2a6ce5e74f857143a225c6a196025453a493076af5640e3b04d809ee7aa201955476b1d937423e693ddd510cf1ba509fcefc97f830133636fc6cc55767d993ae49655e9978fac5e938d72d0eca302abb76a31f38dc5fef532c5151a89c466814c3ab16c02c13ccd16be190f81a5879f2b570db4dcb91715456b5f9b7f27fb2be203705274b8fdaa2e5bbf3fc535261a42f5070b4b8f98f75d73634c1a3196277feb6d1f044ee8c8112ddb0ae4f3b865186e2abbce5c751f960c04eb41566fed469301d6b7a49a87e9aca46e0985f9e0006470a5174424428b37a5e4790202788cbf90a517e22a817c03260a853c9264415a3f949647caf173a17330b3309f3c22edf8e16b4b2fba7e163019a32e022020f4a01f7015cd95961392184e0e881e53f47b23211d9b9f1175c46c6f80c365da5b14afbd5a8ef7fb94a17d0aba16cf3f7406664b16a9b307d174f2fcb97f1f4a8911ee39c7323178f8e06524905331fbe3d4e4e28f070629baad24e1a25cac78608d6446b0b5808533f4e3c1ab4f8bd59ec05c83c1d5a2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191750);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2024-20294");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe86457");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67408");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67411");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67412");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67468");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi29934");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi31871");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-lldp-dos-z7PncTgt");

  script_name(english:"Cisco FXOS Software Link Layer Discovery Protocol DoS (cisco-sa-nxos-lldp-dos-z7PncTgt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS is affected by a vulnerability. The vulnerability lies in the Link
Layer Discovery Protocol (LLDP) feature of Cisco FXOS Software and could allow an unauthenticated, adjacent attacker to
cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper handling of
specific fields in an LLDP frame. An attacker could exploit this vulnerability by sending a crafted LLDP packet to an
interface of an affected device and having an authenticated user retrieve LLDP statistics from the affected device 
through CLI show commands or Simple Network Management Protocol (SNMP) requests. A successful exploit could allow the
attacker to cause the LLDP service to crash and stop running on the affected device. In certain situations, the LLDP
crash may result in a reload of the affected device. Note: LLDP is a Layer 2 link protocol. To exploit this 
vulnerability, an attacker would need to be directly connected to an interface of an affected device, either physically 
or logically (for example, through a Layer 2 Tunnel configured to transport the LLDP protocol).

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-lldp-dos-z7PncTgt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?789ffa5c");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75059
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e327a04a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe86457");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67409");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67411");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67412");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67468");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi29934");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi31871");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe86457, CSCwf67408, CSCwf67409, CSCwf67411,
CSCwf67412, CSCwf67468, CSCwi29934, CSCwi31871");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20294");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(805);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'FXOS');

# Vuln models Firepower 4100/9000 Series
if (product_info['model'] !~ "(41[0-9]{2}|9[0-9]{3})") 
  audit(AUDIT_HOST_NOT, 'affected');

var version_list = [
  '2.2.1.63',
  '2.2.1.66',
  '2.2.1.70',
  '2.2.2.17',
  '2.2.2.19',
  '2.2.2.24',
  '2.2.2.26',
  '2.2.2.28',
  '2.2.2.54',
  '2.2.2.60',
  '2.2.2.71',
  '2.2.2.83',
  '2.2.2.86',
  '2.2.2.91',
  '2.2.2.97',
  '2.2.2.101',
  '2.2.2.137',
  '2.2.2.148',
  '2.2.2.149',
  '2.3.1.99',
  '2.3.1.93',
  '2.3.1.91',
  '2.3.1.88',
  '2.3.1.75',
  '2.3.1.73',
  '2.3.1.66',
  '2.3.1.58',
  '2.3.1.130',
  '2.3.1.111',
  '2.3.1.110',
  '2.3.1.144',
  '2.3.1.145',
  '2.3.1.155',
  '2.3.1.166',
  '2.3.1.173',
  '2.3.1.179',
  '2.3.1.180',
  '2.3.1.56',
  '2.3.1.190',
  '2.3.1.215',
  '2.3.1.216',
  '2.3.1.219',
  '2.3.1.230',
  '2.6.1.131',
  '2.6.1.157',
  '2.6.1.166',
  '2.6.1.169',
  '2.6.1.174',
  '2.6.1.187',
  '2.6.1.192',
  '2.6.1.204',
  '2.6.1.214',
  '2.6.1.224',
  '2.6.1.229',
  '2.6.1.230',
  '2.6.1.238',
  '2.6.1.239',
  '2.6.1.254',
  '2.6.1.259',
  '2.6.1.264',
  '2.6.1.265',
  '2.8.1.105',
  '2.8.1.125',
  '2.8.1.139',
  '2.8.1.143',
  '2.8.1.152',
  '2.8.1.162',
  '2.8.1.164',
  '2.8.1.172',
  '2.8.1.186',
  '2.8.1.190',
  '2.8.1.198',
  '2.9.1.131',
  '2.9.1.135',
  '2.9.1.143',
  '2.9.1.150',
  '2.9.1.158',
  '2.10.1.159',
  '2.10.1.166',
  '2.10.1.179',
  '2.10.1.207',
  '2.10.1.234',
  '2.10.1.245',
  '2.10.1.271',
  '2.11.1.154',
  '2.11.1.182',
  '2.11.1.200',
  '2.11.1.205',
  '2.12.0.31',
  '2.12.0.432',
  '2.12.0.450',
  '2.12.0.467',
  '2.12.0.498',
  '2.12.1.29',
  '2.12.1.48',
  '2.13.0.198',
  '2.13.0.212',
  '2.13.0.243',
  '2.14.1.131'
];

# LLDP on by default and cant be disabled on FXOS
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = make_list();

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe86457, CSCwf67408, CSCwf67409, CSCwf67411, CSCwf67412, CSCwf67468, CSCwi29934, CSCwi31871'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params: workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
