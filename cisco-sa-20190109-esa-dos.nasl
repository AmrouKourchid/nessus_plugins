#TRUSTED 92b20b660df540de304e92832e9fdc37edd1afde56fb6b7550d98162bf1caf274799febf8dfd3514d250d624960491160f90c909aff9bde1c70f47135c79db127d6f5adcaa411c2b52593284196279a5783d8ea23e69e8aeeb98b8c577557a314766bd6da7b18a1f503614fbfcab3bb999cfb4b1a12736be8eff8dd2ec8d26a5e1ddbe9b871fefc7c242fd8b249e67dbc917c6c380211346dd2749a2d4d91d19d1b1c25822139118f9f2ce6895c1cbe42dbf614c9a4eba400ae34b0d01859ba44d071d7dcc1233e7cc0a1432a2e2fe4c69ce531c399fad0c5a816b98138c4d93ab6a391065a85c1b3717677e9ac8a3bebb8145bbd25ddac145794cbfa6da1c56e26e41d9d1e4d4a837b32b0634b4a27309c24a4585bd0cad78f9f979ce5e605a41fa5a9c53021bc07a1f3030111ca32b91c2a8f93f745ade2256004ca190ee902ee557719d875b54860fb9bc0508296fa71dd5795ef45f764d1e7389ea35ef6fa32dcb8c6403a98214178e1cb64f2fde380df43670e172e43e4b5e377626ee4b4dd3e070f3e9f6b064d2c978d514775cb2e468dafa052e01d1902189b1d08ea7ca99ec2a62ee94d255641c5585d407123e6e553aff17d634df0d89202d61ba7d5764b64fc4fad29ae25afcb9fb83ec3717ff4ae016c60a4ea333062d5bb2f73f2d4d471da8f1373f284ae9942acdc7ef663bb4ef9a8d3e4a8988a4f55d15ad91
#TRUST-RSA-SHA256 7e4372c02d5e0cca6f33a96307d64861ec3e1110bc400bf52228b278d27bf1241d1f6adf15f83fd7584f5cff70cfafd8301f30ffd7619d70e6df7d338c5f3abb601caa927f028bce439f7b9cf6fb07a7ac309a0ff064d361d6f58dfca0cd70f1afb18e22f353ce7572ae0c181aa6824224b3604dd5b216ff8a4e4ce837f607082c8bfd22e6b10dd6cc24863b95dc6f17eecfdc2bbfc8a5e107fbc0aeb5b32e810518aa5afdd549fbed234628ff05778c0e047949ef7f28b62845e182ba6be937ac539921b04115a2559cc65447f9826d547bd464f46ccf0d15dabbf8dc7beb6a6f8cb5161caa55c288eaafb9fe4e274229468f703a1c102eb0be84279306f1d9fe8fb4e26ed8205b5ace478db407e3273f01375dea00b758ea65bbf08af22f3107aa73d834c3a647da1cd52e570c17cd6cfcd56cb11f83962be63d26b533e44fe5ca552f8a436213986f7112198118ac04e98da23a5c5b44f1e2a852897e0d5293de8e048dd9691135afb614c3e19368c9bcac546ebf11ecd102f90ae00fcc8aef21c24cc0ba9a00b5b3f4ef33d8d0eaf07243db55f5936a16c87c452ec85d34f8ac902dcd5102426d8d4f32a0f7e6a988a63862cc53100ed8ccc4ff57cbc6e07be9a4b339b1eb55ec49e40c2d0980565729eb362279664371a1ae8d4727c86cb270d457e7ae9fea36bd99e969a88c7e3ba36c1e74e1adda57bca3bf028675e6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121248);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/26");

  script_cve_id("CVE-2018-15453", "CVE-2018-15460");
  script_bugtraq_id(106507, 106511);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk73786");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm81627");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-esa-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-esa-url-dos");

  script_name(english:"Cisco Email Security Appliance Multiple DoS Vulnerabilities (cisco-sa-20190109-esa-dos / cisco-sa-20190109-esa-url-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security
Appliance (ESA) is affected by the following vulnerabilities:

  - A denial of service (DoS) vulnerability exists in
    Secure/Multipurpose Internet Mail Extensions (S/MIME)
    Decryption and Verification and S/MIME Public Key
    Harvesting features due to improper input validation of
    S/MIME-signed emails. An unauthenticated, remote
    attacker can exploit this issue, via malicious
    S/MIME-signed email, to cause the process to stop
    responding. (CVE-2018-15453)

  - A denial of service (DoS) vulnerability exists in email
    message filtering feature due to improper filtering of
    email messages that contain references to whitelisted
    URLs. An unauthenticated, remote attacker can exploit
    this issue, via malicious email message that contains a
    large number of whitelisted URLs, to cause the system to
    stop responding (CVE-2018-15460).");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-esa-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17b6199e");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-esa-url-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3856e4d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk73786");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm81627");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory
cisco-sa-20190109-esa-dos and cisco-sa-20190109-esa-url-dos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15460");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Email Security Appliance (ESA)");

vuln_list = [
  {'min_ver' : '0', 'fix_ver' : '11.0.2.044'},
  {'min_ver' : '11.1.0.0', 'fix_ver' : '11.1.2.023'}
];

if(product_info['version'] =~ "^11\.1\.") fixed='11.1.2-023';
else fixed='11.0.2-044';

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version', product_info['display_version'],
  'fix', fixed
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_list);
