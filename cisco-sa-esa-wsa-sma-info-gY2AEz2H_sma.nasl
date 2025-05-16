#TRUSTED 0b50cc61d34f35364b097872a909dcdabb1f44c673f11fd87ee7e23b94851067d5acf8618b33d9e52ef469607a9669aa3507c7377c48768b014297b7cc7372c4ac84b40f9ac35efca0998e05d6014ce2cdf3b638cd36b62a3bc34de11555623cf194bf36bb3fd06751829d807bafab59118fcd6a1b3ac72f8185acf42bc675401537c936712313e356c271bd6bab6299ec035f1b5a7957643e73141076aec1a567bff31d2eb1ef155d21ad34282d19b784968eb8465353c6dbe8aef86960955fcc7a86ff836206fe981569ff2748230afc58b4321ff37fa4337729acf5617794aa844b688e8d5fcb173668531baece90d2b54512d16398daebf947f0138f6e0e9b5575eeef48ba86be0ea78becddba9ca80ba4f4936cc276ea737afc5557a24439d49016aaf8f8150fd05abcfc628e7f2c6cb0be89cddeae944d007832bcda55f37c0b34aea663170797e813dc5e43a391118414fab5ecac4b281d241a33a2ca8c5f472b37a99801df216cd5358ad733ed0252ca65b8a252d0a332c503650fee380ab7c66d1499fcf4bc044402900ee61bf5773ea0638d7539d17474d8036d4e537337dfc6f1d491eb72a74ae4904d9b9910e724b547d266a5ea965b455a927f7138b33911cf9d38315a7c23850a17dc6294ed9167c81d73769ffba987ec96ed95ebdde4f15359a16bf75dffc9029541da28ae968345b6973913c414805b755a
#TRUST-RSA-SHA256 65a7bb7bcc30fc36cdf1fc918d129e7e2ab86e1e843c1a8f0f4ddbd4e6f7d969f9de2be79c953e0edb1f2f2e09a4c7f0b9b122a42951833676c4a0a332918f70256f137377e2b60358a0219da1937c68bc1a47e53a63f67f942fd5fc362ae3d74803a51ccc94d59ed8f80a22636bc7d5641856a4efc6a33c7b4c213be669c1b6db9429b50d2c40e9aac5f1eeed8de58742cbf9310185e59fd7bf90fad2181bec8a3cdb7b2d0c790974d677101413b1c150873af9aca83e1f8b628acb2aeec0996d89c72353390019cd61952f089653dc903c6de14fef2e5d2d95963473aea36615fc3a45c8529c54f40c6dbe9c4536eb2be48b10647e55fb593ff50860b0964466a7810dd22260fb805555c54ad23574e6b730334611e442bd7bdb277a0fc98c5d329177007842de51e8c8c763e928ac3355a23049dbdb7695f3f656db92955344c35040e185b39950caef1164286c915ff25b3a5f2338abe7dee66fd7f335175336bb78342c1f61fb2bbb4937fa1cef0bacd504cbee26c06c6e1396ec42959290ec938e89cc3ee666b88d7d28722a0997e2814f9d04d792d0ee8337b3d0917061f3ff2fb74044ac1dfc3265744152da79a06fd0b4af91e65231282ece5e08375a9b78fa210c991f05a72cb9d666a50a912ac93047043e5a26b63bf77209814bfcbcf4fe32a2ec58e36dbce77e029b245a82d1bc7eb7464045192502c23476d1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149842);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2021-1516");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98333");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98379");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98422");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03419");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03505");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw04276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw35465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw36748");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-info-gY2AEz2H");
  script_xref(name:"IAVA", value:"2021-A-0244-S");

  script_name(english:"Cisco Content Security Management Appliance Information Disclosure (cisco-sa-esa-wsa-sma-info-gY2AEz2H)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Content Security Management 
Appliance (SMA) could allow an authenticated, remote attacker to access sensitive information on an affected device. 
The vulnerability exists because confidential information is included in HTTP requests that are exchanged between the 
user and the device. An attacker could exploit this vulnerability by looking at the raw HTTP requests that are sent to 
the interface. A successful exploit could allow the attacker to obtain some of the passwords that are configured 
throughout the interface.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-info-gY2AEz2H
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?156a645c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98333");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98363");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98379");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98401");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98422");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99534");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03419");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03505");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw04276");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw35465");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw36748");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401,
CSCvv98422, CSCvv98448, CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(540);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '14.0' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401, CSCvv98422, CSCvv98448,
CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
