#TRUSTED ac188a193b0281455d07feac8d6b3d58462fd433fe2a317cd4ad32fc9ecd3e828ec74092e7f998d7171dc6eda3e94564da78685885c7c866a19a6e3e2e7162943b9214560c7bbfedceea76a0c3f0c69f0ebee93e210700d5d8df398307483a9510da83f26bb30fa0142d46bee97dce460a813d39964369f790aedd180cd5f9b1bac682ff5fbbe1444ad4c46684bb9d6dab01339f64aece5b0483f60f23364b763ac365368f4064239d389fda463ed7133a81cf20cf2f6026dd1d56977a4e5168614f4f01ffb485168d2bae69fb9c85f85b9443c232459ddd2bdacb26df68ada91a438792ec1619325b2b18c5c6bdcf8b08f8d51510cc3ea48344edf579e8ae41b876dd077aa9caabef38ea7e32fd2575ad3e2bc0aa6f5d03feff127a3c3f0efdee3ceda672aa1471e70c4a2855824d0f1c89eeec714efb7dda7c0fc6c0257159cf052e08d23ab081cceff2145f96ab7dacde4e29581be5ef3f81cc2c6b5aa10e22283aa19221c8fbc4fe3013b1f81aa871ca36a66c0d52f362480f5a069b82ce24a8238d4ccfe9765c725c98ccaf29909a48bd9e6cf1077fe448066414295bb41b78107b593e0132abe4b98f72304d66ad472d617bd873f2283334ea2f0e5db8b8ddd3eb3cf7738135ffffe66570f8115ce9068c74c0c49532e32368eea25369d5beeb0f360e3d652e8b7ea52b38c3fb4c2bbb93f84e592063fbf92787f2fa4b
#TRUST-RSA-SHA256 603638fabcef9a66805c20f68e30615c5107431af10d49e3e05597f6b128dde19d59ba365f1fadcb4fb651ae9084ded38461482180ab69bc454252a7520e524f5478fa0ae5fc9c9d6c26f7ba136f2bba31624bf6d820d957a3a3dec255ac8cfcb97f71e13cf68a7463c6b24dd2613863fc00d042290071bef5f2374d4a504c2df101eb87b86e7061f624b900142dd793a62fd5ee61f3efede6a2027e7b025b6f9554ab92d51e7ca87e9d5f925e7be654c08299e95ebf35ad17158f4342ecd5c5d646c2d7094d78f06fbbc32dad5dd914d75ca0576a2f7f221c43024bc0d9cc9383fe98b65154411b7889143322fa65c08752550a70d0e6a86934a9315055473ee7830cc79709d726da4df032019dd3bf6d7e673cef86f08f2d3838b9e350447223232602b3adf8b846928e445b9d49ecd57fdd06fb0164d4b0cdba8ddd0e2a0f0718922ac6fae43aba0511461c5e6094102630ebbe7eacf18b28f66ac205a5939495e53bea8beac9228632a453fc491d7651dfedc8af260f0dcf6ad8b0a2eb632840fdae4fcc6098fbe6b6b8af12a8790374c06451db5da6718b8480809845a4f265e9f707196f20c2a0ded97819995797e01d066d39fa0bb1d426d9ba1435f12f4f00f454b8bc9bf62faefbcdbc8cbb99d21815fb86d0e770dd1174998eba14649038db658fef9202f82451f24effa3f40a29ccd2c66ee061398fa686de10b5
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181007);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/25");

  script_cve_id("CVE-2023-20243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe47081");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-radius-dos-W7cNn7gt");
  script_xref(name:"IAVA", value:"2023-A-0459-S");

  script_name(english:"Cisco Identity Services Engine RADIUS DoS (cisco-sa-ise-radius-dos-W7cNn7gt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine RADIUS Denial of Service is affected by a
vulnerability in the RADIUS message processing feature of Cisco Identity Services Engine (ISE), that could allow an
unauthenticated, remote attacker to cause the affected system to stop processing RADIUS packets. This vulnerability is
due to improper handling of certain RADIUS accounting requests. An attacker could exploit this vulnerability by sending
a crafted authentication request to a network access device (NAD) that uses Cisco ISE for authentication, authorization,
and accounting (AAA). This would eventually result in the NAD sending a RADIUS accounting request packet to Cisco ISE.
An attacker could also exploit this vulnerability by sending a crafted RADIUS accounting request packet to Cisco ISE
directly if the RADIUS shared secret is known. A successful exploit could allow the attacker to cause the RADIUS process
to unexpectedly restart, resulting in authentication or authorization timeouts and denying legitimate users access to
the network or service. Clients already authenticated to the network would not be affected. Note: To recover the ability
to process RADIUS packets, a manual restart of the affected Policy Service Node (PSN) may be required.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-radius-dos-W7cNn7gt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc4d8092");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe47081");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe47081");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20243");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

# Paranoid due to RADIUS policy config
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [ 
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'7'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'3'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe47081',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
