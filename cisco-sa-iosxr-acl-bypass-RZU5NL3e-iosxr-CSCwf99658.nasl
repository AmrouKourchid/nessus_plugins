#TRUSTED 4124b9d6cf64cd9cc74e7f1e44c02fef02da39fe67bd97b3cb1e93156d1237e5e1705fbd4bc60540f0693a3e05a681a39e4d14f564c71a815b615e5f528698ffae50a7ecc5cb8e92c456581a907869c970de67ecfcd663e72a6ab9938565fc3a0c531913c179a0feeff1646d0775d06c1647dbf2fd0139edbd6a94266703d60ffeef1457228956b06ccd1d34b68cf0824af7fee7494ea5358b0acf192d80b18da1815736649c03fd2780386e4b8c31e947f8e9b6f339f75f244ce041d1e9b9765ed2a53447289594849019a640101425eb647ccec48e4686ae8fa8d9dd901229819266bb0b230f1820145c9b4e615663a94a7177dd1584602fe7eb9cb2d9c1135988bf16dd63252541d5b597ef158ea168ef992a7ae666ff1b8fd3f6996603ace005e9e33a76c5602936b1fe05fd4a132c42a0797b17eac3804c17a8ad48704abfe8745337a1e2860397cc7ede4eba2aca40bb5ef3176a52057145a873a3b463329290e0863f0733f2bb6b2400f419ac5d41e85bd7b329cd2e80ea6109d9d9007191c40ea872e3cba8cb95f9f5f961c1951c7db83ec6188ddb3356ab8e203574597b1396293d5bfed80757a0eb8e168f5b9e3cce497a365a96928666aa6fefbf1e8e8d3dc1b19b0bf90f10616b885dd8e1044ee7d0c92f78da1d5b273dc660fcfbe8c2ad57db2eb4443da812aea32b9f2c021de18553fffabf7489d148b03f89
#TRUST-RSA-SHA256 a6f038d6d3401d64e18dfa8dc25038df72e1735e8d606b548635d31b6f91fee29e107594faaadae001bc0c787c90cf0561acceff8327232bcd328b4387e37e73de946e0c4b0a187fc7567dca1772f0b516db1aad1f2b01d0d373046a55bfaf5c501a78b968a91bf56aa7824201d72a86657852fa7ce941d875202582f43155e98acf68376b5b55f8f635d9ee76583ac4ba420dca2b6564f91ba30727706841e496e6cf2c5fec07dcaa4c5051a0a1c2a203430386d5d3cc15e8f910a7eb59ebcd9b37afbd7bd9ce180cd81a5549aa6b25a78b20fbd22f2194db202c376d42e42eba078238adc9cd394213ba6b9323b07eb9827f516bd38168d7edf12c53698643756027388647bab0f8163098b5812f2875cebbc9b03c54b6c2bc0a055a19ece548c8ebd33513a8a7d45b6134a847c34c811f031f3c6b7c86c4abe43cb3cb07cd227462f059b0aac5d97f8345807620cf4a0582e3efae713fba0edee057787da5b6fbf8c2e734dc85345ce8caf3c8dc8fa494e3b25057bc2ceb4670e2500746cebd4e1ec58eaa05c43290962c1606d8eb13348eb847a161c5ca668127bb7bd528cc1b3d3d61c4c58b07743083d18d360b3a7a5f878c09b933ca8566579a185245125c9f67ba929556080728e2c9f862e0735c61295c698b2714a81acadd3495759880ac34693718838665d4bebb8565188bb785d9b9957dcf37328b402f2ab62e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206038);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/21");

  script_cve_id("CVE-2024-20315");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf99658");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-acl-bypass-RZU5NL3e");

  script_name(english:"Cisco IOS XR Software MPLS Pseudowire Interfaces Access Control List Bypass (CSCwf99658)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the access control list (ACL) processing on MPLS interfaces in the ingress direction of
    Cisco IOS XR Software could allow an unauthenticated, remote attacker to bypass a configured ACL. This
    vulnerability is due to improper assignment of lookup keys to internal interface contexts. An attacker
    could exploit this vulnerability by attempting to send traffic through an affected device. A successful
    exploit could allow the attacker to access resources behind the affected device that were supposed to be
    protected by a configured ACL. (CVE-2024-20315)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-acl-bypass-RZU5NL3e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7ec5d32");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3206828a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf99658");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwf99658");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var ingress_found = FALSE;

var override = 0;
# Not using cisco_workarounds.inc because it's not likely to be reused 

# Check for mpls enabled
var buf = cisco_command_kb_item('Host/Cisco/Config/show_mpls_interfaces', 'show mpls interfaces');

if (check_cisco_result(buf))
{
  var pattern = "^([a-zA-Z0-9\/]+)\s+((Yes|No)\s+([a-zA-Z0-9\(\)]*)\s+)+Yes$";
  buf = split(buf, sep:'\n', keep:FALSE);
  
  foreach line (buf)
  {
    var conf_match = pregmatch(pattern:pattern, multiline:TRUE, string:line);

    if (!isnull(conf_match) && !isnull(conf_match[1]))
    {
        # RP/0/RP0/CPU0:NCS5501-1##show mpls interfaces
        # Thu Mar 16 02:47:56.142 UTC
        # Interface                  LDP      Tunnel   Static   Enabled
        # -------------------------- -------- -------- -------- --------
        # TenGigE0/0/0/0             No       No       No       Yes
      # save found interface ex. TenGigE0/0/0/0
      var interface = conf_match[1];

      # check interfaces have either an IPv4 or IPv6 ingress ACL applied
      var buf2 = cisco_command_kb_item('Host/Cisco/Config/show_run_interface', 'show run interface' + interface);

      if (check_cisco_result(buf2))
      {
        var pattern2 = "ipv[46].*ingress";

        var conf_match2 = pregmatch(pattern:pattern2, multiline:TRUE, string:buf2);

        if (!isnull(conf_match2))
        {
          ingress_found = TRUE;
          break;
        }
      }
      else if (cisco_needs_enable(buf))
        override = 1;
    }
  }
}
else if (cisco_needs_enable(buf))
  override = 1;

if (!ingress_found)
    audit(AUDIT_HOST_NOT, "affected because IP ingress ACL filtering on MPLS interfaces is not configured on the host");

vuln_ranges = [
  {'min_ver' : '7.9',  'fix_ver' : '7.10.2'}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf99658',
  'cmds'    , make_list('show mpls interfaces', 'show run interface') 
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
