#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70895);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2013-4548");
  script_bugtraq_id(63605);

  script_name(english:"OpenSSH 6.2 and 6.3 AES-GCM Cipher Memory Corruption");
  script_summary(english:"Checks OpenSSH banner version");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server on the remote host is affected by a memory corruption
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is version 6.2 or 6.3.  It is, therefore, affected by a memory
corruption vulnerability in post-authentication when the AES-GCM cipher
is used for the key exchange.  Exploitation of this vulnerability could
lead to arbitrary code execution. 

Note that installations are only vulnerable if built against an OpenSSL
library that supports AES-GCM.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/gcmrekey.adv");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-6.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 6.4 or refer to the vendor for a patch or
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4548");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin", "ssh_supported_algorithms.nasl");
  script_require_keys("installed_sw/OpenSSH");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var types = make_list("client_to_server", "server_to_client");
var fail = 0;
var vuln = 0;
foreach var type (types)
{
  var algs = get_kb_list("SSH/" + port + "/encryption_algorithms_" + type);
  if (isnull(algs)) fail++;
  else
  {
    algs = make_list(algs);
    foreach var alg (algs)
      if ('aes128-gcm' >< alg || 'aes256-gcm' >< alg) vuln++;
  }
}
if (fail > 1)
  exit(1, "Failed to retrieve list of supported encryption algorithms on remote host.");
if (!vuln)
  exit(0, "OpenSSH installed on the remote host is not affected because AES-GCM is not supported.");

var constraints = [
  {'min_version': '6.2', 'fixed_version': '6.4'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
