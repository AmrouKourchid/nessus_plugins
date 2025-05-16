#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70658);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/27");

  script_cve_id("CVE-2008-5161");
  script_bugtraq_id(32319);
  script_xref(name:"CERT", value:"958563");

  script_name(english:"SSH Server CBC Mode Ciphers Enabled");
  script_summary(english:"SSH server has been configured with support for CBC cipher mode");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server is configured to use Cipher Block Chaining.");
  script_set_attribute(attribute:"description", value:
"The SSH server is configured to support Cipher Block Chaining (CBC)
encryption.  This may allow an attacker to recover the plaintext message
from the ciphertext. 

Note that this plugin only checks for the options of the SSH server and
does not check for vulnerable software versions.");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor or consult product documentation to disable CBC mode
cipher encryption, and enable CTR or GCM cipher mode encryption.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-5161");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ssh:ssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_supported_algorithms.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

function get_cbcs(port, type)
{
  local_var alg, algs, cbcs;

  cbcs = make_list();

  algs = get_kb_list("SSH/" + port + "/encryption_algorithms_" + type);
  if (isnull(algs))
    return cbcs;

  algs = make_list(algs);
  if (max_index(algs) == 0)
    return cbcs;

  foreach alg (algs)
  {
    if ("-cbc" >< alg)
      cbcs = make_list(cbcs, alg);
  }

  return cbcs;
}

var port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

var algs_c2s = sort(get_cbcs(port:port, type:"client_to_server"));
var algs_s2c = sort(get_cbcs(port:port, type:"server_to_client"));
if (max_index(algs_c2s) == 0 && max_index(algs_s2c) == 0)
  audit(AUDIT_NOT_DETECT, "SSH with encryption in CBC mode", port);

var report = NULL;

if (max_index(algs_c2s) != 0)
{
  report +=
    '\nThe following client-to-server Cipher Block Chaining (CBC) algorithms' +
    '\nare supported : ' +
    '\n' +
    '\n  ' + join(sort(algs_c2s), sep:'\n  ') +
    '\n';
}

if (max_index(algs_s2c) != 0)
{
  report +=
    '\nThe following server-to-client Cipher Block Chaining (CBC) algorithms' +
    '\nare supported : ' +
    '\n' +
    '\n  ' + join(sort(algs_s2c), sep:'\n  ') +
    '\n';
}

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
