#TRUSTED 644b6f2e8fb4781e8fe468cd73cac735d2fc8a63aaba21edac87773a4b1c25912de3ce6ceb3351437f2af40d77ca36031dc6e25e032cb54a0a973c297eaf742903f903c9346bfe72505d4344d3c862f6895ee176a55f6f24aa57fb763106899f2d7e3c5b07c6cbd6a028d63b0b76f4708a543f9842428ff707b2621d12bd5afd6d8207d10016112f0b00632fc15cf1be03a309ac39239c554623ab3e1548d33f075b189b33ee246d9ddac9340aac1b233ef27899f4ce3fa869597c67fe3a1cf0f42de4e8d4ec36f19b73bdca457eb7c14c0b3037880c870cf48a46b47300223700aaf217fc964921f0c2e564d066b5328fc3784ff1c07fe7f01e758c76e5827851569842ef483d62af7641a9432ce31f267a34e6ab188840f09cfa3269994a3de470747710fede05c3d7330ad7d8ce2ce1a6326c52e7931ec1ff19df81af2d5b95b3cd5109f3fad9f3d17cbf351aa140e1dea3c0f01b6aa7d287a52ff3a0494aaca28a0736afb3e9a413c2ad5734b5224a05aef811df355d564dc3236634c9872e75269a13cf7dd05a1de8c6379cbb3e25ba764c170f8e8d57aa24d0f854cc54c65434a34cbfda1ea505b70fb26e647b2dbbd145bad2aa3dca492de1457cc8df98dcbe199a0326a5aa741927a8722606b717b68b29dd387eabc078ea85ccae129b09bcf1a48846a7509b6e4ca2eb340bc98342b3166fa55450119e9a20eb1b00
#TRUST-RSA-SHA256 5b97f9c3c8e7aa918d48b371a554e49bb8a32a6b72e7d32c979689bb61f18688c72befe286a17cab394a9578b5d94b15de861cbdb34eaa76d4caa2a1d4a7af3d46858abcd0493c25b51a90a3686c6da0092ca44bacf5a52e5724b31342687537740d691b08a8de803fe64578da705f9720d7ff726a7043fcccca677d3a0e3d5cbadf5367e30a39a4102d10054a64e8046b3078b26611012bf802265389c6b338941d9602fec60e4d8e1d33712efc987dbe93546951f3d3a2daf06b19d629a29115ef48aabc74b47452bd2c7d557eea0d65f39130c7b671dc920d5a8e0a432f8ea387235dd9651323cf0fb86499e6f57f6cfd1b395e5129a933402b085a3c7890276fa9423f9f6e0b5ec75f055b087fee6fe05d4bde45da71f24c0aea3d599d234c5b73786ac4876adee66f7e3fa436e0ce06b39f821715bb8f1412670fdced4fb8069856f0342745a5140ea7246e5a5c3acbf0c604978ad25ef5c34195d319573bb3229f034855b8673cebe6b038d1d643dec18ca7cce21aa8efaef2abdaa82d9c668e0dc7f687348ead101842b10dcad3d5db750f504a689ee585781a647b74915d7ba4c380d71812ff3306c99af1998e5f24939ec83762a4a89109415ec783996d0128d2a1bc79ca70fa9ad39c825aff0efadd87cecbb81b368c11e476e728b5e5a02c036254233cc47e821273a3f6f4bef2dbb7b647e2629d510f47a01520
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153954);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/16");

  script_name(english:"SSH Host Keys < 2048 Bits Considered Weak");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host has public key that is considered weak.");
  script_set_attribute(attribute:"description", value:
"Brute force setting must be enabled to use this plugin.

The remote SSH server has a host key size that is smaller than 2048 bits. NIST Special Publication 800-57 Part 3
Recommendation for Key Management recommends RSA keys greater or equal to 2048 bits in length.");
  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8c76607");
  script_set_attribute(attribute:"solution", value:
"Generate a new, larger SSH host key.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for weak host key");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include('ssh_func.inc');

# used as a flag in the SSH libs
checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

var soc = open_sock_tcp(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port);

var _ssh_socket = soc;

# Tell the server we support only RSA host keys, to ensure we get sent one.
sshlib::KEX_SUPPORTED_NAME_LISTS.server_host_key_algorithms = 'ssh-rsa';

ssh_login(login:'n3ssus', password:rand_str(length:8));
ssh_close_connection();

# KEY_LEN will be null if the SSH server does not support ssh-rsa
if (empty_or_null(KEY_LEN))
  audit(AUDIT_LISTEN_NOT_VULN, 'SSH server', port);

var report = 'The remote SSH server host key size is ' + KEY_LEN + ' bits.';

# audit out if we are not affected
if (KEY_LEN == 0 || KEY_LEN >= 2048)
  exit(0, report);

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
