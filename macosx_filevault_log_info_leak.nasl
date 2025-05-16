#TRUSTED 3371d2cbad859590b5cfa51a9ccaa9d91694664f625ba851b5853f95fe9a87adbf9f782729b68d2cda4f8356aee80f048e0f7afb1e251597eb97b5193bf6d8f76772eb9953e2f5fc8fee09f3c6633ddc923d47bb6e1c38292c4c069b26e1ffb7a869febfe8137b9bc7fe499c9dc97d2d1c89d81f665f16e1ef88a546e56935157386e3abaf003a3eacccf667840e5e7cb29f9f54291440eacf5683cc768fdef83a27f69f184fd17a1fd8ea2cfb2ab6d50123037e33c1a28eb71b0c25a940c158dcf1d733e57a186c3af4d79749de0bcd5d7a562a0e24fb23d35f687597e22a6874d09ce832c4abb1215f3b6777829c05926987951588885512e3be062f18af2c5a8231e69c81dbcc3a520c4982730b4108be3c18d2d47608fb05797017e11b459210de9df173ef649b817e4a34cf9c6a68dcb1508c72e65658f2cb6cd3cff29146ee6876d91459c4808da09d7429f81c85f3e3ac77e30d02eeaa09d4dc00abb4740d7157f41ab50b541ecac2297664ed6ef3e09ea44d19bb05d9ffe3eb65d18ea317921d7632a41f333e60e94619587e75bb75e3048c5910245cfcf530257275f43ad7bf3d44b8aef61f5870a8a2ff7dd7a507fcadf92b0f44ef6eb8f2dd6401cae73090ce070a5a5d70e27eafc460a5403a2b4ddf022f896285f870adcb0ac143c766a36f462dbda927a4349600844d7ddfd0615af2172162b38fe10d3a2257
#TRUST-RSA-SHA256 5ef642b69984a6bca105ea094aabc6ba34432df36643e6be5a18b2ccc0eae1744183d0ea0a5d607d1072ea4378ad12fc7877764004c8b191ece894506dfcf0221a689f685296e1c294dc81f02b0ebb30db64c86503a1e87062b92aab3080700ab36dc5de0f134b93cc97fd9302d91c9653a28b7bfbf52d18a77b1acb3ed0209b7bb0f05ef35f225f08a723a99213a2bf36276c089d734fd625021fd3ec7e3eeb979468d6f6b609b1fe2823f3f797803bb2a4c9f1b5ce7c4d176842451aff4515fb764c73f13e6ddc5682cedebab938b9b520be8cabf9a8cfcf75759c8028f410a465a3ba1b6c9a862da032424e4c8ce27bd36aff4879cd62bb0e31a9ebe0224d0a2125defd3109058d33c0c509e9941c566f019eff90b67024e88313a47354d314b34f8b9ca867fb0dc734ef9d36b311cb9a18f190a07f2c5e4c01fbc9182ca20792fb115dd0579c279556b2091187311ce156fd0948eff2326c5e4b11a2b53ea7042f5fabb034d82ec5170e7631d573e75c007ed2a8d3ec3b9de3d3294f38a12fbd1e697f2896cf94334dd12c34f6fd55b41a025423ea5c04b341ebeef9340a50c1dd28bf0c62d70affd52e2907e2001a5ef9298c72dae7c1ab98dc462f57165388abf6922b6ad4ce25fd75dc5268ec71be6f0dd2b5be5e82747fb3f3e6692dc10868b5f8b8e551edd5ce855e81c8eed97cdcb4bf7905cf864e96d2ffca8e24
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(59090);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2012-0652");
  script_bugtraq_id(53402);

  script_name(english:"Mac OS X FileVault Plaintext Password Logging");
  script_summary(english:"Checks secure.log files for plaintext passwords");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host logs passwords in plaintext."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Plaintext passwords were discovered in a system log file.  Mac OS X
Lion release 10.7.3 enabled a debug logging feature that causes
plaintext passwords to be logged to /var/log/secure.log on systems
that use certain FileVault configurations.  A local attacker in the
admin group or an attacker with physical access to the host could
exploit this to get user passwords, which could be used to gain access
to encrypted partitions."
  );
  script_set_attribute(attribute:"see_also",value:"https://discussions.apple.com/thread/3715366");
  script_set_attribute(attribute:"see_also",value:"https://discussions.apple.com/thread/3872437");
  script_set_attribute(attribute:"see_also",value:"http://cryptome.org/2012/05/apple-filevault-hole.htm");
  script_set_attribute(attribute:"see_also",value:"http://support.apple.com/kb/HT5281");
  script_set_attribute(attribute:"see_also",value:"http://support.apple.com/kb/TS4272");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Mac OS X 10.7.4 or later and securely remove log files
that contain plaintext passwords (refer to article TS4272)."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/02/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");


enable_ssh_wrappers();

get_kb_item_or_exit("Host/local_checks_enabled");
ver = get_kb_item_or_exit("Host/MacOSX/Version");

match = eregmatch(string:ver, pattern:'([0-9.]+)');
ver = match[1];

# the vulnerability was introduced in 10.7.3
if (ver_compare(ver:ver, fix:'10.7.3', strict:FALSE) < 0)
  audit(AUDIT_HOST_NOT, 'Mac OS X >= 10.7.3');

cmd = "/usr/bin/bzgrep ': DEBUGLOG |.*, password[^ ]* =' /var/log/secure.log* 2> /dev/null";
output = exec_cmd(cmd:cmd);
if (!strlen(output))
  audit(AUDIT_HOST_NOT, 'affected');

credentials = make_array();

foreach line (split(output, sep:'\n', keep:FALSE))
{
  # this might be asking for trouble because it's unclear how the logger handles things like passwords with ', '
  # in them. at worst, all that should happen is the last character of the password will be reported incorrectly
  logdata = strstr(line, ' | about to call ');
  fields = split(logdata, sep:', ', keep:FALSE);
  user = NULL;
  pass = NULL;

  foreach field (fields)
  {
    usermatch = eregmatch(string:field, pattern:'name = (.+)');
    if (isnull(usermatch))
      usermatch = eregmatch(string:field, pattern:'= /Users/([^/]+)');
    if (!isnull(usermatch))
      user = usermatch[1];

    passmatch = eregmatch(string:field, pattern:'password(AsUTF8String)? = (.+)');
    if (!isnull(passmatch))
    {
      pass = passmatch[2];
      pass = pass[0] + '******' + pass[strlen(pass) - 1];
    }
  }

  if (!isnull(user) && !isnull(pass))
    credentials[user] = pass;
}

if (max_index(keys(credentials)) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

report =
  '\nNessus discovered plaintext passwords by running the following command :\n\n' +
  cmd + '\n' +
  '\nThe following usernames and passwords were extracted (note' +
  '\nthat any passwords displayed have been partially obfuscated) :\n';

foreach user (sort(keys(credentials)))
{
  report +=
    '\n  Username : ' + user +
    '\n  Password : ' + credentials[user] + '\n';
}

security_note(port:0, extra:report);

