#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128116);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2019-1547",
    "CVE-2019-1549",
    "CVE-2019-1552",
    "CVE-2019-1563"
  );
  script_xref(name:"IAVA", value:"2019-A-0303-S");

  script_name(english:"OpenSSL 1.1.1 < 1.1.1d Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.1d. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.1.1d advisory.

  - In situations where an attacker receives automated notification of the success or failure of a decryption
    attempt an attacker, after sending a very large number of messages to be decrypted, can recover a
    CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the
    public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a
    certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the
    correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL
    1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s). (CVE-2019-1563)

  - OpenSSL 1.1.1 introduced a rewritten random number generator (RNG). This was intended to include
    protection in the event of a fork() system call in order to ensure that the parent and child processes did
    not share the same RNG state. However this protection was not being used in the default case. A partial
    mitigation for this issue is that the output from a high precision timer is mixed into the RNG state so
    the likelihood of a parent and child process sharing state is significantly reduced. If an application
    already calls OPENSSL_init_crypto() explicitly using OPENSSL_INIT_ATFORK then this problem does not occur
    at all. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). (CVE-2019-1549)

  - Normally in OpenSSL EC groups always have a co-factor present and this is used in side channel resistant
    code paths. However, in some cases, it is possible to construct a group using explicit parameters (instead
    of using a named curve). In those cases it is possible that such a group does not have the cofactor
    present. This can occur even where all the parameters match a known named curve. If such a curve is used
    then OpenSSL falls back to non-side channel resistant code paths which may result in full key recovery
    during an ECDSA signature operation. In order to be vulnerable an attacker would have to have the ability
    to time the creation of a large number of signatures where explicit parameters with no co-factor present
    are in use by an application using libcrypto. For the avoidance of doubt libssl is not vulnerable because
    explicit parameters are never used. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL
    1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s). (CVE-2019-1547)

  - OpenSSL has internal defaults for a directory tree where it can find a configuration file as well as
    certificates used for verification in TLS. This directory is most commonly referred to as OPENSSLDIR, and
    is configurable with the --prefix / --openssldir configuration options. For OpenSSL versions 1.1.0 and
    1.1.1, the mingw configuration targets assume that resulting programs and libraries are installed in a
    Unix-like environment and the default prefix for program installation as well as for OPENSSLDIR should be
    '/usr/local'. However, mingw programs are Windows programs, and as such, find themselves looking at sub-
    directories of 'C:/usr/local', which may be world writable, which enables untrusted users to modify
    OpenSSL's default configuration, insert CA certificates, modify (or even replace) existing engine modules,
    etc. For OpenSSL 1.0.2, '/usr/local/ssl' is used as default for OPENSSLDIR on all Unix and Windows
    targets, including Visual C builds. However, some build instructions for the diverse Windows targets on
    1.0.2 encourage you to specify your own --prefix. OpenSSL versions 1.1.1, 1.1.0 and 1.0.2 are affected by
    this issue. Due to the limited scope of affected deployments this has been assessed as low severity and
    therefore we are not creating new releases at this time. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c).
    Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).
    (CVE-2019-1552)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1b0fe00e2704b5e20334a16d3c9099d1ba2ef1be
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a8e1f29");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=54aa9d51b09d67e90db443f682cface795f5af9e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7572df8d");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=08229ad838c50f644d7e928e2eef147b4308ad64
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b878099f");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=30c22fa8b1d840036b8e203585738df62a03cec8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6f7882a");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2019-1547");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2019-1549");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2019-1552");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2019-1563");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20190910.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20190730.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.1d or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1549");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.1.1', 'fixed_version' : '1.1.1d' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
