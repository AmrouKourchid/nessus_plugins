#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(45039);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2009-1377",
    "CVE-2009-1378",
    "CVE-2009-1379",
    "CVE-2009-1387",
    "CVE-2009-3245",
    "CVE-2009-3555",
    "CVE-2009-4355"
  );
  script_bugtraq_id(31692, 36935, 38562);
  script_xref(name:"Secunia", value:"37291");
  script_xref(name:"Secunia", value:"38200");

  script_name(english:"OpenSSL 0.9.8 < 0.9.8m Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 0.9.8m. It is, therefore, affected by multiple
vulnerabilities as referenced in the 0.9.8m advisory.

  - OpenSSL before 0.9.8m does not check for a NULL return value from bn_wexpand function calls in (1)
    crypto/bn/bn_div.c, (2) crypto/bn/bn_gf2m.c, (3) crypto/ec/ec2_smpl.c, and (4) engines/e_ubsec.c, which
    has unspecified impact and context-dependent attack vectors. (CVE-2009-3245)

  - Memory leak in the zlib_stateful_finish function in crypto/comp/c_zlib.c in OpenSSL 0.9.8l and earlier and
    1.0.0 Beta through Beta 4 allows remote attackers to cause a denial of service (memory consumption) via
    vectors that trigger incorrect calls to the CRYPTO_cleanup_all_ex_data function, as demonstrated by use of
    SSLv3 and PHP with the Apache HTTP Server, a related issue to CVE-2008-1678. (CVE-2009-4355)

  - The TLS protocol, and the SSL protocol 3.0 and possibly earlier, as used in Microsoft Internet Information
    Services (IIS) 7.0, mod_ssl in the Apache HTTP Server 2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS
    2.8.5 and earlier, Mozilla Network Security Services (NSS) 3.12.4 and earlier, multiple Cisco products,
    and other products, does not properly associate renegotiation handshakes with an existing connection,
    which allows man-in-the-middle attackers to insert data into HTTPS sessions, and possibly other types of
    sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by
    a server in a post-renegotiation context, related to a plaintext injection attack, aka the Project
    Mogul issue. (CVE-2009-3555)

  - Use-after-free vulnerability in the dtls1_retrieve_buffered_fragment function in ssl/d1_both.c in OpenSSL
    1.0.0 Beta 2 allows remote attackers to cause a denial of service (openssl s_client crash) and possibly
    have unspecified other impact via a DTLS packet, as demonstrated by a packet from a server that uses a
    crafted server certificate. (CVE-2009-1379)

  - Multiple memory leaks in the dtls1_process_out_of_seq_message function in ssl/d1_both.c in OpenSSL 0.9.8k
    and earlier 0.9.8 versions allow remote attackers to cause a denial of service (memory consumption) via
    DTLS records that (1) are duplicates or (2) have sequence numbers much greater than current sequence
    numbers, aka DTLS fragment handling memory leak. (CVE-2009-1378)

  - The dtls1_buffer_record function in ssl/d1_pkt.c in OpenSSL 0.9.8k and earlier 0.9.8 versions allows
    remote attackers to cause a denial of service (memory consumption) via a large series of future epoch
    DTLS records that are buffered in a queue, aka DTLS record buffer limitation bug. (CVE-2009-1377)

  - The dtls1_retrieve_buffered_fragment function in ssl/d1_both.c in OpenSSL before 1.0.0 Beta 2 allows
    remote attackers to cause a denial of service (NULL pointer dereference and daemon crash) via an out-of-
    sequence DTLS handshake message, related to a fragment bug. (CVE-2009-1387)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=561cbe567846a376153bea7f1f2d061e78029c2d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b059be1");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=abda7c114791fa7fe95672ec7a66fc4733c40dbc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c9c6054");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=7e4cae1d2f555cbe9226b377aff4b56c9f7ddd4d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66b78730");
  # https://web.archive.org/web/20100824233642/http://rt.openssl.org/Ticket/Display.html?id=1923&user=guest&pass=guest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8017a0da");
  # https://web.archive.org/web/20120306065500/http://rt.openssl.org/Ticket/Display.html?id=1930&user=guest&pass=guest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81086b9d");
  # https://web.archive.org/web/20100710092848/https://rt.openssl.org/Ticket/Display.html?id=1838
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1dd7a8e");
  # https://web.archive.org/web/20101120211136/http://rt.openssl.org/Ticket/Display.html?id=1931&user=guest&pass=guest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be95a7f1");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1b31b5ad560b16e2fe1cad54a755e3e6b5e778a3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c95727f2");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=88b48dc68024dcc437da4296c9fb04419b0ccbe1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f79b6f49");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2009-1377");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2009-1378");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2009-1379");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2009-1387");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2009-3245");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2009-3555");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2009-4355");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20091111.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 0.9.8m or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3245");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2009-3555");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("openssl_nix_installed.nbin", "openssl_version.nasl", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '0.9.8', 'fixed_version' : '0.9.8m' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
