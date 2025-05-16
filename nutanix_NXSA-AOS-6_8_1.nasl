#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202829);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-1999-0524",
    "CVE-2021-4160",
    "CVE-2022-31692",
    "CVE-2022-48624",
    "CVE-2023-4408",
    "CVE-2023-28322",
    "CVE-2023-38545",
    "CVE-2023-38546",
    "CVE-2023-46218",
    "CVE-2023-50387",
    "CVE-2023-50868",
    "CVE-2023-52425",
    "CVE-2024-1753",
    "CVE-2024-2961",
    "CVE-2024-21011",
    "CVE-2024-21012",
    "CVE-2024-21068",
    "CVE-2024-21085",
    "CVE-2024-21094",
    "CVE-2024-28834"
  );
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.8.1)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.8.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.8.1 advisory.

  - There is a carry propagation bug in the MIPS32 and MIPS64 squaring procedure. Many EC algorithms are
    affected, including some of the TLS 1.3 default curves. Impact was not analyzed in detail, because the
    pre-requisites for attack are considered unlikely and include reusing private keys. Analysis suggests that
    attacks against RSA and DSA as a result of this defect would be very difficult to perform and are not
    believed likely. Attacks against DH are considered just feasible (although very difficult) because most of
    the work necessary to deduce information about a private key may be performed offline. The amount of
    resources required for such an attack would be significant. However, for an attack on TLS to be
    meaningful, the server would have to share the DH private key among multiple clients, which is no longer
    an option since CVE-2016-0701. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0.0. It was
    addressed in the releases of 1.1.1m and 3.0.1 on the 15th of December 2021. For the 1.0.2 release it is
    addressed in git commit 6fc1aaaf3 that is available to premium support customers only. It will be made
    available in 1.0.2zc when it is released. The issue only affects OpenSSL on MIPS platforms. Fixed in
    OpenSSL 3.0.1 (Affected 3.0.0). Fixed in OpenSSL 1.1.1m (Affected 1.1.1-1.1.1l). Fixed in OpenSSL 1.0.2zc-
    dev (Affected 1.0.2-1.0.2zb). (CVE-2021-4160)

  - CVE-2023-38545 is a heap-based buffer overflow vulnerability in the SOCKS5 proxy handshake in libcurl and
    curl.  When curl is given a hostname to pass along to a SOCKS5 proxy that is greater than 255 bytes in
    length, it will switch to local name resolution in order to resolve the address before passing it on to
    the SOCKS5 proxy. However, due to a bug introduced in 2020, this local name resolution could fail due to a
    slow SOCKS5 handshake, causing curl to pass on the hostname greater than 255 bytes in length into the
    target buffer, leading to a heap overflow.  The advisory for CVE-2023-38545 gives an example exploitation
    scenario of a malicious HTTPS server redirecting to a specially crafted URL. While it might seem that an
    attacker would need to influence the slowness of the SOCKS5 handshake, the advisory states that server
    latency is likely slow enough to trigger this bug. (CVE-2023-38545)

  - This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake. When curl is asked to
    pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting
    done by curl itself, the maximum length that host name can be is 255 bytes. If the host name is detected
    to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due
    to this bug, the local variable that means let the host resolve the name could get the wrong value
    during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target
    buffer instead of copying just the resolved address there. The target buffer being a heap based buffer,
    and the host name coming from the URL that curl has been told to operate with. (CVE-2023-38545)

  - An information disclosure vulnerability exists in curl <v8.1.0 when doing HTTP(S) transfers, libcurl might
    erroneously use the read callback (`CURLOPT_READFUNCTION`) to ask for data to send, even when the
    `CURLOPT_POSTFIELDS` option has been set, if the same handle previously wasused to issue a `PUT` request
    which used that callback. This flaw may surprise the application and cause it to misbehave and either send
    off the wrong data or use memory after free or similar in the second transfer. The problem exists in the
    logic for a reused handle when it is (expected to be) changed from a PUT to a POST. (CVE-2023-28322)

  - This flaw allows an attacker to insert cookies at will into a running program using libcurl, if the
    specific series of conditions are met. libcurl performs transfers. In its API, an application creates
    easy handles that are the individual handles for single transfers. libcurl provides a function call that
    duplicates en easy handle called
    [curl_easy_duphandle](https://curl.se/libcurl/c/curl_easy_duphandle.html). If a transfer has cookies
    enabled when the handle is duplicated, the cookie-enable state is also cloned - but without cloning the
    actual cookies. If the source handle did not read any cookies from a specific file on disk, the cloned
    version of the handle would instead store the file name as `none` (using the four ASCII letters, no
    quotes). Subsequent use of the cloned handle that does not explicitly set a source to load cookies from
    would then inadvertently load cookies from a file named `none` - if such a file exists and is readable in
    the current directory of the program using libcurl. And if using the correct file format of course.
    (CVE-2023-38546)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.8.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3be2d0ae");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4160");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38545");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-1999-0524");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1997/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '6.8.1', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.8.1 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.8.1', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.8.1 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
