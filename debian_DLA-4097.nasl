#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4097. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(233548);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/30");

  script_cve_id(
    "CVE-2021-3872",
    "CVE-2021-4019",
    "CVE-2021-4173",
    "CVE-2021-4187",
    "CVE-2022-0261",
    "CVE-2022-0351",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0392",
    "CVE-2022-0417",
    "CVE-2022-0572",
    "CVE-2022-1616",
    "CVE-2022-1785",
    "CVE-2022-1897",
    "CVE-2022-1942",
    "CVE-2022-2000",
    "CVE-2022-2129",
    "CVE-2022-2304",
    "CVE-2022-3099",
    "CVE-2022-3134",
    "CVE-2022-3324",
    "CVE-2022-4141",
    "CVE-2023-0054",
    "CVE-2023-1175",
    "CVE-2023-2610",
    "CVE-2023-4738",
    "CVE-2023-4752",
    "CVE-2023-4781",
    "CVE-2023-5344",
    "CVE-2024-22667",
    "CVE-2024-43802",
    "CVE-2024-47814"
  );
  script_xref(name:"IAVA", value:"2024-A-0526-S");
  script_xref(name:"IAVA", value:"2024-A-0618-S");
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"IAVB", value:"2022-B-0058-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");
  script_xref(name:"IAVB", value:"2023-B-0018-S");
  script_xref(name:"IAVB", value:"2023-B-0033-S");
  script_xref(name:"IAVB", value:"2023-B-0066-S");
  script_xref(name:"IAVB", value:"2023-B-0074-S");

  script_name(english:"Debian dla-4097 : vim - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4097 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4097-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Sean Whitton
    March 30, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : vim
    Version        : 2:8.2.2434-3+deb11u3
    CVE ID         : CVE-2021-3872 CVE-2021-4019 CVE-2021-4173 CVE-2021-4187
                     CVE-2022-0261 CVE-2022-0351 CVE-2022-0359 CVE-2022-0361
                     CVE-2022-0392 CVE-2022-0417 CVE-2022-0572 CVE-2022-1616
                     CVE-2022-1785 CVE-2022-1897 CVE-2022-1942 CVE-2022-2000
                     CVE-2022-2129 CVE-2022-2304 CVE-2022-3099 CVE-2022-3134
                     CVE-2022-3324 CVE-2022-4141 CVE-2023-0054 CVE-2023-1175
                     CVE-2023-2610 CVE-2023-4738 CVE-2023-4752 CVE-2023-4781
                     CVE-2023-5344 CVE-2024-22667 CVE-2024-43802 CVE-2024-47814
    Debian Bug     : 1015984 1019590 1027146 1031875 1035955 1053694 1084806

    Multiple vulnerabilities were discovered in vim, an enhanced vi editor.

    CVE-2021-3872

        Heap-based buffer overflow possible if the buffer name is very long.

    CVE-2021-4019

        Heap-based buffer overflow possible with a very long help argument.

    CVE-2021-4173

        Double free in the VimScript9 compiler with a nested :def function.

    CVE-2021-4187

        Double free in the VimScript9 compiler if a nested function has a
        line break in its argument list.

    CVE-2022-0261

        Buffer overflow in block insert, which goes over the end of the line.

    CVE-2022-0351

        In a command, a condition with many parentheses can cause a crash,
        because there was previously no recursion limit.

    CVE-2022-0359

        A heap-based buffer overflow could occur with a large tabstop in Ex
        mode.

    CVE-2022-0361

        A buffer overflow was found in the code copying lines in Visual
        mode.

    CVE-2022-0392

        A heap-based buffer overflow was found in the code handling
        bracketed paste in ex mode.

    CVE-2022-0417

        The :retab 0 command may cause a buffer overflow because a limit
        was set too high.

    CVE-2022-0572

        Repeatedly using the :retab command may have caused a crash.

    CVE-2022-1616

        There is a possbile buffer overflow when processing an invalid
        command with composing characters.

    CVE-2022-1785

        It was possible to change the window in a substitute expression,
        which could lead to an out-of-bounds write.

    CVE-2022-1897

        It was possible to use the undo command in a substitute expression,
        leading to an invalid memory overwrite.

    CVE-2022-1942

        It was possible to open a command line window from a substitute
        expression, leading to a heap-based buffer overflow.

    CVE-2022-2000

        Command error messages were not truncated, and as such could lead to
        out-of-bounds writes.

    CVE-2022-2129

        It was possible to switch buffers in a substitute expression,
        leading to a heap-based buffer overflow.

    CVE-2022-2304

        Long words might cause a buffer overflow in the spellchecker.

    CVE-2022-3099

        Line numbers in :for commands were not validated, which could lead
        to a crash.

    CVE-2022-3134

        If a relevant window was unexpectedly closed while searching for
        tags, vim would crash.

    CVE-2022-3324

        Negative window widths caused the use of a negative array index,
        that is, an invalid read.

    CVE-2022-4141

        Functions that visit another file during a substitution could cause
        a heap-based buffer overflow.

    CVE-2023-0054

        A recursive substitute expression could cause an out-of-bounds write.

    CVE-2023-1175

        When doing virtual editing, a buffer size calculation was wrong.

    CVE-2023-2610

        When expanding ~ in a substitution, if the resulting expansion was
        very long, vim would crash.

    CVE-2023-4738

        A buffer overflow problem was found in vim_regsub_both().

    CVE-2023-4752

        A use-after-free problem was found in ins_compl_get_exp().

    CVE-2023-4781

        A second buffer overflow problem was found in vim_regsub_both().

    CVE-2023-5344

        trunc_string() made an incorrect assumption about when a certain
        buffer would be writeable.

    CVE-2024-22667

        Several calls writing error messages did not check that there was
        enough space for the full message.

    CVE-2024-43802

        The typeahead buffer end pointer could be moved past its end when
        flushing that buffer, leading to an out-of-bounds read.

    CVE-2024-47814

        When splitting the window and editing a new buffer, the new buffer
        could be marked for deletion, leading to a use-after-free.

    For Debian 11 bullseye, these problems have been fixed in version
    2:8.2.2434-3+deb11u3.

    We recommend that you upgrade your vim packages.

    For the detailed security status of vim please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/vim

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/vim");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3872");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4173");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4187");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0261");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0351");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0359");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0361");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0392");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0417");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0572");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1942");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2000");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2129");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2304");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3134");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3324");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0054");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1175");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2610");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4738");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5344");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22667");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47814");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/vim");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2304");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-22667");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xxd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'vim', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-athena', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-common', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-doc', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-gtk', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-gtk3', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-gui-common', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-nox', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-runtime', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'vim-tiny', 'reference': '2:8.2.2434-3+deb11u3'},
    {'release': '11.0', 'prefix': 'xxd', 'reference': '2:8.2.2434-3+deb11u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-common / vim-doc / vim-gtk / vim-gtk3 / etc');
}
