##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:5997. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163972);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2022-0670");
  script_xref(name:"RHSA", value:"2022:5997");

  script_name(english:"RHEL 8 / 9 : Red Hat Ceph Storage Security, Bug Fix, and Enhancement Update (Moderate) (RHSA-2022:5997)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by a vulnerability as referenced
in the RHSA-2022:5997 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform that combines the most stable
    version of the Ceph storage system with a Ceph management platform, deployment utilities, and support
    services.

    The ceph-ansible package provides Ansible playbooks for installing, maintaining, and upgrading Red Hat
    Ceph Storage.

    Perf Tools is a collection of performance analysis tools, including a high-performance multi-threaded
    malloc() implementation that works particularly well with threads and STL, a thread-friendly heap-checker,
    a heap profiler, and a cpu-profiler.

    The libunwind packages contain a C API to determine the call chain of a program. This API is necessary for
    compatibility with Google Performance Tools (gperftools).

    nfs-ganesha : NFS-GANESHA is a NFS Server running in user space. It comes with various back-end modules
    (called FSALs) provided as shared objects to support different file systems and name-spaces.

    The following packages have been upgraded to a later upstream version: ceph (16.2.8), ceph-ansible
    (6.0.27.9), cephadm-ansible (1.8.0), gperftools (2.9.1), leveldb (1.23), libunwind (1.5.0), nfs-ganesha
    (3.5), oath-toolkit (2.6.7). (BZ#1623330, BZ#1942171, BZ#1977888, BZ#1997480, BZ#1997996, BZ#2006214,
    BZ#2006771, BZ#2013215, BZ#2018906, BZ#2024720, BZ#2028628, BZ#2029307, BZ#2030540, BZ#2039669,
    BZ#2041563, BZ#2041571, BZ#2042417, BZ#2042602, BZ#2043602, BZ#2047487, BZ#2048681, BZ#2049272,
    BZ#2053468, BZ#2053591, BZ#2055173, BZ#2057307, BZ#2060278, BZ#2064627, BZ#2077843, BZ#2080242)

    Security Fix(es):

    * ceph: user/tenant can obtain access (read/write) to any share (CVE-2022-0670)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    This update also fixes several bugs and adds various enhancements. Documentation for these changes is
    available from the Release Notes document linked to in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_5997.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60c1af05");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1623330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1889976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1910419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1910503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1938670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1939716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1942171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1962511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1962575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1967901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1971694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1972506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1976128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1977888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1982962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1988773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1996667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1997480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1997996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1999710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2003925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2004171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2005960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2008402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2009118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2013085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2013215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2015597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2016936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2017389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2018906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2019909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2024301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2024720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2027599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2028036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2028628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2028693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2028879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2029307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2030154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2030540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2031173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2034060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2034309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2035179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2035331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2037752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2039669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2039741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2039816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2042320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2042417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2042602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2043366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2043602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2047487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2048681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2049272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2051640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2052936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2053468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2053470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2053591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2053706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2053709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2054967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2055173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2057307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2058038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2058372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2058669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2060278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2061501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2064171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2064627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2065443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2067987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2068039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2069720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2071458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2073209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2073881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2074105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2076850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2077827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2077843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2079089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2080242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2080276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2083885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2086419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2086438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2087236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2087736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2087986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2088602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2088654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2090357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2090421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2090456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2093017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2093022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2093031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2093065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2093788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2094112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2094416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2096882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2096959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2098105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2099348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2099374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2099828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2099992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2100503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2100915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2100967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2102227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2102365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2103673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2103686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2104780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2105454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2105881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2108656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2109151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2109703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2110913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2112101");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(863);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-grafana-dashboards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-diskprediction-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-prometheus-alerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephfs-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephfs-top");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephsqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-nbd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/rhceph-mon/5/debug',
      'content/dist/layered/rhel8/ppc64le/rhceph-mon/5/os',
      'content/dist/layered/rhel8/ppc64le/rhceph-mon/5/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhceph-osd/5/debug',
      'content/dist/layered/rhel8/ppc64le/rhceph-osd/5/os',
      'content/dist/layered/rhel8/ppc64le/rhceph-osd/5/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/5/debug',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/5/os',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/5/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhceph-mon/5/debug',
      'content/dist/layered/rhel8/s390x/rhceph-mon/5/os',
      'content/dist/layered/rhel8/s390x/rhceph-mon/5/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhceph-osd/5/debug',
      'content/dist/layered/rhel8/s390x/rhceph-osd/5/os',
      'content/dist/layered/rhel8/s390x/rhceph-osd/5/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhceph-tools/5/debug',
      'content/dist/layered/rhel8/s390x/rhceph-tools/5/os',
      'content/dist/layered/rhel8/s390x/rhceph-tools/5/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhceph-mon/5/debug',
      'content/dist/layered/rhel8/x86_64/rhceph-mon/5/os',
      'content/dist/layered/rhel8/x86_64/rhceph-mon/5/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhceph-osd/5/debug',
      'content/dist/layered/rhel8/x86_64/rhceph-osd/5/os',
      'content/dist/layered/rhel8/x86_64/rhceph-osd/5/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/5/debug',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/5/os',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-base-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-grafana-dashboards-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-cephadm-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-dashboard-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-diskprediction-local-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-k8sevents-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-modules-core-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-rook-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mib-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-prometheus-alerts-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-resource-agents-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-resource-agents-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-resource-agents-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephadm-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephfs-mirror-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephfs-mirror-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephfs-mirror-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephfs-top-16.2.8-84.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephsqlite-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephsqlite-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephsqlite-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-16.2.8-84.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-16.2.8-84.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-16.2.8-84.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/ppc64le/rhceph-mon/5/debug',
      'content/dist/layered/rhel9/ppc64le/rhceph-mon/5/os',
      'content/dist/layered/rhel9/ppc64le/rhceph-mon/5/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/rhceph-osd/5/debug',
      'content/dist/layered/rhel9/ppc64le/rhceph-osd/5/os',
      'content/dist/layered/rhel9/ppc64le/rhceph-osd/5/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/5/debug',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/5/os',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/5/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhceph-mon/5/debug',
      'content/dist/layered/rhel9/s390x/rhceph-mon/5/os',
      'content/dist/layered/rhel9/s390x/rhceph-mon/5/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhceph-osd/5/debug',
      'content/dist/layered/rhel9/s390x/rhceph-osd/5/os',
      'content/dist/layered/rhel9/s390x/rhceph-osd/5/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhceph-tools/5/debug',
      'content/dist/layered/rhel9/s390x/rhceph-tools/5/os',
      'content/dist/layered/rhel9/s390x/rhceph-tools/5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhceph-mon/5/debug',
      'content/dist/layered/rhel9/x86_64/rhceph-mon/5/os',
      'content/dist/layered/rhel9/x86_64/rhceph-mon/5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhceph-osd/5/debug',
      'content/dist/layered/rhel9/x86_64/rhceph-osd/5/os',
      'content/dist/layered/rhel9/x86_64/rhceph-osd/5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/5/debug',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/5/os',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-base-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-grafana-dashboards-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-cephadm-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-dashboard-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-diskprediction-local-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-k8sevents-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-modules-core-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-rook-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mib-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-prometheus-alerts-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-resource-agents-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-resource-agents-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-resource-agents-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephadm-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephfs-top-16.2.8-84.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephsqlite-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephsqlite-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephsqlite-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-16.2.8-84.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-16.2.8-84.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-16.2.8-84.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph-base / ceph-common / ceph-fuse / ceph-grafana-dashboards / etc');
}
