#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-ce2936b568
#

include('compat.inc');

if (description)
{
  script_id(197952);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");
  script_xref(name:"FEDORA", value:"2024-ce2936b568");

  script_name(english:"Fedora 40 : glycin-loaders / gnome-tour / helix / helvum / libipuz / loupe / etc (2024-ce2936b568)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2024-ce2936b568 advisory.

    This update contains builds from a mini-mass-rebuild for Rust applications (and some C-style libraries).

    Rebuilding with the Rust 1.78 toolchain should fix incomplete debug information for the Rust standard
    library (and the resulting low-quality stack traces). Additionally, builds will have picked up fixes for
    some minor low-priority security and / or safety fixes in crate dependencies that had not yet been handled
    via a separate (targeted) rebuild:

    - h2 v0.3.26+ (denial-of-service): https://rustsec.org/advisories/RUSTSEC-2024-0332.html
    - glib v0.19.4+ and backports (UB): https://github.com/gtk-rs/gtk-rs-core/pull/1343
    - hashbrown v0.14.5+ (UB): https://github.com/rust-lang/hashbrown/pull/511
    - rustls v0.22.4+, v0.21.11+ (denial-of-service): https://rustsec.org/advisories/RUSTSEC-2024-0336.html


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ce2936b568");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glycin-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-tour");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:helix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:helvum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libipuz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:loupe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maturin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ntpd-rs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-afterburn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-alacritty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-asahi-btsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-asahi-nvram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-asahi-wifisync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-askalono-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-b3sum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-bat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-bindgen-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-bitvec_helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-blsctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-bodhi-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-btrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cargo-deny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cargo-insta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cargo-readme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cbindgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-choosier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-clang-tidy-sarif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-clippy-sarif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-comrak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-copydeps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-coreos-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-count-zeroes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-desed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-difftastic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-diskonaut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-docopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-dolby_vision");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-dotenvy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-dua-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-dutree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-elfcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-erdtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-eza");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-fd-find");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-fedora-update-feedback");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gimoji");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-git-delta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gitui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gst-plugin-gif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gst-plugin-gtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gst-plugin-reqwest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-hadolint-sarif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-handlebars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-heatseeker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-hexyl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-hyperfine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-ifcfg-devname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-is_ci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-jql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-kdotool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-krunvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-leb128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-libcramjam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-lino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-local_ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-lscolors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-lsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-mdsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-names");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-navi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-nu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-oxipng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pleaser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-prefixdevname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pretty-bytes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pretty-git-prompt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-procs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pulldown-cmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-python-launcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rav1e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rbspy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rd-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rd-hashd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-resctl-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-resctl-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-ripgrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-routinator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-routinator-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rpick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rpki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rpm-sequoia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rustcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sarif-fmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-scx_rustland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-scx_rusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-chameleon-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-keyring-linter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-octopus-librnp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-policy-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-sqv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-wot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sevctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sha1collisiondetection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-shellcheck-sarif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-silver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-skim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-snphost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-speakersafetyd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-ssh-key-dir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-system76_ectool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-szip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tealdeer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-termbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tiny-dfr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tokei");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tree-sitter-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uefi-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_base32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_base64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_basename");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_basenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_cat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_cksum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_comm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_cp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_csplit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_cut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_date");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_dd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_df");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_dir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_dircolors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_dirname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_du");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_echo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_env");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_expand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_expr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_factor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_false");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_fmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_fold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_hashsum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_head");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_join");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_link");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_ln");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_ls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_mkdir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_mktemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_more");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_mv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_numfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_od");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_paste");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_pr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_printenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_printf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_ptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_pwd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_readlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_realpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_rmdir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_seq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_shred");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_shuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_sleep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_sort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_split");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_sum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_tac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_tail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_tee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_touch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_true");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_truncate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_tsort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_unexpand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_uniq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_unlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_vdir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_wc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_whoami");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-uu_yes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-varlink-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-varlink_generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-vhost-device-scmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-vhost-device-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-weezl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-ybaas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-yubibomb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-zoxide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-zram-generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust2rpm-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rustup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:snapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sudo-rs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:system76-keyboard-configurator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wildcard");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'glycin-loaders-1.0.1-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-tour-46.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'helix-24.03-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'helvum-0.5.1-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipuz-0.4.6.2-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'loupe-46.2-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'maturin-1.5.1-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ntpd-rs-1.1.2-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruff-0.3.7-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-afterburn-5.5.1-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-alacritty-0.13.2-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-asahi-btsync-0.2.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-asahi-nvram-0.2.1-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-asahi-wifisync-0.2.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-askalono-cli-0.4.6-9.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-b3sum-1.5.1-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-bat-0.24.0-5.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-bindgen-cli-0.69.4-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-bitvec_helpers-3.1.4-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-blsctl-0.2.3-14.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-bodhi-cli-2.1.2-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-btrd-0.5.3-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cargo-deny-0.14.21-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cargo-insta-1.38.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cargo-readme-3.3.1-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cbindgen-0.26.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cfonts-1.1.4-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-choosier-0.1.0-17.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-clang-tidy-sarif-0.4.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-clippy-sarif-0.4.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-comrak-0.18.0-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-copydeps-5.0.1-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-coreos-installer-0.21.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-count-zeroes-0.2.1-9.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cpc-1.9.3-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-desed-1.2.1-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-difftastic-0.57.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-diskonaut-0.11.0-18.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-docopt-1.1.1-13.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-dolby_vision-3.3.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-dotenvy-0.15.7-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-dua-cli-2.29.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-dutree-0.2.18-12.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-elfcat-0.1.8-10.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-erdtree-3.1.2-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-eza-0.17.3-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-fd-find-9.0.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-fedora-update-feedback-2.1.4-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gimoji-1.1.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-git-delta-0.16.5-10.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gitui-0.24.3-5.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gst-plugin-gif-0.12.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gst-plugin-gtk4-0.12.5-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gst-plugin-reqwest-0.12.4-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-hadolint-sarif-0.4.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-handlebars-5.1.2-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-heatseeker-1.7.1-16.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-hexyl-0.14.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-hyperfine-1.18.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-ifcfg-devname-1.1.0-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-is_ci-1.2.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-jql-7.1.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-kdotool-0.2.1-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-krunvm-0.1.6-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-leb128-0.2.5-9.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-libcramjam-0.3.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-lino-0.10.0-9.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-local_ipaddress-0.1.3-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-lscolors-0.17.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-lsd-1.1.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-mdsh-0.7.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-names-0.14.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-navi-2.20.1-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-nu-0.91.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-oxipng-9.1.1-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pleaser-0.5.4-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pore-0.1.11-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-prefixdevname-0.2.0-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pretty-bytes-0.2.0-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pretty-git-prompt-0.2.2-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-procs-0.14.4-5.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pulldown-cmark-0.10.3-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-python-launcher-1.0.0-12.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rav1e-0.7.1-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rbspy-0.17.0-5.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rd-agent-2.2.5-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rd-hashd-2.2.5-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-resctl-bench-2.2.5-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-resctl-demo-2.2.5-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-ripgrep-14.1.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-routinator-0.13.2-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-routinator-ui-0.3.4-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rpick-0.9.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rpki-0.18.1-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rpm-sequoia-1.6.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rustcat-1.3.0-11.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sarif-fmt-0.4.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-scx_rustland-0.0.3-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-scx_rusty-0.5.4-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sd-1.0.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-chameleon-gnupg-0.9.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-keyring-linter-1.0.1-7.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-octopus-librnp-1.8.1-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-policy-config-0.6.0-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-sq-0.35.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-sqv-1.2.1-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-wot-0.11.0-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sevctl-0.4.3-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sha1collisiondetection-0.3.4-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-shellcheck-sarif-0.4.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-silver-2.0.1-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sinit-0.1.2-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-skim-0.10.4-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-snphost-0.1.2-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-speakersafetyd-0.1.9-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-ssh-key-dir-0.1.4-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-system76_ectool-0.3.8-9.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-szip-1.0.0-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tealdeer-1.6.1-8.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-termbg-0.4.4-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tiny-dfr-0.2.0-5.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tokei-12.1.2-9.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tree-sitter-cli-0.22.5-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uefi-run-0.6.1-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_base32-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_base64-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_basename-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_basenc-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_cat-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_cksum-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_comm-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_cp-0.0.23-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_csplit-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_cut-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_date-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_dd-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_df-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_dir-0.0.23-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_dircolors-0.0.23-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_dirname-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_du-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_echo-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_env-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_expand-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_expr-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_factor-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_false-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_fmt-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_fold-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_hashsum-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_head-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_join-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_link-0.0.23-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_ln-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_ls-0.0.23-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_mkdir-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_mktemp-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_more-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_mv-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_nl-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_numfmt-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_od-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_paste-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_pr-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_printenv-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_printf-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_ptx-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_pwd-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_readlink-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_realpath-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_rm-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_rmdir-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_seq-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_shred-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_shuf-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_sleep-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_sort-0.0.23-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_split-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_sum-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_tac-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_tail-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_tee-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_test-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_touch-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_tr-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_true-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_truncate-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_tsort-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_unexpand-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_uniq-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_unlink-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_vdir-0.0.23-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_wc-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_whoami-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-uu_yes-0.0.23-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-varlink-cli-4.5.3-7.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-varlink_generator-10.1.0-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-vhost-device-scmi-0.1.0-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-vhost-device-sound-0.1.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-weezl-0.1.8-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-ybaas-0.0.17-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-yubibomb-0.2.14-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-zoxide-0.9.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-zram-generator-1.1.2-11.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust2rpm-helper-0.1.5-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustup-1.26.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'snapshot-46.3-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sudo-rs-0.2.2-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'system76-keyboard-configurator-1.3.10-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wildcard-0.3.3-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glycin-loaders / gnome-tour / helix / helvum / libipuz / loupe / etc');
}
