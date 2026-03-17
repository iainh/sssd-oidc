%global crate sssd-oidc
%global _version 0.1.0

Name:           sssd-oidc
Version:        %{_version}
Release:        1%{?dist}
Summary:        NSS and PAM modules for OIDC/SCIM identity resolution
License:        GPL-2.0-or-later
URL:            https://github.com/iainh/sssd-oidc
Source0:        %{crate}-%{version}.tar.gz

# Rust release builds don't produce rpmbuild-compatible debuginfo
%global debug_package %{nil}

# Build requirements (rust/cargo installed via rustup, not RPM)
BuildRequires:  gcc
BuildRequires:  pam-devel
BuildRequires:  perl-interpreter

# Runtime requirements
Requires:       sssd
Requires:       pam

%description
NSS and PAM modules (written in Rust) that let Linux resolve users and groups
and authenticate against any OIDC identity provider via SCIM 2.0 lookups.
Designed to run behind SSSD's proxy provider.

%prep
%setup -q -n %{crate}-%{version}

%build
cargo build --workspace --release --locked

%install
# Directories
install -d %{buildroot}%{_libdir}
install -d %{buildroot}%{_libdir}/security
install -d %{buildroot}%{_sysconfdir}/sssd-oidc
install -d %{buildroot}%{_sharedstatedir}/sssd-oidc

# NSS module — glibc expects libnss_<name>.so.2
install -p -m 0755 target/release/libnss_oidc.so %{buildroot}%{_libdir}/libnss_oidc.so.2

# PAM module
install -p -m 0755 target/release/libpam_oidc.so %{buildroot}%{_libdir}/security/pam_oidc.so

# Example config (marked noreplace so admin edits survive upgrades)
install -p -m 0600 dist/rpm/config.toml.example %{buildroot}%{_sysconfdir}/sssd-oidc/config.toml

%post
# Rebuild the shared-library cache so NSS can find libnss_oidc.so.2
/sbin/ldconfig

echo "----------------------------------------------------------------------"
echo " sssd-oidc installed."
echo ""
echo " Next steps:"
echo "   1. Edit /etc/sssd-oidc/config.toml with your SCIM/OIDC details"
echo "   2. Create /etc/sssd-oidc/scim-token with your SCIM bearer token"
echo "      chmod 600 /etc/sssd-oidc/scim-token"
echo "   3. Add 'oidc' to passwd/group in /etc/nsswitch.conf:"
echo "        passwd: files sss oidc"
echo "        group:  files sss oidc"
echo "   4. Configure SSSD proxy domain (see README)"
echo "   5. Restart SSSD: systemctl restart sssd"
echo "----------------------------------------------------------------------"

%postun
/sbin/ldconfig

%files
%license LICENSE
%doc README.md
%dir %attr(0750,root,root) %{_sysconfdir}/sssd-oidc
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/sssd-oidc/config.toml
%{_libdir}/libnss_oidc.so.2
%{_libdir}/security/pam_oidc.so
%dir %attr(0750,root,root) %{_sharedstatedir}/sssd-oidc

%changelog
* Mon Mar 16 2026 Iain H. <iain@spiralpoint.org> - 0.1.0-1
- Initial RPM package
