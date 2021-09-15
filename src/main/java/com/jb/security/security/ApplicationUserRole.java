package com.jb.security.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.jb.security.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
   ADMIN(Sets.newHashSet(
           ADMIN_READ,ADMIN_WRITE,
           COMPANY_READ,COMPANY_WRITE,
           CUSTOMER_READ,CUSTOMER_WRITE,
           COUPON_READ,COUPON_WRITE
   )),
   SUPPORT(Sets.newHashSet(
           ADMIN_READ,
           COMPANY_READ,
           CUSTOMER_READ,
           COUPON_READ
   )),
   COMPANY(Sets.newHashSet()),
   CLIENT(Sets.newHashSet()),
   GUEST(Sets.newHashSet());

   private final Set<ApplicationUserPermission> permissions;

   ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
      this.permissions = permissions;
   }

   public Set<ApplicationUserPermission> getPermissions() {
      return permissions;
   }

   public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
      Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
              .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
              .collect(Collectors.toSet());
      permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
      return permissions;
   }
}
