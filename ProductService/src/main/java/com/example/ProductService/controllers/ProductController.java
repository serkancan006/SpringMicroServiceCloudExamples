package com.example.ProductService.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/product")
public class ProductController {

    @GetMapping("/public")
    public String publicAccess() {
        return "Herkese açık içerik";
    }

    // ClientUser → resource_access içinden geldiği için hasRole kullanılır
    @GetMapping("/user")
    @PreAuthorize("hasRole('ClientUser')")
    public String userAccess() {
        return "ClientUser rolüne sahip kullanıcı erişebilir. resource_access";
    }

    // realm_access içindeki 'admin' rolü → hasAuthority('ROLE_admin') şeklinde kontrol edilir
    @GetMapping("/user/realm_access")
    @PreAuthorize("hasAuthority('ROLE_User')")
    public String userRealmRoleAccess() {
        return "user rolüne sahip kullanıcı erişebilir. realm_access";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ClientAdmin')")
    public String adminAccess() {
        return "ClientAdmin rolüne sahip kullanıcı erişebilir. resource_access";
    }

    @GetMapping("/admin/realm_access")
    @PreAuthorize("hasAuthority('ROLE_Admin')")
    public String adminRealmRoleAccess() {
        return "Admin rolüne sahip kullanıcı erişebilir. realm_access";
    }

}
