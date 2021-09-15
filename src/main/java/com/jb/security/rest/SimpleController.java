package com.jb.security.rest;

import com.jb.security.beans.Company;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("company")
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SimpleController {

    private static final List<Company> COMPANIES = Arrays.asList(
            new Company(1,"Rami Levi"),
            new Company(2,"Osher Ad"),
            new Company(3,"SuperSal"),
            new Company(4,"Mega")
    );

    //hasRole('ROLE_') hasAnyRole('ROLE_') hashAuthority('permission') hasAnyAuthority('permission')

    @GetMapping()
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_SUPPORT')")
    private List<Company> getAll(){
        System.out.println(COMPANIES);
        return COMPANIES;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('company:write')")
    private void addCompany(@RequestBody Company company){
        System.out.println(company);
    }

    @DeleteMapping(path = {"companyId"})
    @PreAuthorize("hasAuthority('company:write')")
    public void deleteCompany(@PathVariable("companyId") int companyId){
        System.out.println(companyId);
    }

    @PutMapping(path={"companyId"})
    @PreAuthorize("hasAuthority('company:write')")
    public void updateStudent(@PathVariable("companyId") int companyId, @RequestBody Company company){
        System.out.println(String.format("%s %s",companyId,company));
    }
}
