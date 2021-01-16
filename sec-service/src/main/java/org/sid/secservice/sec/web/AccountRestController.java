package org.sid.secservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Data;
import org.sid.secservice.sec.JwtUtil;
import org.sid.secservice.sec.entities.AppRole;
import org.sid.secservice.sec.entities.AppUser;
import org.sid.secservice.sec.service.AccountService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    private AccountService accountService;
    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }
    @GetMapping(path = "/users")
    @PreAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.allUsers();
    }
    @PostMapping(path = "/users" )
    @PreAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return  accountService.addNewUser(appUser);
    }
    @PostMapping(path = "/roles" )
    @PreAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole ){
        return  accountService.addNewRole(appRole);
    }
    @PostMapping(path = "/addRoleToUser" )
    @PreAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm ){
        accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRolename());
    }
    @GetMapping(path = "/refreshToken")
    public Map<String,String> refreshToken(HttpServletRequest request, HttpServletResponse response){
        String authToken=request.getHeader(JwtUtil.AUTH_HEADER);
        if(authToken!=null && authToken.startsWith(JwtUtil.HEADER_PREFIX)){
            try {
                String jwtRefreshToken = authToken.substring(JwtUtil.HEADER_PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);
                String username = decodedJWT.getSubject();

                AppUser appUser=accountService.loadUserByUserName(username);
                String jwtAccessToken= JWT.create()
                        .withSubject(appUser.getUsername())
                        .withIssuer(request.getRequestURL().toString())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.EXPIRE_ACCESS_TOKEN))
                        .withClaim("roles",appUser.getAppRoles().stream().map(r-> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken=new HashMap<>();
                idToken.put("access-token",jwtAccessToken);
                idToken.put("refresh-token",jwtRefreshToken);
                return idToken;


            }
            catch (Exception e){
                throw new RuntimeException(e.getMessage());
            }
        }
        else{
            throw new RuntimeException("Refresh Token Required");
        }
    }
    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUserName(principal.getName());
    }

}

@Data
class RoleUserForm {
    private String username;
    private String rolename;


}
