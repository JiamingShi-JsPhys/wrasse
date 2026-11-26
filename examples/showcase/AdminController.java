import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;

@CrossOrigin
public class AdminController {
    @GetMapping("/admin/users")
    public String users() {
        return "ok";
    }

    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests().antMatchers("/public/**").permitAll();
    }
}
