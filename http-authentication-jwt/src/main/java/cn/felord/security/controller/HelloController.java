package cn.felord.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author huzhifengqing@qq.com
 * @since 2022/4/17 21:41
 */
@RestController
public class HelloController {

    @GetMapping("hello")
    public String hello() {
        return "Hello, World";
    }
}
