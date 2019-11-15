package cn.shuhan.securityTest.controller;

import cn.shuhan.securityTest.result.RespBean;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("login")
    public RespBean login(){
        return RespBean.error("不好,没有登录");
    }

    @GetMapping("hello")
    public String  hello(){
        return "hello";
    }
}
