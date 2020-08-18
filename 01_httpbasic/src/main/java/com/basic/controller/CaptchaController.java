package com.basic.controller;

import com.basic.config.auth.imagecode.CaptchaCode;
import com.basic.utils.MyContants;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;

@RestController
public class CaptchaController {

    @Resource
    DefaultKaptcha captchaProducer;


    @RequestMapping(value="/kaptcha",method = RequestMethod.GET)
    public void kaptcha(HttpSession session, HttpServletResponse response) throws IOException {

        response.setDateHeader("Expires", 0);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("image/jpeg");

        String capText = captchaProducer.createText();

        session.setAttribute(MyContants.CAPTCHA_SESSION_KEY,
                new CaptchaCode(capText,2 * 60));

        try(ServletOutputStream out = response.getOutputStream()){
            BufferedImage bufferedImage = captchaProducer.createImage(capText);
            ImageIO.write(bufferedImage,"jpg",out);
            out.flush();
        }

    }


}
