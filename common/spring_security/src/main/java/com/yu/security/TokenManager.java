package com.yu.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * @Program: iplat
 * @ClassName: com.yu.security
 * @Description:
 * @Copyright: ©上海宝信软件股份有限公司 Copyright @2017 BAOSIGHT Corporation. All Rights Reserved
 * @Website: www.baosight.com
 * @Author: 于龙飞
 * @CreateDate: 2022/8/4
 * @version: 1.0
 */
@Component
public class TokenManager {
    private long tokenExpiration = 24 * 60 * 60 * 1000;
    private String tokenSignKey = "123456";

    public String createToken(String username) {
        String token = Jwts.builder().setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() +
                        tokenExpiration))
                .signWith(SignatureAlgorithm.HS512,
                        tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
        return token;
    }

    public String getUserFromToken(String token) {
        String user = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
        return user;
    }

    public void removeToken(String token) {
        //jwttoken 无需删除，客户端扔掉即可。
    }

}
