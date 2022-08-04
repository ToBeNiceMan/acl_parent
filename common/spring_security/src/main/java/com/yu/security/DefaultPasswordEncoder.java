package com.yu.security;

import com.yu.utils.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

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
public class DefaultPasswordEncoder implements PasswordEncoder {

    public DefaultPasswordEncoder() {
        this(-1);
    }

    public DefaultPasswordEncoder(int strendth) {
    }

    /**
     * @FunName: encode
     * @Description: 使用MD5进行加密
     * @Author: 于龙飞
     * @Date: 2022/8/4
     * @Param:
     * @Return:
     **/
    @Override
    public String encode(CharSequence rawPassword) {
        return MD5.encrypt(rawPassword.toString());
    }

    /**
     * @FunName: matches
     * @Description: 判断密码是否一致
     * @Author: 于龙飞
     * @Date: 2022/8/4
     * @Param:
     * @Return:
     **/
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encodedPassword.equals(encode(rawPassword));
    }
}
