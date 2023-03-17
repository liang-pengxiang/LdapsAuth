package ldaps.auth;

import ldaps.auth.enums.LDAPSReturnCode;

/**
 * @Author: liangpx2
 * @Date: 2023/3/17 15:10
 * @Description: LDAPS认证测试类
 */
public class Test {
    public static void main(String[] args) throws Exception {
        LDAPSReturnCode code = LDAPSVerifier.verify("Linux001", "1111");
        System.out.println("code: " + code.getCode() + ", message: " + code.getMsg());
    }
}
