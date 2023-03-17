package ldaps.auth;

import ldaps.auth.enums.LDAPSReturnCode;
import ldaps.auth.utils.LDAPSUtil;

/**
 * @Author: liangpx2
 * @Date: 2023/3/17 10:26
 * @Description: 此类为 JAVA 集成 AD 进行 LDAPS 认证的入口类
 */
public class LDAPSVerifier {
    public static LDAPSReturnCode verify(String username, String password) throws Exception {
        return LDAPSUtil.verify(username, password);
    }
}
