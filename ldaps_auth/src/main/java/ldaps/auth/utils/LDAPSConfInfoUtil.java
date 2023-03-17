package ldaps.auth.utils;

import java.util.HashMap;

/**
 * @Author: liangpx2
 * @Date: 2023/3/17 10:54
 * @Description:
 */
public class LDAPSConfInfoUtil {

    //用于LDAPS认证的配置信息
    public final static HashMap<String,String> LDAPSConfMap;

    static {
        LDAPSConfMap = new HashMap<String, String>();

        //AD域服务器地址，域名
        LDAPSConfMap.put("host","123.56.12.213");
        //AD域服务器端口，默认636
        LDAPSConfMap.put("port","636");
        //AD域服务器根节点信息，在此范围内进行用户查询
        LDAPSConfMap.put("baseDn","DC=contoso,DC=com");
        //LDAPS认证证书，本地路径
        LDAPSConfMap.put("cert","D:\\Utils\\JAVA\\jdk1.8.0_241\\jre\\lib\\security\\jssecacerts");
        //是否使用免密认证，true为不使用，false为使用
        LDAPSConfMap.put("useCert","true");
        //LDAP工厂类
        LDAPSConfMap.put("LDAPFactoryClass","com.sun.jndi.ldap.LdapCtxFactory");
        //LDAP访问安全级别："none","simple","strong"
        LDAPSConfMap.put("LDAPLevel","simple");
        //安全协议
        LDAPSConfMap.put("securityProtocol","ssl");
        //套接字工厂
        LDAPSConfMap.put("socketFactory","ldaps.auth.DummySSLSocketFactory");
        //“管理员用户”用户名（因为所有的连接都是先通过此用户进行查询DN信息，再去连接认证，所以为了区别其它用户，将其称为“管理员用户”）
        LDAPSConfMap.put("userName","administrator@contoso.com");
        //密码
        LDAPSConfMap.put("password","123456789");
    }
}
