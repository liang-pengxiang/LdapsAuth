package ldaps.auth.utils;

import ldaps.auth.enums.AdUserAttributeEnum;
import ldaps.auth.enums.LDAPSReturnCode;
import ldaps.auth.exception.BusinessException;
import ldaps.auth.exception.LDAPSException;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Calendar;
import java.util.Properties;

/**
 * @Author: liangpx2
 * @Date: 2023/3/17 10:45
 * @Description: LDAPS 操作类
 */
public class LDAPSUtil {

    private final static Control[] connCtls = null;

    static {
        //是否禁用端点标识
        System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification", "true");
    }

    /**
     *
     * @param userName
     * @param password
     * @return
     * @throws BusinessException
     */
    public static LDAPSReturnCode verify(String userName, String password) throws Exception {
        verifyUserNameAndPassword(userName, password);
        LdapContext adminCtx = getAdminCtx(initProperties());
        String userDN = getAdUserDN(userName, adminCtx);
        //通过用户DN进行用户登录认证
        verifyUser(userName, userDN, password, adminCtx);
        return LDAPSReturnCode.VERIFICATION_SUCCESS;
    }

    /**
     * 用户认证
     * 成功无反应，如果失败抛出异常
     * @param userName
     * @param userDN
     * @param password
     * @param adminCtx
     */
    private static void verifyUser(String userName, String userDN, String password, LdapContext adminCtx) {
        Properties prop = initProperties();
        LdapContext ctx = null;
        try {
            ctx =  new InitialLdapContext(prop, connCtls);
        } catch (NamingException e) {
//            Logger.error("用户认证获取ctx失败：", e);
            throw new LDAPSException(LDAPSReturnCode.CONNECT_FAIL);
        }

        try {
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, userDN);
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
            ctx.reconnect(connCtls);
        }catch (Exception e){
//            Logger.error("用户认证失败：", e);
            //分析失败原因
            Long userExpiresDateLong = getUserExpiresDateLong(userName, adminCtx);
            Long curTime = System.currentTimeMillis();
            if(userExpiresDateLong != null && curTime.compareTo(userExpiresDateLong) > 0){
                throw new LDAPSException(LDAPSReturnCode.ADPWD_TIMEOUT);
            }else if(getAdUserIsMustModifyPwd(userName, adminCtx)){
                throw new LDAPSException(LDAPSReturnCode.ADPWD_MUST_MODIFY);
            }else{
                throw new LDAPSException(LDAPSReturnCode.VERIFICATION_FAIL);
            }
        }finally {
            //不管成功失败，都需要关掉ctx
            if(ctx != null){
                try {
                    ctx.close();
                } catch (NamingException e) {
//                    Logger.error("ctx close error",e);
                    System.out.println("ctx close error：" + e.getMessage());
                }
            }
            if(adminCtx != null){
                try {
                    adminCtx.close();
                } catch (NamingException e) {
//                    Logger.error("adminCtx close error",e);
                    System.out.println("ctx close error：" + e.getMessage());
                }
            }
        }
    }

    /**
     * 用户下次登录是否必须修改密码
     *
     * @param userName 用户名
     * @param adminCtx 管理员用户的连接
     * @return true：是  false：否
     */
    private static Boolean getAdUserIsMustModifyPwd(String userName, LdapContext adminCtx) {
        Attributes attrs = getAdUserAttr(userName, adminCtx);
        String isMustModify = attrs.get(
                AdUserAttributeEnum.PWD_LAST_SET.getAttr()).toString().split(":")[1].trim();
//        Logger.error("获取是否下次登录必须修改密码，账户名：{" + userName + "}，配置项：{" + AdUserAttributeEnum.PWD_LAST_SET.getAttr() + "}，值{" + isMustModify + "}");
        return isMustModify.equals("0");
    }

    /**
     * 获取AD账户失效日期
     * @param userName
     * @param adminCtx 管理员用户的连接
     * @return
     */
    private static Long getUserExpiresDateLong(String userName, LdapContext adminCtx){
        Attributes attrs = getAdUserAttr(userName, adminCtx);
        String accountexpires = attrs.get(
                AdUserAttributeEnum.ACCOUNT_EXPIRES.getAttr()).toString().split(":")[1].trim();
//        Logger.error("获取AD账户失效日期，账户名：{" + userName + "}，配置项：{" + AdUserAttributeEnum.ACCOUNT_EXPIRES.getAttr() + "}，值{" + accountexpires + "}");
        //0或者9223372036854775807代表永不失效
        if ("0".equals(accountexpires) || "9223372036854775807".equals(accountexpires)){
            return null;
        }
        return adExpiresToLong(Long.parseLong(accountexpires));
    }

    /**
     * AD账户时间戳转换
     * @param accountExpiresL 到期时间数据
     * @return
     */
    private static Long adExpiresToLong(long accountExpiresL){
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(1601, 0, 1, 0, 0);
        accountExpiresL = accountExpiresL/ 10000 + calendar.getTime().getTime();
        return accountExpiresL;
    }

    /**
     * 通过管理员用户的连接查需要登录认证的用户的DN信息
     * @param userName
     * @param adminCtx
     * @return
     */
    private static String getAdUserDN(String userName, LdapContext adminCtx) throws Exception {
        String userDN = null;
        try {
            Attributes attrs = getAdUserAttr(userName, adminCtx);
            String userDNAttr = attrs.get(AdUserAttributeEnum.DN.getAttr()).toString();
//        Logger.error("获取AD账户DN，账户名：{" + userName + "}，配置项：{" + AdUserAttributeEnum.DN.getAttr() + "}，值{" + userDNAttr + "}");
            userDN = userDNAttr.split(":")[1].trim();
            return userDN;
        }catch (Exception e){
            if (e instanceof LDAPSException){
                throw e;
            }else {
                throw new LDAPSException(LDAPSReturnCode.GET_AD_USER_DN_FAIL);
            }
        }finally {
            //如果userDN为空，说明获取用户DN失败了，需要关掉连接
            if(userDN == null) {
                if(adminCtx != null){
                    try {
                        adminCtx.close();
                    } catch (NamingException e) {
//                        Logger.error("ctx close error",e1);
                        System.out.println("ctx close error：" + e.getMessage());
                    }
                }
            }
        }
    }

    /**
     * 查找用户信息
     * @param userName
     * @param adminCtx
     * @return
     */
    private static Attributes getAdUserAttr(String userName, LdapContext adminCtx) {
        Attributes attrs = null;
        SearchControls control = new SearchControls();
        control.setSearchScope(SearchControls.SUBTREE_SCOPE);
        try {
            //有的企业员工的dn不是有cn开头的，而是由uid开头的，这个因企业而异
            //使用cn，若存在重名用户，则返回的是最后一个员工，存在bug
            //NamingEnumeration<SearchResult> en = ctx.search(BASEN, "cn=" + cn, contro);
            //使用sAMAccountName，避免重名，比如存在四个张伟
            //删除域名，才能进行查询
            if(userName.contains("@")){
                userName = userName.substring(0, userName.indexOf("@"));
            }
            NamingEnumeration<SearchResult> en = adminCtx.search(LDAPSConfInfoUtil.LDAPSConfMap.get("baseDn"),
                    AdUserAttributeEnum.SAM_ACCOUNT_NAME.getSearchParameter(userName),
                    control);
            if (en == null) {
                throw new LDAPSException(LDAPSReturnCode.AD_USER_NOT_EXIST);
            }
            while (en.hasMoreElements()) {
                SearchResult obj = en.nextElement();
                if (obj != null) {
                    attrs = obj.getAttributes();
//                    Logger.error("获取AD账户属性，账户名：{" + userName + "}，属性：{" + attrs + "}");
                    break;
                }
            }
            if(attrs == null){
                throw new LDAPSException(LDAPSReturnCode.AD_USER_NOT_EXIST);
            }
        }catch (NamingException e) {
//            Logger.error("AD User Get Attr Error:", e);
            throw new LDAPSException(LDAPSReturnCode.AD_USER_NOT_EXIST);
        }
        return attrs;
    }

    /**
     * 获取管理员连接
     * @param prop
     * @return
     */
    private static LdapContext getAdminCtx(Properties prop){
        LdapContext ctx = null;
        try {
            ctx = new InitialLdapContext(prop, connCtls);
        } catch (NamingException e) {
            throw new LDAPSException(LDAPSReturnCode.CONNECT_FAIL);
        }

        //管理员用户连接AD
        try {
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, LDAPSConfInfoUtil.LDAPSConfMap.get("userName"));// AD User
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, LDAPSConfInfoUtil.LDAPSConfMap.get("password"));// AD Password
            ctx.reconnect(connCtls);
            return ctx;
        }catch (Exception e) {
            throw new LDAPSException(LDAPSReturnCode.VERIFICATION_FAIL);
        }
    }

    /**
     * 初始化一个Properties，并配置好基础参数
     * @return
     */
    private static Properties initProperties(){
        Properties prop = new Properties();
        String ldapURL = "LDAP://" + LDAPSConfInfoUtil.LDAPSConfMap.get("host") + ":"
                + LDAPSConfInfoUtil.LDAPSConfMap.get("port") + "/";

        prop.put(Context.INITIAL_CONTEXT_FACTORY, LDAPSConfInfoUtil.LDAPSConfMap.get("LDAPFactoryClass"));
        prop.put(Context.SECURITY_AUTHENTICATION, LDAPSConfInfoUtil.LDAPSConfMap.get("LDAPLevel"));// LDAP访问安全级别："none","simple","strong"
        prop.put(Context.PROVIDER_URL, ldapURL);
        prop.put(Context.SECURITY_PROTOCOL, LDAPSConfInfoUtil.LDAPSConfMap.get("securityProtocol"));

        //判断是否使用证书，如果否，则使用免密认证方式
        String useCert = LDAPSConfInfoUtil.LDAPSConfMap.get("useCert");
        if(useCert.equalsIgnoreCase("TRUE")){
            if(System.getProperty("javax.net.ssl.trustStore") == null){
                System.setProperty("javax.net.ssl.trustStore", LDAPSConfInfoUtil.LDAPSConfMap.get("cert"));
            }
        }else{
            prop.put("java.naming.ldap.factory.socket", LDAPSConfInfoUtil.LDAPSConfMap.get("socketFactory"));
        }

        return prop;
    }

    /**
     * 校验用户名和密码的输入是否合规
     * @param userName
     * @param password
     * @return
     */
    private static void verifyUserNameAndPassword(String userName, String password){
        if (userName == null || "".equals(userName))
            throw new BusinessException("用户名为空");
        //ldaps认证时如果密码为空，会返回认证成功
        if (password == null || "".equals(password))
            throw new BusinessException("密码为空");
    }
}
