package ldaps.auth.enums;

/**
 * @Author: liangpx2
 * @Date: 2023/3/17 11:04
 * @Description: AD用户属性枚举
 */
public enum  AdUserAttributeEnum {
    DN("distinguishedname"),//用户DN
    ACCOUNT_EXPIRES("accountexpires"),//账号过期时间
    SAM_ACCOUNT_NAME("sAMAccountName"),//安全主体对象（唯一账号名）
    PWD_LAST_SET("pwdLastSet"),//此项为0，则下次登录必须修改密码
    USER_ACCOUNT_CONTROL("userAccountControl"),
    MEMBER("memberof"),//组
    ;

    private String attr;

    AdUserAttributeEnum(String attr) {
        this.attr = attr;
    }

    public String getSearchParameter(String value){
        return this.getAttr()+"="+value;
    }

    public String getAttr() {
        return attr;
    }
}
