package ldaps.auth.exception;

import ldaps.auth.enums.LDAPSReturnCode;

/**
 * @Author: liangpx2
 * @Date: 2023/3/17 10:46
 * @Description: 自定义异常
 */
public class LDAPSException extends RuntimeException {
    private LDAPSReturnCode code;

    public LDAPSException(LDAPSReturnCode code){
        super(code.getMsg());
        this.code = code;
    }

    public LDAPSReturnCode getCode() {
        return code;
    }
}
