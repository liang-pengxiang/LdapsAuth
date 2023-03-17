package ldaps.auth.enums;

/**
 * @Author: liangpx2
 * @Date: 2023/3/17 10:40
 * @Description: LDAPS 认证返回值定义
 */
public enum LDAPSReturnCode {
    //================ad 认证
    VERIFICATION_FAIL(0, "认证失败"),//认证失败
    VERIFICATION_SUCCESS(1, "认证成功"),//认证成功
    //================通用返回值
    PARAM_ERR(2, "参数为空或错误"),//参数为空或错误
    CONNECT_FAIL(3, "连接AD服务器失败"),//连接AD服务器失败
    SERVER_ERR(4, "服务器内部错误"),//服务器内部错误
    //================ad 修改密码
    ADPWD_POLICY_INVALID(5, "AD认证密码不符合策略"),//AD认证密码不符合策略
    ADPWD_MODIFY_SUCCESS(6, "AD认证密码修改成功"),//AD认证密码修改成功
    AD_USER_NOT_EXIST(7, "AD用户不存在"),//AD用户不存在
    ADPWD_TIMEOUT(8, "AD用户密码过期"),//AD用户密码过期
    ADPWD_MUST_MODIFY(9, "AD用户下次登录必须修改密码"),//AD用户下次登录必须修改密码
    //================ad 解锁
    AD_USER_UNLOCAK_SUCCESS(10, "AD用户解锁成功"),//AD用户解锁成功
    AD_USER_UNLOCAK_FAIL(11, "AD用户解锁失败"),//AD用户解锁失败
    //================ad 获取用户信息
    GET_AD_USER_DN_FAIL(12, "获取AD用户DN失败")
            ;

    private Integer code;
    private String msg;

    LDAPSReturnCode(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public Integer getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }
}
