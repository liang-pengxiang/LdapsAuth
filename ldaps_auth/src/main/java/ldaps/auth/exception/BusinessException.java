package ldaps.auth.exception;

/**
 * @Author: liangpx2
 * @Date: 2023/3/17 13:40
 * @Description: 自定义业务异常
 */
public class BusinessException extends RuntimeException {
    public BusinessException(String message){
        super(message);
    }
}
